import { type Request, type Response, Router } from "express";
import { randomBytes } from "node:crypto";
import { config } from "../config.js";
import { createUser, generateApiKey } from "../auth.js";
import { signAccessToken } from "./jwt.js";
import {
  cleanupPending,
  clientSecretMatches,
  consumeAuthCode,
  consumePending,
  getClient,
  issueRefreshToken,
  newRandomToken,
  registerClient,
  rotateRefreshToken,
  saveAuthCode,
  savePending,
  verifyPkce,
} from "./store.js";

export const oauthRouter = Router();

const SUPPORTED_SCOPE = "qbo:access";
const PENDING_TTL_MS = 15 * 60 * 1000;
const CODE_TTL_MS = 10 * 60 * 1000;
const ALL_SCOPES = [SUPPORTED_SCOPE];

// ---- Discovery ----

oauthRouter.get(
  "/.well-known/oauth-protected-resource",
  (_req: Request, res: Response) => {
    res.json({
      resource: config.publicBaseUrl,
      authorization_servers: [config.publicBaseUrl],
      scopes_supported: ALL_SCOPES,
      bearer_methods_supported: ["header"],
      resource_documentation: `${config.publicBaseUrl}/`,
    });
  },
);

oauthRouter.get(
  "/.well-known/oauth-authorization-server",
  (_req: Request, res: Response) => {
    res.json({
      issuer: config.publicBaseUrl,
      authorization_endpoint: `${config.publicBaseUrl}/oauth/authorize`,
      token_endpoint: `${config.publicBaseUrl}/oauth/token`,
      registration_endpoint: `${config.publicBaseUrl}/oauth/register`,
      scopes_supported: ALL_SCOPES,
      response_types_supported: ["code"],
      grant_types_supported: ["authorization_code", "refresh_token"],
      code_challenge_methods_supported: ["S256"],
      token_endpoint_auth_methods_supported: [
        "none",
        "client_secret_basic",
        "client_secret_post",
      ],
    });
  },
);

// ---- Dynamic Client Registration (RFC 7591) ----

oauthRouter.post("/oauth/register", (req: Request, res: Response) => {
  const body = (req.body ?? {}) as Record<string, unknown>;
  const redirect_uris = Array.isArray(body.redirect_uris) ? body.redirect_uris : [];
  if (redirect_uris.length === 0) {
    res.status(400).json({
      error: "invalid_redirect_uri",
      error_description: "redirect_uris must be a non-empty array",
    });
    return;
  }
  for (const uri of redirect_uris) {
    if (typeof uri !== "string" || (!uri.startsWith("https://") && !uri.startsWith("http://localhost"))) {
      res.status(400).json({
        error: "invalid_redirect_uri",
        error_description: `redirect URI must be https:// or http://localhost: ${uri}`,
      });
      return;
    }
  }

  const tokenAuth =
    typeof body.token_endpoint_auth_method === "string"
      ? body.token_endpoint_auth_method
      : "none";

  const { client_id, client_secret } = registerClient({
    client_name: typeof body.client_name === "string" ? body.client_name : undefined,
    redirect_uris: redirect_uris as string[],
    grant_types: Array.isArray(body.grant_types) ? (body.grant_types as string[]) : undefined,
    response_types: Array.isArray(body.response_types)
      ? (body.response_types as string[])
      : undefined,
    token_endpoint_auth_method: tokenAuth,
    scope: typeof body.scope === "string" ? body.scope : SUPPORTED_SCOPE,
  });

  res.status(201).json({
    client_id,
    ...(client_secret ? { client_secret } : {}),
    client_id_issued_at: Math.floor(Date.now() / 1000),
    redirect_uris,
    grant_types: body.grant_types ?? ["authorization_code", "refresh_token"],
    response_types: body.response_types ?? ["code"],
    token_endpoint_auth_method: tokenAuth,
    scope: body.scope ?? SUPPORTED_SCOPE,
  });
});

// ---- /oauth/authorize ----
//
// MCP client (e.g. claude.ai) hits this to start the auth code flow. We
// DON'T forward to Intuit here — Intuit only allows one admin per app
// per realm, and a coworker authorizing would kick the existing admin out.
// Instead, we park the request and show our own consent page that asks
// for the shared TEAM_SIGNUP_TOKEN (distributed by the admin out-of-band).
// Once the user pastes a valid token, we issue an auth code and redirect
// back to the MCP client.

oauthRouter.get("/oauth/authorize", (req: Request, res: Response) => {
  const q = req.query as Record<string, string | undefined>;
  const {
    response_type,
    client_id,
    redirect_uri,
    state,
    scope,
    code_challenge,
    code_challenge_method,
  } = q;

  if (response_type !== "code") {
    res.status(400).type("html").send(errorHtml("unsupported_response_type", "Only response_type=code is supported."));
    return;
  }
  if (!client_id || !redirect_uri || !code_challenge) {
    res.status(400).type("html").send(errorHtml("invalid_request", "Missing client_id, redirect_uri, or code_challenge."));
    return;
  }
  const challengeMethod = code_challenge_method ?? "plain";
  if (challengeMethod !== "S256") {
    res.status(400).type("html").send(errorHtml("invalid_request", "code_challenge_method must be S256."));
    return;
  }

  const client = getClient(client_id);
  if (!client) {
    res.status(400).type("html").send(errorHtml("invalid_client", "Unknown client_id."));
    return;
  }
  if (!client.redirect_uris.includes(redirect_uri)) {
    res.status(400).type("html").send(errorHtml("invalid_redirect_uri", "redirect_uri does not match the registered set."));
    return;
  }

  cleanupPending();
  const internalState = newRandomToken("st_", 18);
  savePending(
    {
      state: internalState,
      client_id,
      client_state: state ?? null,
      redirect_uri,
      scope: scope ?? SUPPORTED_SCOPE,
      code_challenge,
      code_challenge_method: challengeMethod,
    },
    PENDING_TTL_MS,
  );

  // Render the team-token consent page. Form posts back to /oauth/consent
  // with the internalState carried in a hidden field.
  res.type("html").send(consentPageHtml(internalState, client.client_name ?? "this app"));
});

// Form target for the consent page. Validates the team token and either
// issues an auth code (redirect back to client) or shows an error.
oauthRouter.post("/oauth/consent", (req: Request, res: Response) => {
  const body = (req.body ?? {}) as Record<string, string>;
  const { state, team_token } = body;
  if (!state || !team_token) {
    res.status(400).type("html").send(errorHtml("invalid_request", "Missing state or team_token."));
    return;
  }
  if (!config.teamSignupToken || team_token !== config.teamSignupToken) {
    res.status(403).type("html").send(errorHtml("forbidden", "Invalid team token. Ask the admin for the current value."));
    return;
  }
  const pending = consumePending(state);
  if (!pending) {
    res.status(400).type("html").send(errorHtml("invalid_request", "State expired or already consumed."));
    return;
  }

  // Issue a new MCP user + auth code. The user_id will end up bound to
  // the JWT we eventually issue. They can call any tool — every call
  // uses the *shared* admin QBO connection underneath.
  const { hash } = generateApiKey();
  const user = createUser(hash, "oauth-issued");
  const code = newRandomToken("ac_", 24);
  saveAuthCode(
    {
      code,
      client_id: pending.client_id,
      user_id: user.id,
      redirect_uri: pending.redirect_uri,
      scope: pending.scope,
      code_challenge: pending.code_challenge,
      code_challenge_method: pending.code_challenge_method,
    },
    CODE_TTL_MS,
  );

  const url = new URL(pending.redirect_uri);
  url.searchParams.set("code", code);
  if (pending.client_state) url.searchParams.set("state", pending.client_state);
  res.redirect(url.toString());
});

// ---- /oauth/token ----

oauthRouter.post("/oauth/token", async (req: Request, res: Response) => {
  const body = (req.body ?? {}) as Record<string, string>;
  const grant_type = body.grant_type;

  // Authenticate the client (PKCE-only public clients pass none; otherwise basic/post)
  const presented = authenticateClient(req);
  if (!presented) {
    res.status(401).json({
      error: "invalid_client",
      error_description: "client authentication failed",
    });
    return;
  }

  if (grant_type === "authorization_code") {
    await handleAuthorizationCodeGrant(body, presented.client_id, res);
    return;
  }
  if (grant_type === "refresh_token") {
    await handleRefreshTokenGrant(body, presented.client_id, res);
    return;
  }

  res.status(400).json({
    error: "unsupported_grant_type",
    error_description: `Grant type '${grant_type}' is not supported`,
  });
});

async function handleAuthorizationCodeGrant(
  body: Record<string, string>,
  clientId: string,
  res: Response,
): Promise<void> {
  const { code, redirect_uri, code_verifier } = body;
  if (!code || !redirect_uri || !code_verifier) {
    res.status(400).json({
      error: "invalid_request",
      error_description: "code, redirect_uri, and code_verifier are required",
    });
    return;
  }

  const ac = consumeAuthCode(code);
  if (!ac) {
    res.status(400).json({
      error: "invalid_grant",
      error_description: "code is invalid, expired, or already used",
    });
    return;
  }
  if (ac.client_id !== clientId) {
    res.status(400).json({
      error: "invalid_grant",
      error_description: "code was issued to a different client",
    });
    return;
  }
  if (ac.redirect_uri !== redirect_uri) {
    res.status(400).json({
      error: "invalid_grant",
      error_description: "redirect_uri does not match",
    });
    return;
  }
  if (!verifyPkce(ac.code_challenge, ac.code_challenge_method, code_verifier)) {
    res.status(400).json({
      error: "invalid_grant",
      error_description: "PKCE verification failed",
    });
    return;
  }

  const { token: access_token, expiresIn } = await signAccessToken({
    sub: String(ac.user_id),
    client_id: ac.client_id,
    scope: ac.scope ?? SUPPORTED_SCOPE,
  });
  const refresh_token = issueRefreshToken({
    user_id: ac.user_id,
    client_id: ac.client_id,
    scope: ac.scope,
  });

  res.json({
    access_token,
    token_type: "Bearer",
    expires_in: expiresIn,
    refresh_token,
    scope: ac.scope ?? SUPPORTED_SCOPE,
  });
}

async function handleRefreshTokenGrant(
  body: Record<string, string>,
  clientId: string,
  res: Response,
): Promise<void> {
  const { refresh_token } = body;
  if (!refresh_token) {
    res.status(400).json({ error: "invalid_request", error_description: "refresh_token required" });
    return;
  }
  const old = rotateRefreshToken(refresh_token);
  if (!old) {
    res.status(400).json({ error: "invalid_grant", error_description: "refresh_token invalid or already used" });
    return;
  }
  if (old.client_id !== clientId) {
    res.status(400).json({ error: "invalid_grant", error_description: "refresh_token was issued to a different client" });
    return;
  }
  const { token: access_token, expiresIn } = await signAccessToken({
    sub: String(old.user_id),
    client_id: old.client_id,
    scope: old.scope ?? SUPPORTED_SCOPE,
  });
  const new_refresh = issueRefreshToken({
    user_id: old.user_id,
    client_id: old.client_id,
    scope: old.scope,
  });
  res.json({
    access_token,
    token_type: "Bearer",
    expires_in: expiresIn,
    refresh_token: new_refresh,
    scope: old.scope ?? SUPPORTED_SCOPE,
  });
}

function authenticateClient(req: Request): { client_id: string } | null {
  const body = (req.body ?? {}) as Record<string, string>;
  // Try Basic auth first
  const authz = req.header("authorization");
  if (authz && authz.toLowerCase().startsWith("basic ")) {
    try {
      const decoded = Buffer.from(authz.slice(6), "base64").toString("utf8");
      const idx = decoded.indexOf(":");
      if (idx > 0) {
        const id = decoded.slice(0, idx);
        const secret = decoded.slice(idx + 1);
        const c = getClient(id);
        if (c && clientSecretMatches(c, secret)) return { client_id: id };
      }
    } catch {
      // fall through
    }
    return null;
  }
  // POST form params
  const id = body.client_id;
  const secret = body.client_secret;
  if (!id) return null;
  const c = getClient(id);
  if (!c) return null;
  if (c.token_endpoint_auth_method === "none") {
    return { client_id: id }; // public client, PKCE protects the code
  }
  if (secret && clientSecretMatches(c, secret)) return { client_id: id };
  return null;
}

function errorHtml(error: string, description: string): string {
  return `<!doctype html><html><head><meta charset="utf-8"><title>Authorization error</title>
  <style>body{font-family:system-ui,sans-serif;max-width:560px;margin:48px auto;padding:0 16px}
  code{background:#f3f3f3;padding:2px 6px;border-radius:4px}</style></head><body>
  <h1>Authorization error</h1>
  <p><code>${error}</code>: ${description}</p>
  </body></html>`;
}

function consentPageHtml(state: string, clientName: string): string {
  return `<!doctype html><html><head><meta charset="utf-8"><title>Authorize ${clientName}</title>
  <style>
    body { font-family: system-ui, -apple-system, sans-serif; max-width: 480px;
           margin: 64px auto; padding: 0 16px; line-height: 1.5; color: #222; }
    h1 { font-size: 22px; margin-bottom: 8px; }
    p { color: #555; margin-top: 0; }
    label { display: block; font-weight: 600; margin: 24px 0 6px; }
    input { width: 100%; padding: 10px 12px; font-size: 15px; border: 1px solid #ccc;
            border-radius: 6px; box-sizing: border-box; font-family: ui-monospace, Menlo, monospace; }
    button { background: #2ca01c; color: white; border: 0; padding: 10px 22px;
             border-radius: 6px; font-weight: 600; font-size: 15px; cursor: pointer; margin-top: 16px; }
    .note { font-size: 13px; color: #888; margin-top: 14px; }
  </style></head><body>
  <h1>Authorize ${clientName}</h1>
  <p>Grant ${clientName} access to Ditto's QuickBooks data via the shared admin connection.</p>
  <form method="POST" action="/oauth/consent">
    <input type="hidden" name="state" value="${state}">
    <label for="team_token">Team access token</label>
    <input type="password" name="team_token" id="team_token" autocomplete="off" autofocus required>
    <p class="note">Get this from your team admin (Slack / 1Password). It's a shared per-team secret, not your personal credential.</p>
    <button type="submit">Authorize</button>
  </form>
  </body></html>`;
}
