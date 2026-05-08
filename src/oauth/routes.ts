import { type Request, type Response, Router } from "express";
import { randomBytes } from "node:crypto";
import { config } from "../config.js";
import { buildAuthUrl, exchangeCode } from "../intuit.js";
import { createUser, generateApiKey } from "../auth.js";
import { deriveServerSideUserKey } from "../crypto.js";
import { saveConnection } from "../qbo.js";
import { signAccessToken } from "./jwt.js";
import { jwtSecret } from "./secret.js";
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
// MCP client (e.g. claude.ai) hits this to start the auth code flow.
// We park the request in oauth_pending and bounce the user to Intuit;
// when Intuit returns to /connect/callback we look the state back up
// and complete the flow.

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

  // Send the user to Intuit. The state we pass is our internal one;
  // the Intuit-callback dispatcher in server.ts looks for it in
  // oauth_pending before falling back to legacy linking_sessions.
  res.redirect(buildAuthUrl(internalState));
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

// ---- Intuit callback dispatcher ----
//
// Called from server.ts /connect/callback when the state belongs to a
// new-flow OAuth authorize request (oauth_pending). Completes the Intuit
// dance, links/upserts the user, generates an authz code, and redirects
// the original MCP client back to its redirect_uri with code+state.

export async function completeOAuthIntuitCallback(
  pending: NonNullable<ReturnType<typeof consumePending>>,
  intuitCode: string,
  realmId: string,
): Promise<{ redirect: string }> {
  const tokens = await exchangeCode(intuitCode);

  // Each OAuth-flow login provisions a fresh user_id for clean isolation.
  // The api_key_hash column is required (UNIQUE NOT NULL), but no human
  // ever sees this key — OAuth-flow callers authenticate by JWT, not by
  // qbo_… key. The plaintext is generated and immediately discarded.
  const { hash } = generateApiKey();
  const user = createUser(hash, "oauth-issued");

  // CRITICAL: encryption key for OAuth-flow users must be derived from
  // jwtSecret + user_id, NOT from the throwaway api-key plaintext. The
  // request-time auth path (auth.ts authenticate()) derives the same
  // server-side key when the JWT is presented. Mismatched keys here would
  // make tokens irrecoverable on first call (ask me how I know).
  saveConnection(user.id, realmId, tokens, deriveServerSideUserKey(jwtSecret, user.id));

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
  return { redirect: url.toString() };
}
