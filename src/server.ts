import express, { type Request, type Response, type NextFunction } from "express";
import { randomBytes } from "node:crypto";
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StreamableHTTPServerTransport } from "@modelcontextprotocol/sdk/server/streamableHttp.js";
import { config } from "./config.js";
import { db } from "./db.js";
import { registerAllTools } from "./tools/index.js";
import { buildAuthUrl, exchangeCode } from "./intuit.js";
import { authenticate, createUser, findUserByLabel, generateApiKey, isToolAllowed, upsertUserByLabel, type AuthedUser } from "./auth.js";
import { getSharedRealmInfo, saveSharedConnection } from "./qbo.js";
import { oauthRouter } from "./oauth/routes.js";
import { cfAccessEnabled, identifyFromCfAccess } from "./oauth/cf_access.js";
import { adminRouter } from "./admin/routes.js";
import { requestLogMiddleware } from "./admin/log.js";

function buildMcpServer(): McpServer {
  const server = new McpServer({ name: "qbo-mcp", version: "0.1.0" });
  registerAllTools(server);
  return server;
}

export const app = express();
app.use(express.json({ limit: "1mb" }));
app.use(express.urlencoded({ extended: true, limit: "1mb" }));

// Per-request audit log — runs first so it sees every status code.
app.use(requestLogMiddleware);

app.get("/health", (_req: Request, res: Response) => {
  res.json({ ok: true });
});

// ---- OAuth metadata + endpoints (mounted at root) ----
app.use(oauthRouter);

// ---- Admin UI (gated by CF Access email match OR ADMIN_BOOTSTRAP_TOKEN) ----
app.use(adminRouter);

// ---- MCP endpoint ----

function unauthorized(res: Response, reason: "invalid_token" | "invalid_request"): void {
  const challenge =
    `Bearer realm="${config.publicBaseUrl}", ` +
    `error="${reason}", ` +
    `resource_metadata="${config.publicBaseUrl}/.well-known/oauth-protected-resource"`;
  res
    .status(401)
    .header("WWW-Authenticate", challenge)
    .json({ error: reason });
}

async function requireAuth(req: Request, res: Response, next: NextFunction): Promise<void> {
  const authz = req.header("authorization");
  if (!authz) {
    unauthorized(res, "invalid_request");
    return;
  }
  try {
    const auth = await authenticate(authz);
    if (!auth) {
      unauthorized(res, "invalid_token");
      return;
    }
    (req as any).authedUser = auth;
    next();
  } catch {
    unauthorized(res, "invalid_token");
  }
}

app.post("/mcp", requireAuth, async (req: Request, res: Response) => {
  // Surface JSON-RPC method + tool name to the request logger so /admin
  // shows what was called. Handles both single messages and batched arrays
  // (we capture the first message's method as a representative).
  const raw = req.body;
  const first = Array.isArray(raw) ? raw[0] : raw;
  if (first && typeof first.method === "string") {
    res.locals.rpcMethod = first.method;
    if (first.method === "tools/call" && typeof first.params?.name === "string") {
      res.locals.toolName = first.params.name;

      // Tool-level authorization. Reject denied tools with a JSON-RPC
      // error before the SDK runs the handler. The audit log captures
      // the attempt via res.locals.errorNote.
      const auth = (req as any).authedUser as AuthedUser | undefined;
      if (auth && !isToolAllowed(auth.user, first.params.name)) {
        res.locals.errorNote = `tool denied: ${first.params.name}`;
        res.status(200).json({
          jsonrpc: "2.0",
          id: first.id ?? null,
          error: {
            code: -32000,
            message: `Permission denied: tool '${first.params.name}' is not allowed for your account. Contact your admin.`,
          },
        });
        return;
      }
    }
  }

  const server = buildMcpServer();
  const transport = new StreamableHTTPServerTransport({ sessionIdGenerator: undefined });
  res.on("close", () => {
    transport.close();
    server.close();
  });
  try {
    await server.connect(transport);
    await transport.handleRequest(req, res, req.body);
  } catch (e) {
    console.error("MCP request failed:", e);
    res.locals.errorNote = (e as Error).message;
    if (!res.headersSent) res.status(500).json({ error: "internal" });
  }
});

app.get("/mcp", (_req: Request, res: Response) => {
  res.status(405).json({ error: "method_not_allowed" });
});
app.delete("/mcp", (_req: Request, res: Response) => {
  res.status(405).json({ error: "method_not_allowed" });
});

// ---- HTML helpers ----

function htmlPage(title: string, body: string): string {
  return `<!doctype html>
<html><head><meta charset="utf-8"><title>${title}</title>
<style>
  body { font-family: system-ui, -apple-system, sans-serif; max-width: 680px;
         margin: 48px auto; padding: 0 16px; line-height: 1.5; color: #222; }
  code { background: #f3f3f3; padding: 2px 6px; border-radius: 4px;
         font-size: 13px; font-family: ui-monospace, Menlo, monospace; }
  pre  { background: #f3f3f3; padding: 14px; border-radius: 6px;
         overflow-x: auto; font-size: 13px; }
  a.button, button { display: inline-block; background: #2ca01c; color: white;
                     padding: 10px 20px; border-radius: 6px; text-decoration: none;
                     font-weight: 600; border: 0; font-size: 15px; cursor: pointer; }
  .warn { background: #fff8e1; border-left: 4px solid #f2b200;
          padding: 10px 14px; border-radius: 4px; margin: 16px 0; }
  label { display: block; font-weight: 600; margin: 16px 0 6px; }
  input { width: 100%; padding: 10px 12px; font-size: 15px; border: 1px solid #ccc;
          border-radius: 6px; box-sizing: border-box; font-family: inherit; }
</style></head><body>${body}</body></html>`;
}

// ---- Landing page ----

app.get("/", (_req: Request, res: Response) => {
  const realm = getSharedRealmInfo();
  const realmStatus = realm
    ? `<strong>QBO admin connection active.</strong>`
    : `<strong>No QBO admin connection bootstrapped yet.</strong>`;
  res.type("html").send(
    htmlPage(
      "QBO MCP",
      `<h1>QuickBooks Online MCP Server</h1>
       <p>Read-only access to QuickBooks Online via the Model Context Protocol, shared across the team.</p>
       <p>Environment: <code>${config.intuit.environment}</code><br>${realmStatus}</p>

       <h2>Get a personal access key (team members)</h2>
       <p>If you've been given a team token, mint yourself a personal Bearer to plug into Claude Desktop / Code:</p>
       <p><a class="button" href="/team-signup">Sign up for an access key</a></p>

       <h2>Bootstrap or re-link the QBO admin connection</h2>
       <p>For the team admin only — needs the admin bootstrap token. This (re)connects your QuickBooks company under one shared admin slot at Intuit.</p>
       <p><a class="button" style="background:#0a4dad" href="/connect/quickbooks">Re-link QBO admin (admin only)</a></p>`,
    ),
  );
});

// ---- /team-signup — coworker self-service for static keys ----

function renderSignupResultHtml(plain: string, label: string | null, userId: number): string {
  const cfgSnippet = JSON.stringify(
    {
      mcpServers: {
        quickbooks: {
          command: "npx",
          args: [
            "-y",
            "mcp-remote",
            `${config.publicBaseUrl}/mcp`,
            "--header",
            `Authorization:Bearer ${plain}`,
          ],
        },
      },
    },
    null,
    2,
  );
  return htmlPage(
    "Your access key",
    `<h1>You're in</h1>
     <p>User <code>${userId}</code>${label ? ` (${label})` : ""} created.</p>
     <div class="warn"><strong>Save this key now — it will not be shown again.</strong></div>
     <pre><code>${plain}</code></pre>
     <h3>Claude Desktop config (~/Library/Application Support/Claude/claude_desktop_config.json)</h3>
     <pre><code>${cfgSnippet.replace(/</g, "&lt;")}</code></pre>
     <h3>Claude Code CLI</h3>
     <pre><code>claude mcp add --scope user --transport http quickbooks ${config.publicBaseUrl}/mcp \\
  --header "Authorization: Bearer ${plain}"</code></pre>`,
  );
}

app.get("/team-signup", async (req: Request, res: Response) => {
  // Fast path: Cloudflare Access already authenticated this user — mint
  // their key immediately, no token form. Dedupe by email so the same
  // person re-signing-up reuses their user_id and just rotates the key.
  if (cfAccessEnabled) {
    const identity = await identifyFromCfAccess(req);
    if (identity) {
      const { plain, hash } = generateApiKey();
      const user = upsertUserByLabel(identity.email, hash);
      (req as any).authedUser = { user, kind: "oauth" };
      res.type("html").send(renderSignupResultHtml(plain, identity.email, user.id));
      return;
    }
  }

  if (!config.teamSignupToken) {
    res.status(503).type("html").send(
      htmlPage(
        "Team signup disabled",
        `<h1>Team signup is disabled</h1>
         <p>The admin hasn't enabled either Cloudflare Access gating or a <code>TEAM_SIGNUP_TOKEN</code>.</p>`,
      ),
    );
    return;
  }
  res.type("html").send(
    htmlPage(
      "Team signup",
      `<h1>Team signup</h1>
       <p>Paste the team access token your admin shared with you. If valid, you'll get a personal <code>qbo_…</code> Bearer key
          to drop into your Claude Desktop / Claude Code config.</p>
       <form method="POST" action="/team-signup">
         <label for="token">Team access token</label>
         <input type="password" name="token" id="token" autocomplete="off" autofocus required>
         <label for="label">Optional label (your email or name, for your own audit)</label>
         <input type="text" name="label" id="label" autocomplete="off" placeholder="e.g. your.name@yourdomain.com">
         <p style="margin-top:18px"><button type="submit">Generate my key</button></p>
       </form>`,
    ),
  );
});

app.post("/team-signup", (req: Request, res: Response) => {
  if (!config.teamSignupToken) {
    res.status(503).json({ error: "team_signup_disabled" });
    return;
  }
  const body = (req.body ?? {}) as Record<string, string>;
  if (!body.token || body.token !== config.teamSignupToken) {
    res.status(403).type("html").send(
      htmlPage(
        "Forbidden",
        `<h1>Invalid team token</h1>
         <p>That token didn't match. Ask your admin for the current value.</p>
         <p><a href="/team-signup">Try again</a></p>`,
      ),
    );
    return;
  }
  const label = body.label?.trim() || null;
  const { plain, hash } = generateApiKey();
  const user = createUser(hash, label);
  (req as any).authedUser = { user, kind: "static" };
  res.type("html").send(renderSignupResultHtml(plain, label, user.id));
});

// ---- /connect/quickbooks — admin-only Intuit OAuth bootstrap ----
//
// Whoever runs this *replaces* the QBO admin slot at Intuit's side and
// becomes the sole upstream identity for ALL team users' API calls.
// Gate it.

const insertSession = db.prepare(
  "INSERT INTO linking_sessions (state, created_at, expires_at) VALUES (?, ?, ?)",
);
const consumeSession = db.prepare(
  "DELETE FROM linking_sessions WHERE state = ? AND expires_at > ? RETURNING state",
);
const cleanupSessions = db.prepare("DELETE FROM linking_sessions WHERE expires_at < ?");

function checkAdminToken(provided: string | undefined): boolean {
  if (!config.adminBootstrapToken) {
    // Token unset → bootstrap is open. Log loudly so the operator knows.
    console.warn(
      "ADMIN_BOOTSTRAP_TOKEN is unset — /connect/quickbooks is open to anyone who can reach the URL.",
    );
    return true;
  }
  return provided === config.adminBootstrapToken;
}

app.get("/connect/quickbooks", (req: Request, res: Response) => {
  const token = (req.query.token as string | undefined) ?? undefined;
  if (!checkAdminToken(token)) {
    if (config.adminBootstrapToken && !token) {
      // Show a prompt page so the admin can paste the token without
      // putting it in URL bar history.
      res.type("html").send(
        htmlPage(
          "Admin bootstrap",
          `<h1>Admin bootstrap</h1>
           <p>This will (re)link your QuickBooks company under the shared admin slot at Intuit.
              Running this kicks out the previous admin (if any) and assigns the user
              completing the OAuth dance as the new admin.</p>
           <form method="GET" action="/connect/quickbooks">
             <label for="token">Admin bootstrap token</label>
             <input type="password" name="token" id="token" autocomplete="off" autofocus required>
             <p style="margin-top:16px"><button type="submit">Continue to Intuit</button></p>
           </form>`,
        ),
      );
      return;
    }
    res.status(403).type("html").send(
      htmlPage("Forbidden", `<h1>Invalid admin bootstrap token</h1>`),
    );
    return;
  }

  // Token-auth bootstrap is run by the env-var primary admin. Attribute
  // the audit log row to their user (if their row exists) so the action
  // shows up under a name instead of "—".
  if (config.adminEmail) {
    const adminUser = findUserByLabel(config.adminEmail);
    if (adminUser) (req as any).authedUser = { user: adminUser, kind: "static" };
  }

  cleanupSessions.run(Date.now());
  const state = randomBytes(24).toString("base64url");
  const now = Date.now();
  insertSession.run(state, now, now + 15 * 60 * 1000);
  res.redirect(buildAuthUrl(state));
});

// ---- Intuit redirect ----

app.get("/connect/callback", async (req: Request, res: Response) => {
  const q = req.query as Record<string, string | undefined>;
  const { code, state, realmId, error, error_description } = q;

  if (error) {
    res.status(400).type("html").send(
      htmlPage(
        "Authorization failed",
        `<h1>Authorization failed</h1>
         <p><code>${error}</code>${error_description ? `: ${error_description}` : ""}</p>`,
      ),
    );
    return;
  }
  if (!code || !state || !realmId) {
    res.status(400).type("html").send(
      htmlPage("Missing parameters", `<h1>Missing parameters</h1>`),
    );
    return;
  }

  const session = consumeSession.get(state, Date.now());
  if (!session) {
    res.status(400).type("html").send(
      htmlPage(
        "Invalid or expired",
        `<h1>Invalid or expired state</h1>
         <p>Start again from <a href="/connect/quickbooks">/connect/quickbooks</a>.</p>`,
      ),
    );
    return;
  }

  try {
    const tokens = await exchangeCode(code);
    saveSharedConnection(realmId, tokens);
    // Attribute the callback row to the env-var primary admin too — same
    // reasoning as the GET /connect/quickbooks bootstrap step above.
    if (config.adminEmail) {
      const adminUser = findUserByLabel(config.adminEmail);
      if (adminUser) (req as any).authedUser = { user: adminUser, kind: "static" };
    }
    res.type("html").send(
      htmlPage(
        "QBO admin connection established",
        `<h1>QBO admin connection established</h1>
         <p>This QuickBooks company is now the shared upstream for all team users.</p>
         <p>Anyone who minted a key at <a href="/team-signup">/team-signup</a> can now query QBO via Claude.</p>`,
      ),
    );
  } catch (e) {
    console.error("Callback error:", e);
    res.status(500).type("html").send(
      htmlPage(
        "Error",
        `<h1>Something went wrong</h1>
         <pre><code>${(e as Error).message}</code></pre>`,
      ),
    );
  }
});
