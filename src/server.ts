import express, { type Request, type Response, type NextFunction } from "express";
import { randomBytes } from "node:crypto";
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StreamableHTTPServerTransport } from "@modelcontextprotocol/sdk/server/streamableHttp.js";
import { config } from "./config.js";
import { db } from "./db.js";
import { registerAllTools } from "./tools/index.js";
import { buildAuthUrl, exchangeCode } from "./intuit.js";
import { authenticate, createUser, generateApiKey } from "./auth.js";
import { deriveEncryptionKey } from "./crypto.js";
import { saveConnection } from "./qbo.js";
import { oauthRouter, completeOAuthIntuitCallback } from "./oauth/routes.js";
import { consumePending } from "./oauth/store.js";

function buildMcpServer(): McpServer {
  const server = new McpServer({ name: "qbo-mcp", version: "0.2.0" });
  registerAllTools(server);
  return server;
}

export const app = express();
app.use(express.json({ limit: "1mb" }));
app.use(express.urlencoded({ extended: true, limit: "1mb" }));

app.get("/health", (_req: Request, res: Response) => {
  res.json({ ok: true });
});

// ---- OAuth metadata + endpoints (mounted at root) ----
app.use(oauthRouter);

// ---- MCP endpoint (stateless Streamable HTTP) ----
//
// Requires a Bearer token. On missing/invalid auth we return 401 with a
// WWW-Authenticate header per RFC 9728 so OAuth-aware clients (claude.ai
// web) can discover the protected-resource metadata document and start a
// DCR/OAuth flow against this server.

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
    if (!res.headersSent) res.status(500).json({ error: "internal" });
  }
});

app.get("/mcp", (_req: Request, res: Response) => {
  res.status(405).json({ error: "method_not_allowed" });
});
app.delete("/mcp", (_req: Request, res: Response) => {
  res.status(405).json({ error: "method_not_allowed" });
});

// ---- Legacy connect flow (issues a static qbo_… key for Claude Desktop / Code) ----

const insertSession = db.prepare(
  "INSERT INTO linking_sessions (state, created_at, expires_at) VALUES (?, ?, ?)",
);
const consumeSession = db.prepare(
  "DELETE FROM linking_sessions WHERE state = ? AND expires_at > ? RETURNING state",
);
const cleanupSessions = db.prepare("DELETE FROM linking_sessions WHERE expires_at < ?");

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
  a.button { display: inline-block; background: #2ca01c; color: white;
             padding: 10px 20px; border-radius: 6px; text-decoration: none;
             font-weight: 600; }
  .warn { background: #fff8e1; border-left: 4px solid #f2b200;
          padding: 10px 14px; border-radius: 4px; margin: 16px 0; }
</style></head><body>${body}</body></html>`;
}

app.get("/", (_req: Request, res: Response) => {
  res.type("html").send(
    htmlPage(
      "QBO MCP",
      `<h1>QuickBooks Online MCP Server</h1>
       <p>Read-only access to QuickBooks Online via the Model Context Protocol.</p>
       <p>Environment: <code>${config.intuit.environment}</code></p>
       <p><a class="button" href="/connect/quickbooks">Connect QuickBooks (legacy static-key flow)</a></p>
       <p>OAuth-aware MCP clients (claude.ai web) should add this URL as a custom connector
          and let the OAuth dance run automatically:
          <code>${config.publicBaseUrl}/mcp</code>
       </p>`,
    ),
  );
});

app.get("/connect/quickbooks", (_req: Request, res: Response) => {
  cleanupSessions.run(Date.now());
  const state = randomBytes(24).toString("base64url");
  const now = Date.now();
  insertSession.run(state, now, now + 15 * 60 * 1000);
  res.redirect(buildAuthUrl(state));
});

// ---- Intuit redirect — dispatched by which state table owns the state ----

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
      htmlPage(
        "Missing parameters",
        `<h1>Missing parameters</h1>
         <p>The callback URL was invoked without the required parameters.</p>`,
      ),
    );
    return;
  }

  // 1. Try the new OAuth flow first.
  const pending = consumePending(state);
  if (pending) {
    try {
      const { redirect } = await completeOAuthIntuitCallback(pending, code, realmId);
      res.redirect(redirect);
      return;
    } catch (e) {
      console.error("OAuth-flow callback error:", e);
      res.status(500).type("html").send(
        htmlPage(
          "Error",
          `<h1>Something went wrong</h1>
           <pre><code>${(e as Error).message}</code></pre>`,
        ),
      );
      return;
    }
  }

  // 2. Fall back to the legacy linking-session (issues static qbo_… key).
  const legacy = consumeSession.get(state, Date.now());
  if (!legacy) {
    res.status(400).type("html").send(
      htmlPage(
        "Invalid or expired",
        `<h1>Invalid or expired state</h1>
         <p>The link may have been used already or expired (15 minute limit).</p>
         <p><a href="/connect/quickbooks">Start again</a></p>`,
      ),
    );
    return;
  }

  try {
    const tokens = await exchangeCode(code);
    const { plain, hash } = generateApiKey();
    const user = createUser(hash);
    saveConnection(user.id, realmId, tokens, deriveEncryptionKey(plain));

    const cfgSnippet = JSON.stringify(
      {
        mcpServers: {
          quickbooks: {
            url: `${config.publicBaseUrl}/mcp`,
            headers: { Authorization: `Bearer ${plain}` },
          },
        },
      },
      null,
      2,
    );

    res.type("html").send(
      htmlPage(
        "Connected",
        `<h1>QuickBooks connected</h1>
         <p>Company <code>realmId ${realmId}</code> linked to user <code>${user.id}</code>.</p>
         <div class="warn"><strong>Save this API key now — it will not be shown again.</strong></div>
         <pre><code>${plain}</code></pre>
         <h3>Claude Code / Claude Desktop MCP config</h3>
         <pre><code>${cfgSnippet.replace(/</g, "&lt;")}</code></pre>
         <p>Or via CLI:</p>
         <pre><code>claude mcp add --transport http quickbooks ${config.publicBaseUrl}/mcp \\
  --header "Authorization: Bearer ${plain}"</code></pre>`,
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
