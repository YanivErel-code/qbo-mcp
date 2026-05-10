import Database from "better-sqlite3";
import { mkdirSync } from "node:fs";
import { dirname } from "node:path";
import { config } from "./config.js";

// `:memory:` is a special path for better-sqlite3 — don't try to mkdir it.
// Used by the test suite (tests/setup.ts sets DATABASE_PATH=:memory:).
if (config.databasePath !== ":memory:") {
  mkdirSync(dirname(config.databasePath), { recursive: true });
}

export const db = new Database(config.databasePath);
db.pragma("journal_mode = WAL");
db.pragma("foreign_keys = ON");

db.exec(`
CREATE TABLE IF NOT EXISTS users (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  api_key_hash TEXT UNIQUE NOT NULL,
  label TEXT,
  created_at INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS qbo_connections (
  user_id INTEGER NOT NULL,
  realm_id TEXT NOT NULL,
  access_token TEXT NOT NULL,
  refresh_token TEXT NOT NULL,
  access_expires_at INTEGER NOT NULL,
  refresh_expires_at INTEGER NOT NULL,
  updated_at INTEGER NOT NULL,
  PRIMARY KEY (user_id, realm_id),
  FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS linking_sessions (
  state TEXT PRIMARY KEY,
  created_at INTEGER NOT NULL,
  expires_at INTEGER NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_linking_expires ON linking_sessions(expires_at);

-- ---- OAuth 2.1 (Intuit-as-IdP) ----

-- Dynamic-client-registered MCP clients (e.g. claude.ai)
CREATE TABLE IF NOT EXISTS oauth_clients (
  client_id TEXT PRIMARY KEY,
  client_secret_hash TEXT,                 -- NULL for public (PKCE-only) clients
  client_name TEXT,
  redirect_uris TEXT NOT NULL,             -- JSON array
  grant_types TEXT NOT NULL,               -- JSON array
  response_types TEXT NOT NULL,            -- JSON array
  token_endpoint_auth_method TEXT NOT NULL,-- "none" | "client_secret_basic" | "client_secret_post"
  scope TEXT,
  created_at INTEGER NOT NULL
);

-- Pending /oauth/authorize requests, parked while the user is over at Intuit
CREATE TABLE IF NOT EXISTS oauth_pending (
  state TEXT PRIMARY KEY,                  -- our internal random; we send this to Intuit
  client_id TEXT NOT NULL,
  client_state TEXT,                       -- the state the MCP client originally sent us
  redirect_uri TEXT NOT NULL,
  scope TEXT,
  code_challenge TEXT NOT NULL,
  code_challenge_method TEXT NOT NULL,
  created_at INTEGER NOT NULL,
  expires_at INTEGER NOT NULL,
  FOREIGN KEY (client_id) REFERENCES oauth_clients(client_id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_oauth_pending_expires ON oauth_pending(expires_at);

-- One-shot authorization codes we hand back to the MCP client after Intuit returns
CREATE TABLE IF NOT EXISTS oauth_codes (
  code TEXT PRIMARY KEY,
  client_id TEXT NOT NULL,
  user_id INTEGER NOT NULL,
  redirect_uri TEXT NOT NULL,
  scope TEXT,
  code_challenge TEXT NOT NULL,
  code_challenge_method TEXT NOT NULL,
  expires_at INTEGER NOT NULL,
  consumed INTEGER NOT NULL DEFAULT 0,
  FOREIGN KEY (client_id) REFERENCES oauth_clients(client_id) ON DELETE CASCADE,
  FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_oauth_codes_expires ON oauth_codes(expires_at);

-- Refresh tokens (opaque). Access tokens are stateless JWTs, not stored.
CREATE TABLE IF NOT EXISTS oauth_refresh_tokens (
  token_hash TEXT PRIMARY KEY,
  client_id TEXT NOT NULL,
  user_id INTEGER NOT NULL,
  scope TEXT,
  expires_at INTEGER,                      -- NULL = no absolute expiry
  revoked INTEGER NOT NULL DEFAULT 0,
  created_at INTEGER NOT NULL,
  FOREIGN KEY (client_id) REFERENCES oauth_clients(client_id) ON DELETE CASCADE,
  FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_oauth_rt_user ON oauth_refresh_tokens(user_id);

-- ---- Per-request audit log (powers the /admin activity feed) ----
CREATE TABLE IF NOT EXISTS request_log (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  ts INTEGER NOT NULL,
  user_id INTEGER,           -- nullable: anonymous (no Bearer)
  user_label TEXT,           -- denormalized so listing the log doesn't need a join
  auth_kind TEXT,            -- "static" | "oauth" | NULL
  method TEXT NOT NULL,
  path TEXT NOT NULL,
  tool_name TEXT,            -- only set for MCP tools/call
  status INTEGER NOT NULL,
  duration_ms INTEGER,
  remote_ip TEXT,
  error TEXT                 -- truncated description on failures
);

CREATE INDEX IF NOT EXISTS idx_request_log_ts ON request_log(ts);
CREATE INDEX IF NOT EXISTS idx_request_log_user ON request_log(user_id);
CREATE INDEX IF NOT EXISTS idx_request_log_tool ON request_log(tool_name) WHERE tool_name IS NOT NULL;
`);

// Idempotent column add for rpc_method (existing rows will have NULL, which
// is fine — they just won't show the protocol method in the admin log).
try {
  db.exec("ALTER TABLE request_log ADD COLUMN rpc_method TEXT");
} catch (e) {
  // Already exists — better-sqlite3 throws "duplicate column name". Ignore.
  if (!String((e as Error).message).includes("duplicate column")) throw e;
}

// Idempotent column add for users.tool_whitelist. NULL means "no restriction"
// (default, current behavior). When set, it's a JSON array of tool names the
// user is allowed to call. `whoami` is always implicitly allowed so users can
// always self-diagnose their connection state.
try {
  db.exec("ALTER TABLE users ADD COLUMN tool_whitelist TEXT");
} catch (e) {
  if (!String((e as Error).message).includes("duplicate column")) throw e;
}

// Idempotent column add for users.is_admin. 0 = regular user (default),
// 1 = admin. The ADMIN_EMAIL env var still grants implicit primary admin
// regardless of this flag — see auth.ts isToolAllowed and admin/routes.ts
// requireAdmin. The flag is for additional admins managed via the UI.
try {
  db.exec("ALTER TABLE users ADD COLUMN is_admin INTEGER NOT NULL DEFAULT 0");
} catch (e) {
  if (!String((e as Error).message).includes("duplicate column")) throw e;
}
