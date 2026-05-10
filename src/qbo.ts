import { config } from "./config.js";
import { db } from "./db.js";
import { decryptToken, encryptToken, deriveServerSideUserKey } from "./crypto.js";
import { jwtSecret } from "./oauth/secret.js";
import { refreshTokens, type IntuitTokens } from "./intuit.js";

// ---- Shared-admin model ----
//
// Multi-user note: as of the shared-admin refactor, the qbo_connections
// table holds at most one row per realm — the *admin* connection. Every
// MCP user (regardless of how they authenticated) shares this single
// upstream Intuit refresh token. Per-user audit lives on the inbound
// MCP side (the user_id in the Bearer); per-user audit is NOT preserved
// at Intuit's side.
//
// The encryption key is derived purely server-side from `jwtSecret +
// "realm:<realm_id>"` because the shared connection isn't tied to any
// one user's plaintext Bearer.

type ConnectionRow = {
  realm_id: string;
  access_token: string;
  refresh_token: string;
  access_expires_at: number;
  refresh_expires_at: number;
};

const REFRESH_BUFFER_MS = 5 * 60 * 1000;

// We piggyback on `deriveServerSideUserKey` by passing user_id 0 (a
// reserved sentinel — no real user has id 0, since AUTOINCREMENT starts
// at 1). This keeps the crypto module unchanged. The realm_id participates
// via the salt's "user:0" form being the same across realms — fine here
// because we currently support one realm; if multi-realm support is added
// later, swap to a realm-aware HKDF info string.
const SHARED_ENCRYPTION_USER_SLOT = 0;

function sharedEncryptionKey(): Buffer {
  return deriveServerSideUserKey(jwtSecret, SHARED_ENCRYPTION_USER_SLOT);
}

export class QboNotConnectedError extends Error {
  constructor() {
    super(
      "No QuickBooks admin connection has been established yet. " +
        "An admin must run /connect/quickbooks to bootstrap.",
    );
    this.name = "QboNotConnectedError";
  }
}

export class QboApiError extends Error {
  constructor(
    public status: number,
    message: string,
    public body?: unknown,
  ) {
    super(message);
    this.name = "QboApiError";
  }
}

function loadSharedConnection(): ConnectionRow | null {
  const row = db
    .prepare(
      `SELECT realm_id, access_token, refresh_token,
              access_expires_at, refresh_expires_at
         FROM qbo_connections LIMIT 1`,
    )
    .get() as ConnectionRow | undefined;
  return row ?? null;
}

export function saveSharedConnection(realmId: string, tokens: IntuitTokens): void {
  const key = sharedEncryptionKey();
  const encAccess = encryptToken(tokens.accessToken, key);
  const encRefresh = encryptToken(tokens.refreshToken, key);
  // Wipe any prior rows — we only ever hold one shared connection.
  db.prepare("DELETE FROM qbo_connections").run();
  // user_id = 0 is the sentinel for "shared admin slot" (no real user owns it).
  db.prepare(
    `INSERT INTO qbo_connections
       (user_id, realm_id, access_token, refresh_token,
        access_expires_at, refresh_expires_at, updated_at)
     VALUES (?, ?, ?, ?, ?, ?, ?)`,
  ).run(
    SHARED_ENCRYPTION_USER_SLOT,
    realmId,
    encAccess,
    encRefresh,
    tokens.accessExpiresAt,
    tokens.refreshExpiresAt,
    Date.now(),
  );
}

function deleteSharedConnection(): void {
  db.prepare("DELETE FROM qbo_connections").run();
}

async function ensureFreshAccessToken(conn: ConnectionRow): Promise<string> {
  const key = sharedEncryptionKey();
  let accessToken: string;
  let refreshToken: string;
  try {
    accessToken = decryptToken(conn.access_token, key);
    refreshToken = decryptToken(conn.refresh_token, key);
  } catch {
    deleteSharedConnection();
    throw new QboNotConnectedError();
  }

  if (conn.access_expires_at - Date.now() > REFRESH_BUFFER_MS) {
    return accessToken;
  }

  try {
    const newTokens = await refreshTokens(refreshToken);
    saveSharedConnection(conn.realm_id, newTokens);
    return newTokens.accessToken;
  } catch {
    deleteSharedConnection();
    throw new QboNotConnectedError();
  }
}

async function request(
  path: string,
  query?: Record<string, string>,
): Promise<unknown> {
  const conn = loadSharedConnection();
  if (!conn) throw new QboNotConnectedError();
  const accessToken = await ensureFreshAccessToken(conn);

  const url = new URL(`${config.qboApiBase}/v3/company/${conn.realm_id}${path}`);
  url.searchParams.set("minorversion", "75");
  if (query) for (const [k, v] of Object.entries(query)) url.searchParams.set(k, v);

  const res = await fetch(url, {
    headers: {
      Authorization: `Bearer ${accessToken}`,
      Accept: "application/json",
    },
  });

  if (!res.ok) {
    let body: unknown = null;
    try {
      body = await res.json();
    } catch {
      body = await res.text();
    }
    throw new QboApiError(res.status, `QBO API ${res.status}`, body);
  }
  return res.json();
}

export async function qboGet(path: string, query?: Record<string, string>): Promise<any> {
  return request(path, query);
}

export async function qboQuery(query: string): Promise<any> {
  return request("/query", { query });
}

/** Inspector for /whoami and admin tooling. Does NOT decrypt tokens. */
export function getSharedRealmInfo(): { realmId: string; updatedAt: number } | null {
  const row = db
    .prepare("SELECT realm_id, updated_at FROM qbo_connections LIMIT 1")
    .get() as { realm_id: string; updated_at: number } | undefined;
  if (!row) return null;
  return { realmId: row.realm_id, updatedAt: row.updated_at };
}
