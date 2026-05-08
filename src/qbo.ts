import { config } from "./config.js";
import { db } from "./db.js";
import { type AuthedUser } from "./auth.js";
import { decryptToken, encryptToken, isEncrypted } from "./crypto.js";
import { refreshTokens, type IntuitTokens } from "./intuit.js";

type ConnectionRow = {
  user_id: number;
  realm_id: string;
  access_token: string;
  refresh_token: string;
  access_expires_at: number;
  refresh_expires_at: number;
};

const REFRESH_BUFFER_MS = 5 * 60 * 1000;

export class QboNotConnectedError extends Error {
  constructor() {
    super("This user has not connected a QuickBooks company yet");
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

function loadConnection(userId: number): ConnectionRow | null {
  const row = db
    .prepare(
      `SELECT user_id, realm_id, access_token, refresh_token,
              access_expires_at, refresh_expires_at
         FROM qbo_connections WHERE user_id = ? LIMIT 1`,
    )
    .get(userId) as ConnectionRow | undefined;
  return row ?? null;
}

/**
 * Persist tokens encrypted-at-rest with a key derived from the user's API key.
 * The server holds only `sha256(api_key)`, not the plaintext, so without the
 * user's bearer presented on a request the on-disk tokens cannot be decrypted.
 */
export function saveConnection(
  userId: number,
  realmId: string,
  tokens: IntuitTokens,
  encryptionKey: Buffer,
): void {
  const encAccess = encryptToken(tokens.accessToken, encryptionKey);
  const encRefresh = encryptToken(tokens.refreshToken, encryptionKey);
  db.prepare(
    `INSERT INTO qbo_connections
       (user_id, realm_id, access_token, refresh_token,
        access_expires_at, refresh_expires_at, updated_at)
     VALUES (?, ?, ?, ?, ?, ?, ?)
     ON CONFLICT(user_id, realm_id) DO UPDATE SET
       access_token = excluded.access_token,
       refresh_token = excluded.refresh_token,
       access_expires_at = excluded.access_expires_at,
       refresh_expires_at = excluded.refresh_expires_at,
       updated_at = excluded.updated_at`,
  ).run(
    userId,
    realmId,
    encAccess,
    encRefresh,
    tokens.accessExpiresAt,
    tokens.refreshExpiresAt,
    Date.now(),
  );
}

function deleteConnection(userId: number, realmId: string): void {
  db.prepare(
    "DELETE FROM qbo_connections WHERE user_id = ? AND realm_id = ?",
  ).run(userId, realmId);
}

async function ensureFreshAccessToken(
  conn: ConnectionRow,
  encryptionKey: Buffer,
): Promise<string> {
  // Decrypt or pass through legacy plaintext.
  let accessToken: string;
  let refreshToken: string;
  try {
    accessToken = decryptToken(conn.access_token, encryptionKey);
    refreshToken = decryptToken(conn.refresh_token, encryptionKey);
  } catch {
    // Auth-tag mismatch: corrupt data or wrong key. Force re-link.
    deleteConnection(conn.user_id, conn.realm_id);
    throw new QboNotConnectedError();
  }

  // Lazy migration: any pre-encryption row gets re-saved encrypted on first
  // touch after the upgrade. No explicit migration step needed.
  const wasLegacy =
    !isEncrypted(conn.access_token) || !isEncrypted(conn.refresh_token);
  if (wasLegacy) {
    saveConnection(
      conn.user_id,
      conn.realm_id,
      {
        accessToken,
        refreshToken,
        accessExpiresAt: conn.access_expires_at,
        refreshExpiresAt: conn.refresh_expires_at,
      },
      encryptionKey,
    );
  }

  if (conn.access_expires_at - Date.now() > REFRESH_BUFFER_MS) {
    return accessToken;
  }

  try {
    const newTokens = await refreshTokens(refreshToken);
    saveConnection(conn.user_id, conn.realm_id, newTokens, encryptionKey);
    return newTokens.accessToken;
  } catch {
    // Refresh failed — Intuit refresh tokens expire after 100 days of inactivity,
    // or if the user revoked access. Drop the stale row and force a reconnect.
    deleteConnection(conn.user_id, conn.realm_id);
    throw new QboNotConnectedError();
  }
}

async function request(
  auth: AuthedUser,
  path: string,
  query?: Record<string, string>,
): Promise<unknown> {
  const conn = loadConnection(auth.user.id);
  if (!conn) throw new QboNotConnectedError();
  const accessToken = await ensureFreshAccessToken(conn, auth.encryptionKey);

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

export async function qboGet(
  auth: AuthedUser,
  path: string,
  query?: Record<string, string>,
): Promise<any> {
  return request(auth, path, query);
}

export async function qboQuery(auth: AuthedUser, query: string): Promise<any> {
  return request(auth, "/query", { query });
}
