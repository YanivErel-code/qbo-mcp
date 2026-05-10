import { createHash, randomBytes } from "node:crypto";
import { db } from "./db.js";
import { verifyAccessToken } from "./oauth/jwt.js";

const API_KEY_PREFIX = "qbo_";

export type User = {
  id: number;
  label: string | null;
  /**
   * Per-user MCP tool authorization. NULL = no restriction (all tools).
   * String[] = only these tool names are callable. `whoami` is always
   * implicitly allowed regardless of this list.
   */
  toolWhitelist: string[] | null;
};

export type AuthedUser = {
  user: User;
  /** "static" = qbo_… Bearer; "oauth" = JWT issued via /oauth/token. */
  kind: "static" | "oauth";
};

export function generateApiKey(): { plain: string; hash: string } {
  const plain = API_KEY_PREFIX + randomBytes(32).toString("base64url");
  const hash = hashApiKey(plain);
  return { plain, hash };
}

export function hashApiKey(plain: string): string {
  return createHash("sha256").update(plain).digest("hex");
}

type UserRow = {
  id: number;
  label: string | null;
  tool_whitelist: string | null;
};

function rowToUser(row: UserRow): User {
  let toolWhitelist: string[] | null = null;
  if (row.tool_whitelist) {
    try {
      const parsed = JSON.parse(row.tool_whitelist);
      if (Array.isArray(parsed)) toolWhitelist = parsed.filter((s) => typeof s === "string");
    } catch {
      // Malformed JSON — treat as unrestricted; admin should re-set it.
    }
  }
  return { id: row.id, label: row.label, toolWhitelist };
}

export function createUser(apiKeyHash: string, label: string | null = null): User {
  const now = Date.now();
  const info = db
    .prepare("INSERT INTO users (api_key_hash, label, created_at) VALUES (?, ?, ?)")
    .run(apiKeyHash, label, now);
  return { id: Number(info.lastInsertRowid), label, toolWhitelist: null };
}

export function findUserByApiKey(plain: string | undefined): User | null {
  if (!plain) return null;
  const hash = hashApiKey(plain);
  const row = db
    .prepare("SELECT id, label, tool_whitelist FROM users WHERE api_key_hash = ?")
    .get(hash) as UserRow | undefined;
  return row ? rowToUser(row) : null;
}

export function findUserById(id: number): User | null {
  const row = db
    .prepare("SELECT id, label, tool_whitelist FROM users WHERE id = ?")
    .get(id) as UserRow | undefined;
  return row ? rowToUser(row) : null;
}

export function findUserByLabel(label: string): User | null {
  const row = db
    .prepare("SELECT id, label, tool_whitelist FROM users WHERE label = ? LIMIT 1")
    .get(label) as UserRow | undefined;
  return row ? rowToUser(row) : null;
}

/**
 * Decide whether `user` may call the MCP tool named `toolName`. `whoami` is
 * always allowed (so a user can always check their own connection state and
 * permissions). A NULL `toolWhitelist` means "no restriction" — the historical
 * default. Any explicit array, even empty, gates tool calls.
 */
export function isToolAllowed(user: User, toolName: string): boolean {
  if (toolName === "whoami") return true;
  if (user.toolWhitelist === null) return true;
  return user.toolWhitelist.includes(toolName);
}

export function setUserToolWhitelist(userId: number, whitelist: string[] | null): void {
  db.prepare("UPDATE users SET tool_whitelist = ? WHERE id = ?").run(
    whitelist === null ? null : JSON.stringify(whitelist),
    userId,
  );
}

/**
 * Find-or-create a user keyed by `label` (typically a verified email from
 * Cloudflare Access). If a user with that label already exists, their
 * api_key_hash is rotated to the new value (so the previous static key
 * stops working — last-issued-key-wins). Otherwise a fresh row is created.
 *
 * Use this on flows where we trust the label as a stable identity (CF
 * Access JWT email). Don't use it for free-form user-typed labels — those
 * are not authenticated and the caller could spoof another user's row.
 */
export function upsertUserByLabel(label: string, apiKeyHash: string): User {
  const existing = findUserByLabel(label);
  if (existing) {
    db.prepare("UPDATE users SET api_key_hash = ? WHERE id = ?").run(
      apiKeyHash,
      existing.id,
    );
    return existing;
  }
  return createUser(apiKeyHash, label);
}

/**
 * Resolve an `Authorization: Bearer …` header to an AuthedUser, trying both
 * the JWT path (claude.ai web / OAuth flow) and the static-key path (Claude
 * Desktop / Code with a `qbo_…` token from `/connect/quickbooks`).
 */
export async function authenticate(
  headerValue: string | string[] | undefined,
): Promise<AuthedUser | null> {
  const presented = parseBearer(headerValue);
  if (!presented) return null;

  // Static keys are prefixed; non-prefixed tokens go through JWT first.
  if (!presented.startsWith(API_KEY_PREFIX)) {
    try {
      const verified = await verifyAccessToken(presented);
      const user = findUserById(verified.userId);
      if (user) return { user, kind: "oauth" as const };
    } catch {
      // not a valid JWT — fall through to static key
    }
  }

  const user = findUserByApiKey(presented);
  if (user) return { user, kind: "static" };
  return null;
}

export function parseBearer(headerValue: string | string[] | undefined): string | null {
  const h = Array.isArray(headerValue) ? headerValue[0] : headerValue;
  if (!h) return null;
  const m = /^Bearer\s+(.+)$/i.exec(h.trim());
  return m ? m[1] : null;
}
