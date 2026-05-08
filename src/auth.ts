import { createHash, randomBytes } from "node:crypto";
import { db } from "./db.js";
import { verifyAccessToken } from "./oauth/jwt.js";

const API_KEY_PREFIX = "qbo_";

export type User = {
  id: number;
  label: string | null;
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

export function createUser(apiKeyHash: string, label: string | null = null): User {
  const now = Date.now();
  const info = db
    .prepare("INSERT INTO users (api_key_hash, label, created_at) VALUES (?, ?, ?)")
    .run(apiKeyHash, label, now);
  return { id: Number(info.lastInsertRowid), label };
}

export function findUserByApiKey(plain: string | undefined): User | null {
  if (!plain) return null;
  const hash = hashApiKey(plain);
  const row = db
    .prepare("SELECT id, label FROM users WHERE api_key_hash = ?")
    .get(hash) as { id: number; label: string | null } | undefined;
  return row ?? null;
}

export function findUserById(id: number): User | null {
  const row = db
    .prepare("SELECT id, label FROM users WHERE id = ?")
    .get(id) as { id: number; label: string | null } | undefined;
  return row ?? null;
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
      if (user) return { user, kind: "oauth" };
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
