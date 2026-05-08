import { createHash, randomBytes } from "node:crypto";
import { db } from "../db.js";

// ---- shared helpers ----

export function newRandomToken(prefix: string, bytes = 32): string {
  return prefix + randomBytes(bytes).toString("base64url");
}

export function sha256hex(s: string): string {
  return createHash("sha256").update(s).digest("hex");
}

export function verifyPkce(
  challenge: string,
  method: string,
  verifier: string,
): boolean {
  if (method === "S256") {
    const computed = createHash("sha256").update(verifier).digest("base64url");
    return computed === challenge;
  }
  if (method === "plain") {
    return challenge === verifier;
  }
  return false;
}

// ---- oauth_clients ----

export type OAuthClient = {
  client_id: string;
  client_secret_hash: string | null;
  client_name: string | null;
  redirect_uris: string[];
  grant_types: string[];
  response_types: string[];
  token_endpoint_auth_method: string;
  scope: string | null;
  created_at: number;
};

export type RegisterClientInput = {
  client_name?: string;
  redirect_uris: string[];
  grant_types?: string[];
  response_types?: string[];
  token_endpoint_auth_method?: string;
  scope?: string;
};

export function registerClient(input: RegisterClientInput): {
  client_id: string;
  client_secret: string | null;
} {
  const client_id = newRandomToken("c_", 18);
  const authMethod = input.token_endpoint_auth_method ?? "none";
  let client_secret: string | null = null;
  let secretHash: string | null = null;
  if (authMethod !== "none") {
    client_secret = newRandomToken("cs_", 32);
    secretHash = sha256hex(client_secret);
  }
  db.prepare(
    `INSERT INTO oauth_clients
       (client_id, client_secret_hash, client_name, redirect_uris,
        grant_types, response_types, token_endpoint_auth_method, scope, created_at)
     VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
  ).run(
    client_id,
    secretHash,
    input.client_name ?? null,
    JSON.stringify(input.redirect_uris),
    JSON.stringify(input.grant_types ?? ["authorization_code", "refresh_token"]),
    JSON.stringify(input.response_types ?? ["code"]),
    authMethod,
    input.scope ?? null,
    Date.now(),
  );
  return { client_id, client_secret };
}

export function getClient(client_id: string): OAuthClient | null {
  const row = db
    .prepare("SELECT * FROM oauth_clients WHERE client_id = ?")
    .get(client_id) as any;
  if (!row) return null;
  return {
    ...row,
    redirect_uris: JSON.parse(row.redirect_uris),
    grant_types: JSON.parse(row.grant_types),
    response_types: JSON.parse(row.response_types),
  };
}

export function clientSecretMatches(client: OAuthClient, presented: string): boolean {
  if (!client.client_secret_hash) return false;
  return sha256hex(presented) === client.client_secret_hash;
}

// ---- oauth_pending ----

export type PendingAuthz = {
  state: string;
  client_id: string;
  client_state: string | null;
  redirect_uri: string;
  scope: string | null;
  code_challenge: string;
  code_challenge_method: string;
};

export function savePending(p: PendingAuthz, ttlMs: number): void {
  const now = Date.now();
  db.prepare(
    `INSERT INTO oauth_pending
       (state, client_id, client_state, redirect_uri, scope,
        code_challenge, code_challenge_method, created_at, expires_at)
     VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
  ).run(
    p.state,
    p.client_id,
    p.client_state,
    p.redirect_uri,
    p.scope,
    p.code_challenge,
    p.code_challenge_method,
    now,
    now + ttlMs,
  );
}

export function consumePending(state: string): PendingAuthz | null {
  const row = db
    .prepare(
      `DELETE FROM oauth_pending WHERE state = ? AND expires_at > ?
       RETURNING state, client_id, client_state, redirect_uri, scope,
                 code_challenge, code_challenge_method`,
    )
    .get(state, Date.now()) as PendingAuthz | undefined;
  return row ?? null;
}

export function cleanupPending(): void {
  db.prepare("DELETE FROM oauth_pending WHERE expires_at < ?").run(Date.now());
}

// ---- oauth_codes ----

export type AuthCode = {
  code: string;
  client_id: string;
  user_id: number;
  redirect_uri: string;
  scope: string | null;
  code_challenge: string;
  code_challenge_method: string;
};

export function saveAuthCode(c: AuthCode, ttlMs: number): void {
  db.prepare(
    `INSERT INTO oauth_codes
       (code, client_id, user_id, redirect_uri, scope,
        code_challenge, code_challenge_method, expires_at)
     VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
  ).run(
    c.code,
    c.client_id,
    c.user_id,
    c.redirect_uri,
    c.scope,
    c.code_challenge,
    c.code_challenge_method,
    Date.now() + ttlMs,
  );
}

export function consumeAuthCode(code: string): AuthCode | null {
  // Atomically mark consumed + return row
  const row = db
    .prepare(
      `UPDATE oauth_codes
         SET consumed = 1
       WHERE code = ? AND consumed = 0 AND expires_at > ?
       RETURNING code, client_id, user_id, redirect_uri, scope,
                 code_challenge, code_challenge_method`,
    )
    .get(code, Date.now()) as AuthCode | undefined;
  return row ?? null;
}

// ---- oauth_refresh_tokens ----

export type RefreshTokenInfo = {
  user_id: number;
  client_id: string;
  scope: string | null;
};

export function issueRefreshToken(info: RefreshTokenInfo): string {
  const token = newRandomToken("rt_", 32);
  db.prepare(
    `INSERT INTO oauth_refresh_tokens
       (token_hash, client_id, user_id, scope, expires_at, created_at)
     VALUES (?, ?, ?, ?, NULL, ?)`,
  ).run(sha256hex(token), info.client_id, info.user_id, info.scope, Date.now());
  return token;
}

export function rotateRefreshToken(presented: string): RefreshTokenInfo | null {
  const hash = sha256hex(presented);
  const row = db
    .prepare(
      `UPDATE oauth_refresh_tokens
          SET revoked = 1
        WHERE token_hash = ? AND revoked = 0
          AND (expires_at IS NULL OR expires_at > ?)
       RETURNING user_id, client_id, scope`,
    )
    .get(hash, Date.now()) as RefreshTokenInfo | undefined;
  return row ?? null;
}
