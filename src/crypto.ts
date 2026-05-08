import { createCipheriv, createDecipheriv, hkdfSync, randomBytes } from "node:crypto";

// Versioned prefix lets us distinguish encrypted blobs from legacy plaintext
// rows during the lazy migration that runs on the first call after upgrade.
const ENC_VERSION = "enc.v1.";
const ALGO = "aes-256-gcm";
const IV_LEN = 12;
const TAG_LEN = 16;
const HKDF_INFO = "qbo-mcp:token-encrypt:v1";

/**
 * Derive a 32-byte AES key from the user's plaintext API key.
 *
 * HKDF-SHA256 with a domain-separated info string. The lookup hash
 * (`sha256(api_key)` stored in `users.api_key_hash`) and the encryption key
 * are computed differently, so leaking the lookup hash does not yield the
 * encryption key.
 */
export function deriveEncryptionKey(apiKeyPlain: string): Buffer {
  const ab = hkdfSync("sha256", apiKeyPlain, Buffer.alloc(0), HKDF_INFO, 32);
  return Buffer.from(ab as ArrayBuffer);
}

/**
 * Derive a 32-byte AES key for OAuth-issued users from a server-side master
 * secret + user_id. Used for users authenticated via JWT (where there is no
 * plaintext Bearer to derive from). This is a strictly weaker protection than
 * `deriveEncryptionKey` — a full-server compromise leaks both the master and
 * the data — but it still defends against an at-rest dump that doesn't
 * exfiltrate the master.
 */
export function deriveServerSideUserKey(masterSecret: Buffer, userId: number): Buffer {
  const ab = hkdfSync(
    "sha256",
    masterSecret,
    Buffer.from(`user:${userId}`),
    "qbo-mcp:oauth-token-encrypt:v1",
    32,
  );
  return Buffer.from(ab as ArrayBuffer);
}

export function isEncrypted(stored: string): boolean {
  return stored.startsWith(ENC_VERSION);
}

export function encryptToken(plaintext: string, key: Buffer): string {
  const iv = randomBytes(IV_LEN);
  const cipher = createCipheriv(ALGO, key, iv);
  const ct = Buffer.concat([cipher.update(plaintext, "utf8"), cipher.final()]);
  const tag = cipher.getAuthTag();
  return ENC_VERSION + Buffer.concat([iv, ct, tag]).toString("base64");
}

/**
 * Decrypt a stored token. Returns the plaintext as-is if the value has no
 * version prefix (legacy unencrypted row). Throws on auth-tag mismatch
 * (corrupt data or wrong key).
 */
export function decryptToken(stored: string, key: Buffer): string {
  if (!isEncrypted(stored)) return stored;
  const blob = Buffer.from(stored.slice(ENC_VERSION.length), "base64");
  if (blob.length < IV_LEN + TAG_LEN) {
    throw new Error("encrypted token too short");
  }
  const iv = blob.subarray(0, IV_LEN);
  const tag = blob.subarray(blob.length - TAG_LEN);
  const ct = blob.subarray(IV_LEN, blob.length - TAG_LEN);
  const decipher = createDecipheriv(ALGO, key, iv);
  decipher.setAuthTag(tag);
  return Buffer.concat([decipher.update(ct), decipher.final()]).toString("utf8");
}
