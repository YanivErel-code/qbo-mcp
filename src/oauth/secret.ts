import { randomBytes } from "node:crypto";
import { existsSync, readFileSync, writeFileSync, mkdirSync } from "node:fs";
import { dirname, join } from "node:path";
import { config } from "../config.js";

/**
 * The HMAC key used to sign JWT access tokens. Persisted to disk under the same
 * data directory as the SQLite database so it survives container restarts. If
 * the file is missing on first start, a fresh 32-byte random key is generated.
 *
 * Rotating the key (delete the file, restart) invalidates every issued JWT —
 * users will be forced to re-authenticate. Refresh tokens are opaque and
 * unaffected.
 */
function loadOrCreateSecret(): Buffer {
  const dataDir = dirname(config.databasePath);
  const path = join(dataDir, "jwt-secret.bin");
  if (existsSync(path)) {
    const buf = readFileSync(path);
    if (buf.length >= 32) return buf;
    console.warn(`jwt-secret.bin too short (${buf.length} bytes), regenerating`);
  }
  mkdirSync(dataDir, { recursive: true });
  const fresh = randomBytes(32);
  writeFileSync(path, fresh, { mode: 0o600 });
  return fresh;
}

export const jwtSecret: Buffer = loadOrCreateSecret();
