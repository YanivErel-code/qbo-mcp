import { db } from "../src/db.js";

/**
 * Wipe every table. Disables FK enforcement for the duration so order doesn't
 * matter. Tests should call this in `beforeEach` to start with a clean DB.
 */
export function clearDb(): void {
  db.pragma("foreign_keys = OFF");
  try {
    db.exec(`
      DELETE FROM request_log;
      DELETE FROM oauth_refresh_tokens;
      DELETE FROM oauth_codes;
      DELETE FROM oauth_pending;
      DELETE FROM oauth_clients;
      DELETE FROM linking_sessions;
      DELETE FROM qbo_connections;
      DELETE FROM users;
    `);
  } finally {
    db.pragma("foreign_keys = ON");
  }
}

/** Quick reset of the global fetch mock; pair with `vi.spyOn(global, "fetch")`. */
export function resetFetchMock(): void {
  // No-op helper for clarity; individual tests reset their own spies.
}
