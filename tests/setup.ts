// Runs before any test file imports application code. Sets the env vars
// that `src/config.ts` requires at module-load time, and points the SQLite
// driver at an in-memory database.
//
// Vitest spawns one worker per test file by default, so each test file
// gets a fresh in-memory database. Within a file, tests can call
// `clearDb()` from `tests/util.ts` between cases.

process.env.INTUIT_CLIENT_ID ||= "test_client_id";
process.env.INTUIT_CLIENT_SECRET ||= "test_client_secret";
process.env.PUBLIC_BASE_URL ||= "http://test.local:3000";
process.env.DATABASE_PATH ||= ":memory:";
process.env.PORT ||= "3000";  // not actually bound by tests; just satisfies the schema
process.env.HOST ||= "127.0.0.1";
process.env.ADMIN_BOOTSTRAP_TOKEN ||= "test_admin_token";
process.env.TEAM_SIGNUP_TOKEN ||= "test_team_token";
process.env.ADMIN_EMAIL ||= "admin@test.local";
process.env.INTUIT_ENVIRONMENT ||= "sandbox";
// CF Access intentionally left unset; tests that exercise it set both vars.
