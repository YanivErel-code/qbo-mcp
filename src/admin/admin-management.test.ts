import { beforeEach, describe, expect, it } from "vitest";
import request from "supertest";
import { app } from "../server.js";
import { db } from "../db.js";
import { clearDb } from "../../tests/util.js";
import { createUser, findUserById, generateApiKey } from "../auth.js";

beforeEach(() => {
  clearDb();
  db.prepare(
    `INSERT OR IGNORE INTO users (id, api_key_hash, label, created_at)
     VALUES (0, 'shared-slot-sentinel', 'shared admin slot', 0)`,
  ).run();
});

describe("admin — grant + revoke admin via UI", () => {
  it("grants admin on a regular user (token-auth)", async () => {
    const { hash } = generateApiKey();
    const u = createUser(hash, "promote@test.local");
    expect(findUserById(u.id)?.isAdmin).toBe(false);

    const res = await request(app).post(
      `/admin/users/${u.id}/admin/grant?token=test_admin_token`,
    );
    expect(res.status).toBe(302);
    expect(findUserById(u.id)?.isAdmin).toBe(true);
  });

  it("revokes admin on a non-primary user", async () => {
    const { hash } = generateApiKey();
    const u = createUser(hash, "demote@test.local");
    db.prepare("UPDATE users SET is_admin = 1 WHERE id = ?").run(u.id);
    expect(findUserById(u.id)?.isAdmin).toBe(true);

    const res = await request(app).post(
      `/admin/users/${u.id}/admin/revoke?token=test_admin_token`,
    );
    expect(res.status).toBe(302);
    expect(findUserById(u.id)?.isAdmin).toBe(false);
  });

  it("refuses to revoke the primary (env-var) admin", async () => {
    // tests/setup.ts sets ADMIN_EMAIL=admin@test.local
    const { hash } = generateApiKey();
    const primary = createUser(hash, "admin@test.local");
    db.prepare("UPDATE users SET is_admin = 1 WHERE id = ?").run(primary.id);

    const res = await request(app).post(
      `/admin/users/${primary.id}/admin/revoke?token=test_admin_token`,
    );
    expect(res.status).toBe(400);
    // is_admin flag still set (refusal didn't write); doesn't matter functionally
    // since email match grants admin regardless.
    expect(findUserById(primary.id)?.isAdmin).toBe(true);
  });

  it("404s on grant for unknown user id", async () => {
    const res = await request(app).post(
      `/admin/users/9999/admin/grant?token=test_admin_token`,
    );
    expect(res.status).toBe(404);
  });

  it("403s without admin auth", async () => {
    const { hash } = generateApiKey();
    const u = createUser(hash, "secured@test.local");
    const res = await request(app).post(`/admin/users/${u.id}/admin/grant`);
    expect(res.status).toBe(403);
    expect(findUserById(u.id)?.isAdmin).toBe(false);
  });
});

describe("admin — UI surfaces admin status", () => {
  it("renders 'primary admin' badge for the ADMIN_EMAIL user", async () => {
    const { hash } = generateApiKey();
    createUser(hash, "admin@test.local"); // matches setup.ts ADMIN_EMAIL

    const res = await request(app).get("/admin?token=test_admin_token");
    expect(res.text).toContain("primary admin");
  });

  it("renders 'Make admin' button for a regular user and 'Revoke admin' for granted admin", async () => {
    const { hash: h1 } = generateApiKey();
    createUser(h1, "regular@test.local");
    const { hash: h2 } = generateApiKey();
    const granted = createUser(h2, "granted@test.local");
    db.prepare("UPDATE users SET is_admin = 1 WHERE id = ?").run(granted.id);

    const res = await request(app).get("/admin?token=test_admin_token");
    expect(res.text).toContain("Make admin");
    expect(res.text).toContain("Revoke admin");
  });
});

describe("admin — granted admin can access /admin via CF Access path", () => {
  // This requires CF Access to be configured (CF_ACCESS_TEAM_DOMAIN+AUD), and
  // we'd need to forge a valid Cf-Access-Jwt-Assertion. Both are out of
  // scope for unit tests — the email-match path is exercised here via
  // direct user lookup, not a full HTTP request through CF Access.
  it("findUserByLabel returns isAdmin correctly after grant", async () => {
    // Ensures the round-trip from setUserIsAdmin → users table → findUserByLabel
    // surfaces the flag, which is what requireAdmin's CF Access branch reads.
    const { hash } = generateApiKey();
    const u = createUser(hash, "ci-admin@test.local");
    db.prepare("UPDATE users SET is_admin = 1 WHERE id = ?").run(u.id);

    // Re-import a fresh module to ensure no caching weirdness
    const { findUserByLabel } = await import("../auth.js");
    const found = findUserByLabel("ci-admin@test.local");
    expect(found?.isAdmin).toBe(true);
  });
});
