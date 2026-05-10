import { beforeEach, describe, expect, it } from "vitest";
import request from "supertest";
import { app } from "../server.js";
import { db } from "../db.js";
import { clearDb } from "../../tests/util.js";
import { createUser, generateApiKey } from "../auth.js";

beforeEach(() => {
  clearDb();
  db.prepare(
    `INSERT OR IGNORE INTO users (id, api_key_hash, label, created_at)
     VALUES (0, 'shared-slot-sentinel', 'shared admin slot', 0)`,
  ).run();
});

function logRowsFor(path: string) {
  return db
    .prepare(
      "SELECT user_id, user_label, auth_kind, status FROM request_log WHERE path = ? ORDER BY ts DESC",
    )
    .all(path) as Array<{
      user_id: number | null;
      user_label: string | null;
      auth_kind: string | null;
      status: number;
    }>;
}

describe("request log — skip noise paths", () => {
  it("does NOT log /health", async () => {
    await request(app).get("/health");
    expect(logRowsFor("/health")).toHaveLength(0);
  });

  it("does NOT log /favicon.ico", async () => {
    await request(app).get("/favicon.ico");
    expect(logRowsFor("/favicon.ico")).toHaveLength(0);
  });

  it("does NOT log /.well-known/oauth-protected-resource", async () => {
    await request(app).get("/.well-known/oauth-protected-resource");
    expect(logRowsFor("/.well-known/oauth-protected-resource")).toHaveLength(0);
  });

  it("does NOT log /.well-known/oauth-authorization-server", async () => {
    await request(app).get("/.well-known/oauth-authorization-server");
    expect(logRowsFor("/.well-known/oauth-authorization-server")).toHaveLength(0);
  });

  it("DOES still log /admin (not in skip list)", async () => {
    await request(app).get("/admin?token=test_admin_token");
    expect(logRowsFor("/admin").length).toBeGreaterThan(0);
  });
});

describe("request log — admin attribution", () => {
  it("attributes /admin token-bypass to ADMIN_EMAIL user when their row exists", async () => {
    // tests/setup.ts sets ADMIN_EMAIL=admin@test.local
    const { hash } = generateApiKey();
    createUser(hash, "admin@test.local");

    const res = await request(app).get("/admin?token=test_admin_token");
    expect(res.status).toBe(200);

    const rows = logRowsFor("/admin");
    expect(rows.length).toBeGreaterThan(0);
    expect(rows[0].user_label).toBe("admin@test.local");
    expect(rows[0].auth_kind).toBe("static");
  });

  it("leaves user_id NULL when ADMIN_EMAIL has no users row yet", async () => {
    // No users row inserted for admin@test.local — the env-var admin
    // hasn't signed up via /team-signup, so no row to attribute against.
    const res = await request(app).get("/admin?token=test_admin_token");
    expect(res.status).toBe(200);

    const rows = logRowsFor("/admin");
    expect(rows.length).toBeGreaterThan(0);
    expect(rows[0].user_id).toBeNull();
  });

  it("attributes POST /admin/users/:id/revoke with token-bypass to ADMIN_EMAIL user", async () => {
    const { hash: ah } = generateApiKey();
    createUser(ah, "admin@test.local");
    const { hash: vh } = generateApiKey();
    const victim = createUser(vh, "to-revoke@test.local");

    const res = await request(app).post(
      `/admin/users/${victim.id}/revoke?token=test_admin_token`,
    );
    expect(res.status).toBe(302);

    const rows = logRowsFor(`/admin/users/${victim.id}/revoke`);
    expect(rows.length).toBeGreaterThan(0);
    expect(rows[0].user_label).toBe("admin@test.local");
  });
});

describe("request log — team signup attribution", () => {
  it("attributes POST /team-signup with valid token to the newly-created user", async () => {
    const res = await request(app)
      .post("/team-signup")
      .type("form")
      .send({ token: "test_team_token", label: "newhire@test.local" });
    expect(res.status).toBe(200);

    const rows = logRowsFor("/team-signup");
    expect(rows.length).toBeGreaterThan(0);
    expect(rows[0].user_label).toBe("newhire@test.local");
    expect(rows[0].auth_kind).toBe("static");
  });
});
