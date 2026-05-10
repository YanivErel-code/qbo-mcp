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

describe("admin — gate", () => {
  it("403s without any auth", async () => {
    const res = await request(app).get("/admin");
    expect(res.status).toBe(403);
  });

  it("403s with the wrong admin token", async () => {
    const res = await request(app).get("/admin?token=wrong");
    expect(res.status).toBe(403);
  });

  it("renders the dashboard with the correct admin token", async () => {
    const res = await request(app).get("/admin?token=test_admin_token");
    expect(res.status).toBe(200);
    expect(res.text).toContain("qbo-mcp admin");
    expect(res.text).toContain("QuickBooks connection");
    expect(res.text).toContain("Users");
  });
});

describe("admin — users table", () => {
  it("shows the active users with permissions column", async () => {
    const a = generateApiKey();
    createUser(a.hash, "alice@test.local");
    const b = generateApiKey();
    createUser(b.hash, "bob@test.local");

    const res = await request(app).get("/admin?token=test_admin_token");
    expect(res.text).toContain("alice@test.local");
    expect(res.text).toContain("bob@test.local");
    expect(res.text).toContain("permissions");
    expect(res.text).toContain("All tools"); // both default to no restriction
    expect(res.text).toContain("/permissions"); // edit link
  });

  it("hides the user_id=0 sentinel from the list", async () => {
    const res = await request(app).get("/admin?token=test_admin_token");
    expect(res.text).not.toContain("shared admin slot");
  });
});

describe("admin — revoke user", () => {
  it("403s without admin auth", async () => {
    const res = await request(app).post("/admin/users/5/revoke");
    expect(res.status).toBe(403);
  });

  it("400s on attempting to revoke user_id=0", async () => {
    const res = await request(app).post("/admin/users/0/revoke?token=test_admin_token");
    expect(res.status).toBe(400);
  });

  it("deletes a user and redirects back to /admin", async () => {
    const { hash } = generateApiKey();
    const u = createUser(hash, "to-revoke@test.local");

    const res = await request(app).post(
      `/admin/users/${u.id}/revoke?token=test_admin_token`,
    );
    expect(res.status).toBe(302);
    expect(res.headers.location).toMatch(/^\/admin/);
    expect(findUserById(u.id)).toBeNull();
  });
});

describe("admin — permissions form", () => {
  it("404s on invalid id", async () => {
    const res = await request(app).get(
      "/admin/users/9999/permissions?token=test_admin_token",
    );
    expect(res.status).toBe(404);
  });

  it("renders form with mode radios and tool checkboxes", async () => {
    const { hash } = generateApiKey();
    const u = createUser(hash, "perm-form@test.local");

    const res = await request(app).get(
      `/admin/users/${u.id}/permissions?token=test_admin_token`,
    );
    expect(res.status).toBe(200);
    expect(res.text).toContain("Permissions for user");
    expect(res.text).toContain('value="all"');
    expect(res.text).toContain('value="restricted"');
    expect(res.text).toContain("qbo_query");
    expect(res.text).toContain("list_customers");
    expect(res.text).toContain("whoami"); // included, but disabled
    expect(res.text).toContain("disabled"); // whoami checkbox is disabled
  });

  it("POST mode=all clears the whitelist", async () => {
    const { hash } = generateApiKey();
    const u = createUser(hash, "perm-clear@test.local");

    // First set a restriction directly
    db.prepare("UPDATE users SET tool_whitelist = ? WHERE id = ?").run(
      JSON.stringify(["list_customers"]),
      u.id,
    );

    const res = await request(app)
      .post(`/admin/users/${u.id}/permissions?token=test_admin_token`)
      .type("form")
      .send({ mode: "all" });
    expect(res.status).toBe(302);

    expect(findUserById(u.id)?.toolWhitelist).toBeNull();
  });

  it("POST mode=restricted with tool list saves it (filtered to known tools)", async () => {
    const { hash } = generateApiKey();
    const u = createUser(hash, "perm-restrict@test.local");

    const res = await request(app)
      .post(`/admin/users/${u.id}/permissions?token=test_admin_token`)
      .type("form")
      .send({
        mode: "restricted",
        tool: ["list_customers", "list_invoices", "evil_unknown_tool"],
      });
    expect(res.status).toBe(302);

    const reloaded = findUserById(u.id);
    expect(reloaded?.toolWhitelist).toEqual(["list_customers", "list_invoices"]);
  });

  it("POST mode=restricted with no tool checkboxes saves an empty list (lock-out)", async () => {
    const { hash } = generateApiKey();
    const u = createUser(hash, "perm-empty@test.local");
    const res = await request(app)
      .post(`/admin/users/${u.id}/permissions?token=test_admin_token`)
      .type("form")
      .send({ mode: "restricted" });
    expect(res.status).toBe(302);
    expect(findUserById(u.id)?.toolWhitelist).toEqual([]);
  });
});
