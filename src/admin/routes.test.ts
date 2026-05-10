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

describe("admin — recent activity rendering", () => {
  function insertLogRow(args: {
    user_id: number | null;
    user_label: string | null;
    method: string;
    path: string;
    tool_name: string | null;
    rpc_method: string | null;
    status: number;
  }) {
    db.prepare(
      `INSERT INTO request_log
         (ts, user_id, user_label, auth_kind, method, path, tool_name, rpc_method,
          status, duration_ms, remote_ip, error)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
    ).run(
      Date.now(),
      args.user_id,
      args.user_label,
      args.user_id ? "static" : null,
      args.method,
      args.path,
      args.tool_name,
      args.rpc_method,
      args.status,
      5,
      null,
      null,
    );
  }

  it("shows the real tool name in the tool column for tools/call rows", async () => {
    insertLogRow({
      user_id: null,
      user_label: null,
      method: "POST",
      path: "/mcp",
      tool_name: "qbo_query",
      rpc_method: "tools/call",
      status: 200,
    });
    const res = await request(app).get("/admin?token=test_admin_token");
    // The tool column should contain a <code>qbo_query</code> for this row.
    expect(res.text).toMatch(/<code>qbo_query<\/code>/);
  });

  it("does NOT render rpc_method (e.g. tools/list) inside the tool column", async () => {
    insertLogRow({
      user_id: null,
      user_label: null,
      method: "POST",
      path: "/mcp",
      tool_name: null,
      rpc_method: "tools/list",
      status: 200,
    });
    const res = await request(app).get("/admin?token=test_admin_token");
    // The previous rendering put `tools/list` inside <code>…</code>. The new
    // one places it as a muted suffix on the request column (see next test),
    // never as a <code> in the tool column.
    expect(res.text).not.toMatch(/<code>tools\/list<\/code>/);
  });

  it("shows rpc_method as a muted suffix on the request column when there's no tool name", async () => {
    insertLogRow({
      user_id: null,
      user_label: null,
      method: "POST",
      path: "/mcp",
      tool_name: null,
      rpc_method: "initialize",
      status: 200,
    });
    const res = await request(app).get("/admin?token=test_admin_token");
    expect(res.text).toMatch(/· initialize/);
  });

  it("?tool_calls=1 hides protocol noise rows (no tool_name)", async () => {
    insertLogRow({
      user_id: null,
      user_label: null,
      method: "POST",
      path: "/mcp",
      tool_name: null,
      rpc_method: "tools/list",
      status: 200,
    });
    insertLogRow({
      user_id: null,
      user_label: null,
      method: "POST",
      path: "/mcp",
      tool_name: "list_customers",
      rpc_method: "tools/call",
      status: 200,
    });
    const res = await request(app).get(
      "/admin?token=test_admin_token&tool_calls=1",
    );
    // The tools/list row's "· tools/list" suffix should NOT appear because
    // the row was filtered out. The list_customers row should be visible.
    expect(res.text).not.toMatch(/· tools\/list/);
    expect(res.text).toMatch(/<code>list_customers<\/code>/);
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
    // whoami force-included; submitted "evil_unknown_tool" filtered out;
    // ALL_TOOL_NAMES order is preserved (whoami first).
    expect(reloaded?.toolWhitelist).toEqual([
      "whoami",
      "list_customers",
      "list_invoices",
    ]);
  });

  it("POST mode=restricted with no tool checkboxes saves [whoami] (whoami always implicit)", async () => {
    const { hash } = generateApiKey();
    const u = createUser(hash, "perm-empty@test.local");
    const res = await request(app)
      .post(`/admin/users/${u.id}/permissions?token=test_admin_token`)
      .type("form")
      .send({ mode: "restricted" });
    expect(res.status).toBe(302);
    // whoami is force-included so the persisted whitelist matches what the
    // form's disabled-but-ticked whoami checkbox visually implies.
    expect(findUserById(u.id)?.toolWhitelist).toEqual(["whoami"]);
  });

  it("POST mode=restricted always preserves whoami even if not submitted", async () => {
    const { hash } = generateApiKey();
    const u = createUser(hash, "perm-whoami@test.local");
    const res = await request(app)
      .post(`/admin/users/${u.id}/permissions?token=test_admin_token`)
      .type("form")
      .send({ mode: "restricted", tool: ["list_customers"] });
    expect(res.status).toBe(302);
    expect(findUserById(u.id)?.toolWhitelist).toEqual([
      "whoami",
      "list_customers",
    ]);
  });
});
