import { beforeEach, describe, expect, it, vi } from "vitest";
import request from "supertest";
import { app } from "./server.js";
import { db } from "./db.js";
import { clearDb } from "../tests/util.js";
import {
  createUser,
  generateApiKey,
  setUserToolWhitelist,
} from "./auth.js";

beforeEach(() => {
  clearDb();
  // qbo_connections FK depends on user_id=0 sentinel
  db.prepare(
    `INSERT OR IGNORE INTO users (id, api_key_hash, label, created_at)
     VALUES (0, 'shared-slot-sentinel', 'shared admin slot', 0)`,
  ).run();
});

describe("server — health", () => {
  it("/health returns ok", async () => {
    const res = await request(app).get("/health");
    expect(res.status).toBe(200);
    expect(res.body).toEqual({ ok: true });
  });
});

describe("server — /mcp Bearer auth", () => {
  it("returns 401 with WWW-Authenticate challenge when Authorization is missing", async () => {
    const res = await request(app).post("/mcp").send({});
    expect(res.status).toBe(401);
    expect(res.headers["www-authenticate"]).toMatch(/^Bearer realm=/);
    expect(res.headers["www-authenticate"]).toMatch(
      /resource_metadata="http:\/\/test\.local:3000\/\.well-known\/oauth-protected-resource"/,
    );
  });

  it("returns 401 for an unknown Bearer token", async () => {
    const res = await request(app)
      .post("/mcp")
      .set("Authorization", "Bearer qbo_does-not-exist")
      .send({});
    expect(res.status).toBe(401);
    expect(res.headers["www-authenticate"]).toMatch(/error="invalid_token"/);
  });

  it("405s on GET /mcp", async () => {
    const res = await request(app).get("/mcp");
    expect(res.status).toBe(405);
  });
});

describe("server — /mcp tool authorization", () => {
  // We don't go all the way to a real tool execution (would need to mock
  // fetch + connection); we only verify the per-user authorization gate
  // before the SDK runs. A denied tool returns a JSON-RPC error -32000
  // synchronously without touching the SDK.

  function makeAuthedRequest(plain: string, body: unknown) {
    return request(app)
      .post("/mcp")
      .set("Authorization", `Bearer ${plain}`)
      .set("Accept", "application/json, text/event-stream")
      .set("Content-Type", "application/json")
      .send(body);
  }

  it("denies a tool not in the user's whitelist with -32000", async () => {
    const { plain, hash } = generateApiKey();
    const user = createUser(hash, "perm-test@test.local");
    setUserToolWhitelist(user.id, ["list_customers"]);

    const res = await makeAuthedRequest(plain, {
      jsonrpc: "2.0",
      id: 1,
      method: "tools/call",
      params: { name: "qbo_query", arguments: { query: "SELECT * FROM Customer" } },
    });

    expect(res.status).toBe(200);
    expect(res.body.error?.code).toBe(-32000);
    expect(res.body.error?.message).toMatch(/Permission denied/);
    expect(res.body.error?.message).toMatch(/qbo_query/);
  });

  it("permits an allowed tool to reach the SDK (response shape varies, but no -32000)", async () => {
    // Stub fetch so the QBO call (if it gets that far) doesn't hit the real network.
    vi.spyOn(global, "fetch").mockResolvedValue(
      new Response(JSON.stringify({}), { status: 500 }),
    );

    const { plain, hash } = generateApiKey();
    const user = createUser(hash, "allowed@test.local");
    setUserToolWhitelist(user.id, ["whoami"]);

    const res = await makeAuthedRequest(plain, {
      jsonrpc: "2.0",
      id: 1,
      method: "tools/call",
      params: { name: "whoami", arguments: {} },
    });

    // Either the SDK responded OK (200 with content) or the QBO call failed
    // upstream — but the *authorization* layer should NOT have rejected with
    // -32000 since whoami is implicitly allowed.
    expect(res.body.error?.code).not.toBe(-32000);
  });

  it("always allows whoami even when whitelist is empty", async () => {
    vi.spyOn(global, "fetch").mockResolvedValue(
      new Response(JSON.stringify({}), { status: 500 }),
    );

    const { plain, hash } = generateApiKey();
    const user = createUser(hash, "locked@test.local");
    setUserToolWhitelist(user.id, []);

    const res = await makeAuthedRequest(plain, {
      jsonrpc: "2.0",
      id: 1,
      method: "tools/call",
      params: { name: "whoami", arguments: {} },
    });

    expect(res.body.error?.code).not.toBe(-32000);
  });
});

describe("server — landing page", () => {
  it("/ renders without auth", async () => {
    const res = await request(app).get("/");
    expect(res.status).toBe(200);
    expect(res.text).toContain("QuickBooks Online MCP");
  });
});

describe("server — /team-signup", () => {
  it("GET shows form when no CF Access JWT is present (token fallback path)", async () => {
    const res = await request(app).get("/team-signup");
    expect(res.status).toBe(200);
    expect(res.text).toContain("Team signup");
    expect(res.text).toContain("token");
  });

  it("POST with wrong token returns 403", async () => {
    const res = await request(app)
      .post("/team-signup")
      .type("form")
      .send({ token: "wrong" });
    expect(res.status).toBe(403);
  });

  it("POST with correct team token mints a key", async () => {
    const res = await request(app)
      .post("/team-signup")
      .type("form")
      .send({ token: "test_team_token", label: "newuser@test.local" });
    expect(res.status).toBe(200);
    expect(res.text).toMatch(/qbo_[A-Za-z0-9_-]+/);
    expect(res.text).toContain("newuser@test.local");
  });
});

describe("server — /connect/quickbooks admin gate", () => {
  it("shows form when admin token is missing", async () => {
    const res = await request(app).get("/connect/quickbooks");
    expect(res.status).toBe(200);
    expect(res.text).toContain("Admin bootstrap");
  });

  it("rejects wrong admin token", async () => {
    const res = await request(app).get("/connect/quickbooks?token=wrong");
    expect(res.status).toBe(403);
  });

  it("redirects to Intuit OAuth on correct admin token", async () => {
    const res = await request(app).get(
      "/connect/quickbooks?token=test_admin_token",
    );
    expect(res.status).toBe(302);
    expect(res.headers.location).toMatch(/^https:\/\/appcenter\.intuit\.com\/connect\/oauth2/);
  });
});
