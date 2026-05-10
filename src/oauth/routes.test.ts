import { beforeEach, describe, expect, it } from "vitest";
import request from "supertest";
import { app } from "../server.js";
import { db } from "../db.js";
import { clearDb } from "../../tests/util.js";

beforeEach(() => {
  clearDb();
  db.prepare(
    `INSERT OR IGNORE INTO users (id, api_key_hash, label, created_at)
     VALUES (0, 'shared-slot-sentinel', 'shared admin slot', 0)`,
  ).run();
});

describe("oauth — discovery endpoints", () => {
  it("/.well-known/oauth-protected-resource returns RFC 9728 metadata", async () => {
    const res = await request(app).get("/.well-known/oauth-protected-resource");
    expect(res.status).toBe(200);
    expect(res.body.resource).toBe("http://test.local:3000");
    expect(res.body.authorization_servers).toContain("http://test.local:3000");
    expect(res.body.scopes_supported).toContain("qbo:access");
    expect(res.body.bearer_methods_supported).toContain("header");
  });

  it("/.well-known/oauth-authorization-server returns RFC 8414 metadata", async () => {
    const res = await request(app).get("/.well-known/oauth-authorization-server");
    expect(res.status).toBe(200);
    expect(res.body.issuer).toBe("http://test.local:3000");
    expect(res.body.authorization_endpoint).toBe(
      "http://test.local:3000/oauth/authorize",
    );
    expect(res.body.token_endpoint).toBe("http://test.local:3000/oauth/token");
    expect(res.body.registration_endpoint).toBe(
      "http://test.local:3000/oauth/register",
    );
    expect(res.body.code_challenge_methods_supported).toContain("S256");
    expect(res.body.grant_types_supported).toContain("authorization_code");
    expect(res.body.grant_types_supported).toContain("refresh_token");
  });
});

describe("oauth — Dynamic Client Registration", () => {
  it("rejects missing redirect_uris with invalid_redirect_uri", async () => {
    const res = await request(app)
      .post("/oauth/register")
      .send({ client_name: "test" });
    expect(res.status).toBe(400);
    expect(res.body.error).toBe("invalid_redirect_uri");
  });

  it("rejects http redirect_uri (only https or localhost allowed)", async () => {
    const res = await request(app)
      .post("/oauth/register")
      .send({ redirect_uris: ["http://evil.example.com/cb"] });
    expect(res.status).toBe(400);
  });

  it("accepts http://localhost redirect_uri", async () => {
    const res = await request(app)
      .post("/oauth/register")
      .send({ redirect_uris: ["http://localhost:3000/cb"] });
    expect(res.status).toBe(201);
    expect(res.body.client_id).toMatch(/^c_/);
  });

  it("registers a public client (none auth method) with no client_secret", async () => {
    const res = await request(app)
      .post("/oauth/register")
      .send({
        client_name: "Test client",
        redirect_uris: ["https://example.com/cb"],
        token_endpoint_auth_method: "none",
      });
    expect(res.status).toBe(201);
    expect(res.body.client_id).toMatch(/^c_/);
    expect(res.body.client_secret).toBeUndefined();
    expect(res.body.token_endpoint_auth_method).toBe("none");
  });

  it("registers a confidential client with a client_secret returned once", async () => {
    const res = await request(app)
      .post("/oauth/register")
      .send({
        redirect_uris: ["https://example.com/cb"],
        token_endpoint_auth_method: "client_secret_post",
      });
    expect(res.status).toBe(201);
    expect(res.body.client_secret).toMatch(/^cs_/);
  });
});

describe("oauth — /oauth/authorize consent page", () => {
  async function registerClient(): Promise<string> {
    const r = await request(app)
      .post("/oauth/register")
      .send({
        redirect_uris: ["https://example.com/cb"],
        token_endpoint_auth_method: "none",
      });
    return r.body.client_id;
  }

  it("400s on bad request shape", async () => {
    const res = await request(app).get("/oauth/authorize");
    expect(res.status).toBe(400);
  });

  it("400s for unknown client_id", async () => {
    const res = await request(app).get(
      "/oauth/authorize?response_type=code&client_id=c_unknown&redirect_uri=https%3A%2F%2Fexample.com%2Fcb&code_challenge=abc&code_challenge_method=S256",
    );
    expect(res.status).toBe(400);
  });

  it("400s on redirect_uri not registered for the client", async () => {
    const cid = await registerClient();
    const res = await request(app).get(
      `/oauth/authorize?response_type=code&client_id=${cid}&redirect_uri=https%3A%2F%2Fother.example%2Fcb&code_challenge=abc&code_challenge_method=S256`,
    );
    expect(res.status).toBe(400);
  });

  it("renders the team-token consent page when CF Access not enabled", async () => {
    const cid = await registerClient();
    const res = await request(app).get(
      `/oauth/authorize?response_type=code&client_id=${cid}&redirect_uri=https%3A%2F%2Fexample.com%2Fcb&code_challenge=abc&code_challenge_method=S256`,
    );
    expect(res.status).toBe(200);
    expect(res.text).toContain("Authorize");
    expect(res.text).toContain("team_token");
  });

  it("only accepts S256 code_challenge_method", async () => {
    const cid = await registerClient();
    const res = await request(app).get(
      `/oauth/authorize?response_type=code&client_id=${cid}&redirect_uri=https%3A%2F%2Fexample.com%2Fcb&code_challenge=abc&code_challenge_method=plain`,
    );
    expect(res.status).toBe(400);
  });
});

describe("oauth — /oauth/consent (team-token form submit)", () => {
  async function registerClientAndStartAuthorize(): Promise<{
    clientId: string;
    state: string;
  }> {
    const r1 = await request(app)
      .post("/oauth/register")
      .send({
        redirect_uris: ["https://example.com/cb"],
        token_endpoint_auth_method: "none",
      });
    const clientId = r1.body.client_id;

    const r2 = await request(app).get(
      `/oauth/authorize?response_type=code&client_id=${clientId}&redirect_uri=https%3A%2F%2Fexample.com%2Fcb&code_challenge=abc&code_challenge_method=S256`,
    );
    // Extract internal state from the rendered hidden field
    const m = /name="state" value="([^"]+)"/.exec(r2.text);
    return { clientId, state: m![1] };
  }

  it("rejects wrong team token with 403", async () => {
    const { state } = await registerClientAndStartAuthorize();
    const res = await request(app)
      .post("/oauth/consent")
      .type("form")
      .send({ state, team_token: "wrong" });
    expect(res.status).toBe(403);
  });

  it("issues an auth code on correct team token + redirects to client", async () => {
    const { state } = await registerClientAndStartAuthorize();
    const res = await request(app)
      .post("/oauth/consent")
      .type("form")
      .send({ state, team_token: "test_team_token" });
    expect(res.status).toBe(302);
    const loc = res.headers.location;
    expect(loc.startsWith("https://example.com/cb?")).toBe(true);
    expect(loc).toMatch(/[?&]code=ac_/);
  });
});

describe("oauth — /oauth/token", () => {
  async function fullAuthDance(): Promise<{
    clientId: string;
    code: string;
    verifier: string;
  }> {
    const verifier = "test-pkce-verifier-with-enough-entropy-1234567890";
    const challenge = require("node:crypto")
      .createHash("sha256")
      .update(verifier)
      .digest("base64url");

    const r1 = await request(app)
      .post("/oauth/register")
      .send({
        redirect_uris: ["https://example.com/cb"],
        token_endpoint_auth_method: "none",
      });
    const clientId = r1.body.client_id;

    const r2 = await request(app).get(
      `/oauth/authorize?response_type=code&client_id=${clientId}&redirect_uri=https%3A%2F%2Fexample.com%2Fcb&code_challenge=${challenge}&code_challenge_method=S256`,
    );
    const stateMatch = /name="state" value="([^"]+)"/.exec(r2.text);

    const r3 = await request(app)
      .post("/oauth/consent")
      .type("form")
      .send({ state: stateMatch![1], team_token: "test_team_token" });
    const codeMatch = /[?&]code=([^&]+)/.exec(r3.headers.location);
    return { clientId, code: codeMatch![1], verifier };
  }

  it("exchanges an auth code for an access + refresh token", async () => {
    const { clientId, code, verifier } = await fullAuthDance();

    const res = await request(app)
      .post("/oauth/token")
      .type("form")
      .send({
        grant_type: "authorization_code",
        code,
        redirect_uri: "https://example.com/cb",
        code_verifier: verifier,
        client_id: clientId,
      });
    expect(res.status).toBe(200);
    expect(res.body.access_token).toBeTruthy();
    expect(res.body.refresh_token).toMatch(/^rt_/);
    expect(res.body.token_type).toBe("Bearer");
    expect(res.body.expires_in).toBeGreaterThan(0);
    expect(res.body.scope).toBe("qbo:access");
  });

  it("rejects code reuse (one-shot)", async () => {
    const { clientId, code, verifier } = await fullAuthDance();
    await request(app)
      .post("/oauth/token")
      .type("form")
      .send({
        grant_type: "authorization_code",
        code,
        redirect_uri: "https://example.com/cb",
        code_verifier: verifier,
        client_id: clientId,
      });
    // Second use must fail
    const res2 = await request(app)
      .post("/oauth/token")
      .type("form")
      .send({
        grant_type: "authorization_code",
        code,
        redirect_uri: "https://example.com/cb",
        code_verifier: verifier,
        client_id: clientId,
      });
    expect(res2.status).toBe(400);
    expect(res2.body.error).toBe("invalid_grant");
  });

  it("rejects bad PKCE verifier", async () => {
    const { clientId, code } = await fullAuthDance();
    const res = await request(app)
      .post("/oauth/token")
      .type("form")
      .send({
        grant_type: "authorization_code",
        code,
        redirect_uri: "https://example.com/cb",
        code_verifier: "wrong-verifier",
        client_id: clientId,
      });
    expect(res.status).toBe(400);
    expect(res.body.error).toBe("invalid_grant");
  });

  it("supports refresh_token grant", async () => {
    const { clientId, code, verifier } = await fullAuthDance();
    const issued = await request(app)
      .post("/oauth/token")
      .type("form")
      .send({
        grant_type: "authorization_code",
        code,
        redirect_uri: "https://example.com/cb",
        code_verifier: verifier,
        client_id: clientId,
      });
    const oldRefresh = issued.body.refresh_token;

    const refreshed = await request(app)
      .post("/oauth/token")
      .type("form")
      .send({
        grant_type: "refresh_token",
        refresh_token: oldRefresh,
        client_id: clientId,
      });
    expect(refreshed.status).toBe(200);
    expect(refreshed.body.access_token).toBeTruthy();
    expect(refreshed.body.refresh_token).not.toBe(oldRefresh); // rotated

    // Old refresh token is now dead
    const reuse = await request(app)
      .post("/oauth/token")
      .type("form")
      .send({
        grant_type: "refresh_token",
        refresh_token: oldRefresh,
        client_id: clientId,
      });
    expect(reuse.status).toBe(400);
  });

  it("rejects unsupported grant_type", async () => {
    const r1 = await request(app)
      .post("/oauth/register")
      .send({
        redirect_uris: ["https://example.com/cb"],
        token_endpoint_auth_method: "none",
      });
    const res = await request(app)
      .post("/oauth/token")
      .type("form")
      .send({ grant_type: "password", client_id: r1.body.client_id });
    expect(res.status).toBe(400);
    expect(res.body.error).toBe("unsupported_grant_type");
  });
});
