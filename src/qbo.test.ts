import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { clearDb } from "../tests/util.js";
import { db } from "./db.js";
import {
  getSharedRealmInfo,
  qboGet,
  qboQuery,
  QboNotConnectedError,
  QboApiError,
  saveSharedConnection,
} from "./qbo.js";

beforeEach(() => {
  clearDb();
  // Insert the user_id=0 sentinel that qbo_connections.user_id FK-references.
  db.prepare(
    `INSERT OR IGNORE INTO users (id, api_key_hash, label, created_at)
     VALUES (0, 'shared-slot-sentinel', 'shared admin slot', 0)`,
  ).run();
});

afterEach(() => {
  vi.restoreAllMocks();
});

describe("qbo — saveSharedConnection / getSharedRealmInfo", () => {
  it("saves and retrieves the shared realm info", () => {
    saveSharedConnection("realm-12345", {
      accessToken: "access-tok-A",
      refreshToken: "refresh-tok-A",
      accessExpiresAt: Date.now() + 3600_000,
      refreshExpiresAt: Date.now() + 100 * 86400_000,
    });
    const info = getSharedRealmInfo();
    expect(info?.realmId).toBe("realm-12345");
    expect(info?.updatedAt).toBeGreaterThan(0);
  });

  it("returns null when no connection exists", () => {
    expect(getSharedRealmInfo()).toBeNull();
  });

  it("replaces the previous connection on second save (only one row ever)", () => {
    saveSharedConnection("realm-1", {
      accessToken: "a",
      refreshToken: "r",
      accessExpiresAt: Date.now() + 3600_000,
      refreshExpiresAt: Date.now() + 86400_000,
    });
    saveSharedConnection("realm-2", {
      accessToken: "a2",
      refreshToken: "r2",
      accessExpiresAt: Date.now() + 3600_000,
      refreshExpiresAt: Date.now() + 86400_000,
    });
    const info = getSharedRealmInfo();
    expect(info?.realmId).toBe("realm-2");
    const count = db
      .prepare("SELECT COUNT(*) AS c FROM qbo_connections")
      .get() as { c: number };
    expect(count.c).toBe(1);
  });

  it("encrypts tokens at rest", () => {
    saveSharedConnection("realm-enc", {
      accessToken: "plaintext-secret",
      refreshToken: "plaintext-refresh",
      accessExpiresAt: Date.now() + 3600_000,
      refreshExpiresAt: Date.now() + 86400_000,
    });
    const row = db
      .prepare("SELECT access_token, refresh_token FROM qbo_connections LIMIT 1")
      .get() as { access_token: string; refresh_token: string };
    expect(row.access_token.startsWith("enc.v1.")).toBe(true);
    expect(row.refresh_token.startsWith("enc.v1.")).toBe(true);
    expect(row.access_token).not.toContain("plaintext-secret");
  });
});

describe("qbo — qboGet / qboQuery (with mocked Intuit fetch)", () => {
  it("throws QboNotConnectedError when no connection exists", async () => {
    await expect(qboGet("/anything")).rejects.toBeInstanceOf(QboNotConnectedError);
    await expect(qboQuery("SELECT * FROM Customer")).rejects.toBeInstanceOf(
      QboNotConnectedError,
    );
  });

  it("uses cached access token when not expiring soon", async () => {
    saveSharedConnection("realm-fresh", {
      accessToken: "fresh-access",
      refreshToken: "fresh-refresh",
      accessExpiresAt: Date.now() + 3600_000,
      refreshExpiresAt: Date.now() + 86400_000,
    });

    const fetchSpy = vi.spyOn(global, "fetch").mockResolvedValueOnce(
      new Response(JSON.stringify({ ok: true }), {
        status: 200,
        headers: { "Content-Type": "application/json" },
      }),
    );

    const result = await qboGet("/companyinfo/1");
    expect(result).toEqual({ ok: true });
    expect(fetchSpy).toHaveBeenCalledOnce();

    // Verify the request used the cached access token (not refreshed)
    const [url, init] = fetchSpy.mock.calls[0];
    expect(String(url)).toContain("/v3/company/realm-fresh/companyinfo/1");
    const authHeader = (init?.headers as Record<string, string>).Authorization;
    expect(authHeader).toBe("Bearer fresh-access");
  });

  it("refreshes when access token is past expiry, then makes the API call", async () => {
    saveSharedConnection("realm-stale", {
      accessToken: "stale-access",
      refreshToken: "old-refresh",
      accessExpiresAt: 0, // already expired
      refreshExpiresAt: Date.now() + 86400_000,
    });

    const fetchSpy = vi
      .spyOn(global, "fetch")
      // 1) Refresh-token call to Intuit
      .mockResolvedValueOnce(
        new Response(
          JSON.stringify({
            access_token: "new-access",
            refresh_token: "new-refresh",
            expires_in: 3600,
            x_refresh_token_expires_in: 8640000,
          }),
          { status: 200, headers: { "Content-Type": "application/json" } },
        ),
      )
      // 2) The actual QBO API call after refresh
      .mockResolvedValueOnce(
        new Response(JSON.stringify({ Customer: [] }), {
          status: 200,
          headers: { "Content-Type": "application/json" },
        }),
      );

    const result = await qboQuery("SELECT * FROM Customer");
    expect(result).toEqual({ Customer: [] });
    expect(fetchSpy).toHaveBeenCalledTimes(2);

    // First call: token endpoint
    expect(String(fetchSpy.mock.calls[0][0])).toContain("oauth.platform.intuit.com/oauth2");
    // Second call: QBO API with the NEW access token
    const apiAuth = (fetchSpy.mock.calls[1][1]?.headers as Record<string, string>).Authorization;
    expect(apiAuth).toBe("Bearer new-access");
  });

  it("deletes the connection and throws QboNotConnectedError when refresh fails", async () => {
    saveSharedConnection("realm-revoked", {
      accessToken: "x",
      refreshToken: "revoked-refresh",
      accessExpiresAt: 0,
      refreshExpiresAt: Date.now() + 86400_000,
    });

    vi.spyOn(global, "fetch").mockResolvedValueOnce(
      new Response("invalid_grant", { status: 400 }),
    );

    await expect(qboGet("/companyinfo/1")).rejects.toBeInstanceOf(
      QboNotConnectedError,
    );
    expect(getSharedRealmInfo()).toBeNull();
  });

  it("surfaces a non-2xx QBO API response as QboApiError", async () => {
    saveSharedConnection("realm-403", {
      accessToken: "ok",
      refreshToken: "r",
      accessExpiresAt: Date.now() + 3600_000,
      refreshExpiresAt: Date.now() + 86400_000,
    });

    vi.spyOn(global, "fetch").mockResolvedValueOnce(
      new Response(JSON.stringify({ Fault: { Error: [{ code: "403" }] } }), {
        status: 403,
        headers: { "Content-Type": "application/json" },
      }),
    );

    try {
      await qboGet("/companyinfo/1");
      expect.fail("should have thrown");
    } catch (e) {
      expect(e).toBeInstanceOf(QboApiError);
      expect((e as QboApiError).status).toBe(403);
    }
  });
});
