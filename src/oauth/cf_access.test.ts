import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

// CF Access integration is initialized at module load time from env vars,
// so to fully exercise the verifier we'd need to set CF_ACCESS_TEAM_DOMAIN
// + CF_ACCESS_AUD before importing — but our tests/setup.ts intentionally
// leaves them unset (the production deployment uses them; tests verify
// graceful disabled behavior here).
//
// What we CAN test: the disabled-fallback behavior (cfAccessEnabled=false)
// and that readCfAccessHeader correctly extracts headers/cookies.

describe("oauth/cf_access — disabled (env unset)", () => {
  it("cfAccessEnabled is false when CF_ACCESS_TEAM_DOMAIN/AUD are unset", async () => {
    const mod = await import("./cf_access.js");
    expect(mod.cfAccessEnabled).toBe(false);
  });

  it("verifyCfAccessJwt returns null when disabled regardless of input", async () => {
    const mod = await import("./cf_access.js");
    expect(await mod.verifyCfAccessJwt("anything")).toBeNull();
    expect(await mod.verifyCfAccessJwt("")).toBeNull();
  });

  it("identifyFromCfAccess returns null when no header present", async () => {
    const mod = await import("./cf_access.js");
    const fakeReq = { header: () => undefined } as any;
    expect(await mod.identifyFromCfAccess(fakeReq)).toBeNull();
  });
});

describe("oauth/cf_access — readCfAccessHeader", () => {
  it("reads the assertion header when present", async () => {
    const mod = await import("./cf_access.js");
    const fakeReq = {
      header: (name: string) =>
        name.toLowerCase() === "cf-access-jwt-assertion" ? "tok-from-header" : undefined,
    } as any;
    expect(mod.readCfAccessHeader(fakeReq)).toBe("tok-from-header");
  });

  it("falls back to CF_Authorization cookie when header missing", async () => {
    const mod = await import("./cf_access.js");
    const fakeReq = {
      header: (name: string) => {
        const lower = name.toLowerCase();
        if (lower === "cf-access-jwt-assertion") return undefined;
        if (lower === "cookie") return "foo=bar; CF_Authorization=cookie-tok-123; baz=qux";
        return undefined;
      },
    } as any;
    expect(mod.readCfAccessHeader(fakeReq)).toBe("cookie-tok-123");
  });

  it("returns null when neither header nor cookie has the value", async () => {
    const mod = await import("./cf_access.js");
    const fakeReq = {
      header: () => undefined,
    } as any;
    expect(mod.readCfAccessHeader(fakeReq)).toBeNull();
  });
});
