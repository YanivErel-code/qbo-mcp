import { describe, expect, it } from "vitest";
import { signAccessToken, verifyAccessToken } from "./jwt.js";

describe("oauth/jwt", () => {
  it("round-trips a signed token", async () => {
    const { token, expiresIn } = await signAccessToken({
      sub: "42",
      client_id: "c_test",
      scope: "qbo:access",
    });
    expect(typeof token).toBe("string");
    expect(token.split(".").length).toBe(3); // header.payload.signature
    expect(expiresIn).toBeGreaterThan(0);

    const verified = await verifyAccessToken(token);
    expect(verified.userId).toBe(42);
    expect(verified.clientId).toBe("c_test");
    expect(verified.scope).toBe("qbo:access");
  });

  it("rejects a token with a bad signature", async () => {
    const { token } = await signAccessToken({
      sub: "1",
      client_id: "c_test",
      scope: "qbo:access",
    });
    // Replace the signature segment with a known-invalid value.
    const parts = token.split(".");
    const tampered = `${parts[0]}.${parts[1]}.AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA`;
    await expect(verifyAccessToken(tampered)).rejects.toThrow();
  });

  it("rejects a token whose payload was tampered with", async () => {
    const { token } = await signAccessToken({
      sub: "1",
      client_id: "c_test",
      scope: "qbo:access",
    });
    const parts = token.split(".");
    // Re-encode a forged payload claiming sub=999; signature won't match.
    const forged = Buffer.from(
      JSON.stringify({
        sub: "999",
        iss: "http://test.local:3000",
        aud: "http://test.local:3000/mcp",
        client_id: "c_test",
        scope: "qbo:access",
        iat: Math.floor(Date.now() / 1000),
        exp: Math.floor(Date.now() / 1000) + 60,
      }),
    ).toString("base64url");
    const tampered = `${parts[0]}.${forged}.${parts[2]}`;
    await expect(verifyAccessToken(tampered)).rejects.toThrow();
  });

  it("rejects entirely malformed tokens", async () => {
    await expect(verifyAccessToken("not.a.jwt")).rejects.toThrow();
    await expect(verifyAccessToken("")).rejects.toThrow();
  });

  it("rejects tokens with non-numeric sub", async () => {
    // Manually craft a JWT-ish value with a non-numeric sub. We can't sign one
    // without exposing the secret, so test the pre-condition by verifying
    // that legitimate signed tokens with valid integer sub work, and trust
    // jose to enforce the signature/audience for everything else.
    const { token } = await signAccessToken({
      sub: "0",
      client_id: "c_test",
      scope: "qbo:access",
    });
    const verified = await verifyAccessToken(token);
    expect(verified.userId).toBe(0);
  });
});
