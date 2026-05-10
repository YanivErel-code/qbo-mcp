import { beforeEach, describe, expect, it } from "vitest";
import { clearDb } from "../../tests/util.js";
import {
  cleanupPending,
  clientSecretMatches,
  consumeAuthCode,
  consumePending,
  getClient,
  issueRefreshToken,
  newRandomToken,
  registerClient,
  rotateRefreshToken,
  saveAuthCode,
  savePending,
  sha256hex,
  verifyPkce,
} from "./store.js";
import { createUser, generateApiKey } from "../auth.js";
import { createHash } from "node:crypto";

beforeEach(() => clearDb());

describe("store — random + hashing helpers", () => {
  it("newRandomToken applies prefix and is unique", () => {
    const a = newRandomToken("test_", 16);
    const b = newRandomToken("test_", 16);
    expect(a.startsWith("test_")).toBe(true);
    expect(a).not.toBe(b);
  });

  it("sha256hex returns deterministic 64-char hex", () => {
    const h = sha256hex("abc");
    expect(h.length).toBe(64);
    expect(h).toBe(sha256hex("abc"));
  });
});

describe("store — verifyPkce", () => {
  it("validates an S256 challenge against its verifier", () => {
    const verifier = "test-code-verifier-with-enough-entropy-1234567890";
    const challenge = createHash("sha256").update(verifier).digest("base64url");
    expect(verifyPkce(challenge, "S256", verifier)).toBe(true);
    expect(verifyPkce(challenge, "S256", "wrong-verifier")).toBe(false);
  });

  it("validates a plain challenge", () => {
    expect(verifyPkce("hello", "plain", "hello")).toBe(true);
    expect(verifyPkce("hello", "plain", "world")).toBe(false);
  });

  it("rejects unknown methods", () => {
    expect(verifyPkce("hello", "S512", "hello")).toBe(false);
  });
});

describe("store — DCR clients", () => {
  it("registers a public client (token_endpoint_auth_method=none) without a secret", () => {
    const reg = registerClient({
      redirect_uris: ["https://claude.ai/cb"],
      token_endpoint_auth_method: "none",
    });
    expect(reg.client_id).toBeTruthy();
    expect(reg.client_secret).toBeNull();

    const c = getClient(reg.client_id);
    expect(c).not.toBeNull();
    expect(c!.client_secret_hash).toBeNull();
    expect(c!.redirect_uris).toEqual(["https://claude.ai/cb"]);
    expect(c!.token_endpoint_auth_method).toBe("none");
  });

  it("registers a confidential client and stores only the hashed secret", () => {
    const reg = registerClient({
      client_name: "Test",
      redirect_uris: ["https://app/cb"],
      token_endpoint_auth_method: "client_secret_post",
    });
    expect(reg.client_secret).toBeTruthy();

    const c = getClient(reg.client_id)!;
    expect(c.client_secret_hash).not.toBeNull();
    expect(c.client_secret_hash!.length).toBe(64);
    expect(clientSecretMatches(c, reg.client_secret!)).toBe(true);
    expect(clientSecretMatches(c, "wrong")).toBe(false);
  });

  it("getClient returns null for unknown ids", () => {
    expect(getClient("c_nonexistent")).toBeNull();
  });
});

describe("store — pending authz", () => {
  it("saves and consumes a pending request once", () => {
    const reg = registerClient({
      redirect_uris: ["https://app/cb"],
      token_endpoint_auth_method: "none",
    });
    savePending(
      {
        state: "st_abc",
        client_id: reg.client_id,
        client_state: "client-state",
        redirect_uri: "https://app/cb",
        scope: "qbo:access",
        code_challenge: "challenge",
        code_challenge_method: "S256",
      },
      60_000,
    );
    const consumed = consumePending("st_abc");
    expect(consumed?.state).toBe("st_abc");
    expect(consumed?.client_id).toBe(reg.client_id);
    expect(consumed?.client_state).toBe("client-state");

    // Second consume returns null (one-shot)
    expect(consumePending("st_abc")).toBeNull();
  });

  it("consumePending returns null for expired entries", () => {
    const reg = registerClient({
      redirect_uris: ["https://app/cb"],
      token_endpoint_auth_method: "none",
    });
    savePending(
      {
        state: "st_old",
        client_id: reg.client_id,
        client_state: null,
        redirect_uri: "https://app/cb",
        scope: null,
        code_challenge: "x",
        code_challenge_method: "S256",
      },
      -1, // already expired
    );
    expect(consumePending("st_old")).toBeNull();
  });

  it("cleanupPending wipes expired rows", () => {
    const reg = registerClient({
      redirect_uris: ["https://app/cb"],
      token_endpoint_auth_method: "none",
    });
    savePending(
      {
        state: "st_dead",
        client_id: reg.client_id,
        client_state: null,
        redirect_uri: "https://app/cb",
        scope: null,
        code_challenge: "x",
        code_challenge_method: "S256",
      },
      -1,
    );
    cleanupPending();
    expect(consumePending("st_dead")).toBeNull();
  });
});

describe("store — auth codes", () => {
  it("save and consume-once an authz code", () => {
    const reg = registerClient({
      redirect_uris: ["https://app/cb"],
      token_endpoint_auth_method: "none",
    });
    const { hash } = generateApiKey();
    const user = createUser(hash, "code@test.local");

    saveAuthCode(
      {
        code: "ac_xyz",
        client_id: reg.client_id,
        user_id: user.id,
        redirect_uri: "https://app/cb",
        scope: null,
        code_challenge: "x",
        code_challenge_method: "S256",
      },
      60_000,
    );

    const c1 = consumeAuthCode("ac_xyz");
    expect(c1?.code).toBe("ac_xyz");
    expect(c1?.user_id).toBe(user.id);

    // Second consume yields null (already consumed)
    expect(consumeAuthCode("ac_xyz")).toBeNull();
  });
});

describe("store — refresh tokens", () => {
  it("issue + rotate single-use", () => {
    const reg = registerClient({
      redirect_uris: ["https://app/cb"],
      token_endpoint_auth_method: "none",
    });
    const { hash } = generateApiKey();
    const user = createUser(hash, "rt@test.local");

    const rt = issueRefreshToken({
      user_id: user.id,
      client_id: reg.client_id,
      scope: null,
    });
    expect(rt.startsWith("rt_")).toBe(true);

    const rotated = rotateRefreshToken(rt);
    expect(rotated?.user_id).toBe(user.id);
    expect(rotated?.client_id).toBe(reg.client_id);

    // Already-rotated token is dead
    expect(rotateRefreshToken(rt)).toBeNull();
  });

  it("rejects unknown refresh tokens", () => {
    expect(rotateRefreshToken("rt_does-not-exist")).toBeNull();
  });
});
