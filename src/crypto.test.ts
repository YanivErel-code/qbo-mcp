import { describe, expect, it } from "vitest";
import {
  decryptToken,
  deriveEncryptionKey,
  deriveServerSideUserKey,
  encryptToken,
  isEncrypted,
} from "./crypto.js";

describe("crypto", () => {
  describe("encryptToken / decryptToken", () => {
    it("round-trips a plaintext token", () => {
      const key = deriveEncryptionKey("test-api-key");
      const enc = encryptToken("hello world", key);
      expect(enc.startsWith("enc.v1.")).toBe(true);
      expect(decryptToken(enc, key)).toBe("hello world");
    });

    it("produces different ciphertext on each call (random IV)", () => {
      const key = deriveEncryptionKey("test-api-key");
      const a = encryptToken("same plaintext", key);
      const b = encryptToken("same plaintext", key);
      expect(a).not.toBe(b);
      // Both still decrypt correctly
      expect(decryptToken(a, key)).toBe("same plaintext");
      expect(decryptToken(b, key)).toBe("same plaintext");
    });

    it("throws when decrypted with the wrong key", () => {
      const k1 = deriveEncryptionKey("api-key-one");
      const k2 = deriveEncryptionKey("api-key-two");
      const enc = encryptToken("secret", k1);
      expect(() => decryptToken(enc, k2)).toThrow();
    });

    it("returns plaintext unchanged when input has no version prefix (legacy)", () => {
      const key = deriveEncryptionKey("test-key");
      // Legacy plaintext rows (pre-encryption) pass through.
      expect(decryptToken("legacy-plaintext-token", key)).toBe(
        "legacy-plaintext-token",
      );
    });

    it("rejects ciphertext that's too short for IV+tag", () => {
      const key = deriveEncryptionKey("test-key");
      expect(() => decryptToken("enc.v1.dGVzdA==", key)).toThrow();
    });
  });

  describe("isEncrypted", () => {
    it("recognizes the version prefix", () => {
      expect(isEncrypted("enc.v1.abc")).toBe(true);
    });

    it("rejects strings without the prefix", () => {
      expect(isEncrypted("plaintext")).toBe(false);
      expect(isEncrypted("v1.abc")).toBe(false);
      expect(isEncrypted("enc.v2.abc")).toBe(false);
    });
  });

  describe("deriveEncryptionKey", () => {
    it("produces deterministic 32-byte output for the same input", () => {
      const k1 = deriveEncryptionKey("input");
      const k2 = deriveEncryptionKey("input");
      expect(k1).toEqual(k2);
      expect(k1.length).toBe(32);
    });

    it("differs across distinct inputs", () => {
      const k1 = deriveEncryptionKey("alpha");
      const k2 = deriveEncryptionKey("beta");
      expect(k1.equals(k2)).toBe(false);
    });
  });

  describe("deriveServerSideUserKey", () => {
    it("differs from deriveEncryptionKey for the same input", () => {
      // Domain-separated info string ensures static-key vs OAuth-user keys
      // can't accidentally collide for the same input.
      const master = Buffer.from("master-secret-32-bytes-padding!!");
      const a = deriveServerSideUserKey(master, 1);
      const b = deriveEncryptionKey("master-secret-32-bytes-padding!!");
      expect(a.equals(b)).toBe(false);
    });

    it("differs across user_ids", () => {
      const master = Buffer.from("master-secret-32-bytes-padding!!");
      const k1 = deriveServerSideUserKey(master, 1);
      const k2 = deriveServerSideUserKey(master, 2);
      expect(k1.equals(k2)).toBe(false);
    });
  });

  describe("static-key vs server-side key isolation", () => {
    it("static-key encrypted blob does not decrypt with server-side key", () => {
      const userKey = deriveEncryptionKey("user-bearer");
      const master = Buffer.from("master-secret-32-bytes-padding!!");
      const serverKey = deriveServerSideUserKey(master, 1);

      const enc = encryptToken("payload", userKey);
      expect(() => decryptToken(enc, serverKey)).toThrow();
    });
  });
});
