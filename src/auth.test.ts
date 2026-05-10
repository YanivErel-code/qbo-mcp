import { beforeEach, describe, expect, it } from "vitest";
import {
  authenticate,
  createUser,
  findUserByApiKey,
  findUserById,
  findUserByLabel,
  generateApiKey,
  hashApiKey,
  isToolAllowed,
  parseBearer,
  setUserToolWhitelist,
  upsertUserByLabel,
} from "./auth.js";
import { clearDb } from "../tests/util.js";

describe("auth — pure helpers", () => {
  describe("parseBearer", () => {
    it("extracts the token from a well-formed header", () => {
      expect(parseBearer("Bearer abc123")).toBe("abc123");
      expect(parseBearer("bearer abc123")).toBe("abc123"); // case-insensitive
    });

    it("trims whitespace around the header value", () => {
      expect(parseBearer("  Bearer xyz  ")).toBe("xyz");
    });

    it("returns null for missing or malformed headers", () => {
      expect(parseBearer(undefined)).toBeNull();
      expect(parseBearer("")).toBeNull();
      expect(parseBearer("Basic abc")).toBeNull();
      expect(parseBearer("abc")).toBeNull();
    });

    it("handles array-form headers (Express normalises duplicates)", () => {
      expect(parseBearer(["Bearer one", "Bearer two"])).toBe("one");
    });
  });

  describe("generateApiKey", () => {
    it("produces a qbo_-prefixed plaintext and matching SHA-256 hash", () => {
      const { plain, hash } = generateApiKey();
      expect(plain.startsWith("qbo_")).toBe(true);
      expect(plain.length).toBeGreaterThan(40);
      expect(hash).toBe(hashApiKey(plain));
      expect(hash.length).toBe(64); // sha256 hex
    });

    it("produces unique keys on each call", () => {
      const a = generateApiKey();
      const b = generateApiKey();
      expect(a.plain).not.toBe(b.plain);
      expect(a.hash).not.toBe(b.hash);
    });
  });

  describe("hashApiKey", () => {
    it("is deterministic", () => {
      expect(hashApiKey("xyz")).toBe(hashApiKey("xyz"));
    });
  });

  describe("isToolAllowed", () => {
    const u = (id: number, toolWhitelist: string[] | null) => ({
      id,
      label: null,
      toolWhitelist,
      isAdmin: false,
    });

    it("allows everything when whitelist is null (default)", () => {
      const user = u(1, null);
      expect(isToolAllowed(user, "qbo_query")).toBe(true);
      expect(isToolAllowed(user, "list_customers")).toBe(true);
      expect(isToolAllowed(user, "anything_at_all")).toBe(true);
    });

    it("always allows whoami even when restricted", () => {
      expect(isToolAllowed(u(1, []), "whoami")).toBe(true);
      expect(isToolAllowed(u(1, ["list_customers"]), "whoami")).toBe(true);
    });

    it("restricts to the listed tools", () => {
      const user = u(1, ["list_customers", "list_invoices"]);
      expect(isToolAllowed(user, "list_customers")).toBe(true);
      expect(isToolAllowed(user, "list_invoices")).toBe(true);
      expect(isToolAllowed(user, "qbo_query")).toBe(false);
    });

    it("treats an empty whitelist as 'no tools except whoami'", () => {
      const user = u(1, []);
      expect(isToolAllowed(user, "whoami")).toBe(true);
      expect(isToolAllowed(user, "qbo_query")).toBe(false);
    });
  });
});

describe("auth — DB-backed", () => {
  beforeEach(() => clearDb());

  describe("createUser / findUserByApiKey / findUserById / findUserByLabel", () => {
    it("creates and looks up by api key", () => {
      const { plain, hash } = generateApiKey();
      const user = createUser(hash, "alice@test.local");
      expect(user.id).toBeGreaterThan(0);
      expect(user.label).toBe("alice@test.local");
      expect(user.toolWhitelist).toBeNull();

      const found = findUserByApiKey(plain);
      expect(found?.id).toBe(user.id);
      expect(found?.label).toBe("alice@test.local");
    });

    it("returns null for an unknown api key", () => {
      expect(findUserByApiKey("qbo_does-not-exist")).toBeNull();
      expect(findUserByApiKey(undefined)).toBeNull();
    });

    it("looks up by id and by label", () => {
      const { hash } = generateApiKey();
      const user = createUser(hash, "bob@test.local");
      expect(findUserById(user.id)?.label).toBe("bob@test.local");
      expect(findUserByLabel("bob@test.local")?.id).toBe(user.id);
      expect(findUserByLabel("nobody@test.local")).toBeNull();
    });
  });

  describe("upsertUserByLabel", () => {
    it("inserts when label is new", () => {
      const a = generateApiKey();
      const u = upsertUserByLabel("carol@test.local", a.hash);
      expect(u.label).toBe("carol@test.local");
      expect(findUserByApiKey(a.plain)?.id).toBe(u.id);
    });

    it("rotates the api key on existing label without creating a new row", () => {
      const a = generateApiKey();
      const u1 = upsertUserByLabel("dave@test.local", a.hash);

      const b = generateApiKey();
      const u2 = upsertUserByLabel("dave@test.local", b.hash);

      expect(u2.id).toBe(u1.id); // same row reused
      // Old key no longer authenticates
      expect(findUserByApiKey(a.plain)).toBeNull();
      // New key authenticates the same user_id
      expect(findUserByApiKey(b.plain)?.id).toBe(u1.id);
    });
  });

  describe("setUserToolWhitelist", () => {
    it("stores and retrieves an array as JSON", () => {
      const { hash } = generateApiKey();
      const user = createUser(hash, "perm@test.local");
      setUserToolWhitelist(user.id, ["list_customers", "list_invoices"]);
      const reloaded = findUserById(user.id);
      expect(reloaded?.toolWhitelist).toEqual(["list_customers", "list_invoices"]);
    });

    it("clears the whitelist when set to null", () => {
      const { hash } = generateApiKey();
      const user = createUser(hash, "perm2@test.local");
      setUserToolWhitelist(user.id, ["whoami"]);
      setUserToolWhitelist(user.id, null);
      expect(findUserById(user.id)?.toolWhitelist).toBeNull();
    });
  });

  describe("authenticate", () => {
    it("returns null for missing/invalid headers", async () => {
      expect(await authenticate(undefined)).toBeNull();
      expect(await authenticate("Bearer not-a-real-key")).toBeNull();
    });

    it("resolves a static qbo_ key to its user with kind='static'", async () => {
      const { plain, hash } = generateApiKey();
      const user = createUser(hash, "auth@test.local");
      const ctx = await authenticate(`Bearer ${plain}`);
      expect(ctx).not.toBeNull();
      expect(ctx!.user.id).toBe(user.id);
      expect(ctx!.kind).toBe("static");
    });
  });
});
