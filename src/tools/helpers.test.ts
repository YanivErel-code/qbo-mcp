import { describe, expect, it } from "vitest";
import { errorContent, jsonContent, runTool } from "./helpers.js";
import { QboApiError, QboNotConnectedError } from "../qbo.js";

describe("tools/helpers — content helpers", () => {
  it("jsonContent wraps a value in MCP content shape", () => {
    expect(jsonContent({ a: 1 })).toEqual({
      content: [{ type: "text", text: '{\n  "a": 1\n}' }],
    });
  });

  it("errorContent sets isError true", () => {
    expect(errorContent("oops")).toEqual({
      isError: true,
      content: [{ type: "text", text: "oops" }],
    });
  });
});

describe("tools/helpers — runTool", () => {
  it("returns jsonContent on success", async () => {
    const out = await runTool(async () => ({ ok: true }));
    expect(out.isError).toBeFalsy();
    expect(out.content[0].text).toContain('"ok": true');
  });

  it("converts QboNotConnectedError to a friendly errorContent", async () => {
    const out = await runTool(async () => {
      throw new QboNotConnectedError();
    });
    expect(out.isError).toBe(true);
    expect(out.content[0].text).toMatch(/No QuickBooks company linked/);
  });

  it("converts QboApiError with the status code", async () => {
    const out = await runTool(async () => {
      throw new QboApiError(401, "QBO API 401", { fault: "x" });
    });
    expect(out.isError).toBe(true);
    expect(out.content[0].text).toContain("401");
    expect(out.content[0].text).toContain("fault");
  });

  it("converts generic errors to plain text", async () => {
    const out = await runTool(async () => {
      throw new Error("something broke");
    });
    expect(out.isError).toBe(true);
    expect(out.content[0].text).toBe("something broke");
  });

  it("converts non-Error throws to a string", async () => {
    const out = await runTool(async () => {
      // eslint-disable-next-line @typescript-eslint/no-throw-literal
      throw "raw string thrown";
    });
    expect(out.isError).toBe(true);
    expect(out.content[0].text).toBe("raw string thrown");
  });
});
