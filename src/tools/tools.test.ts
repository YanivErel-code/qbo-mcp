import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import request from "supertest";
import { app } from "../server.js";
import { db } from "../db.js";
import { clearDb } from "../../tests/util.js";
import { createUser, generateApiKey } from "../auth.js";
import { saveSharedConnection } from "../qbo.js";

beforeEach(() => {
  clearDb();
  db.prepare(
    `INSERT OR IGNORE INTO users (id, api_key_hash, label, created_at)
     VALUES (0, 'shared-slot-sentinel', 'shared admin slot', 0)`,
  ).run();
  // Active QBO connection so tool handlers can reach the qbo.ts request path
  saveSharedConnection("test-realm-99", {
    accessToken: "test-access",
    refreshToken: "test-refresh",
    accessExpiresAt: Date.now() + 3_600_000,
    refreshExpiresAt: Date.now() + 86_400_000,
  });
});

afterEach(() => {
  vi.restoreAllMocks();
});

/**
 * Hits /mcp with a static-key Bearer and parses out the SSE-wrapped JSON-RPC
 * response that the MCP SDK emits.
 */
async function callTool(name: string, args: Record<string, unknown>): Promise<{
  status: number;
  rpc?: any;
  rawText: string;
}> {
  const { plain, hash } = generateApiKey();
  createUser(hash, `tool-test-${name}@test.local`);
  const res = await request(app)
    .post("/mcp")
    .set("Authorization", `Bearer ${plain}`)
    .set("Content-Type", "application/json")
    .set("Accept", "application/json, text/event-stream")
    .send({
      jsonrpc: "2.0",
      id: 1,
      method: "tools/call",
      params: { name, arguments: args },
    });
  // The SDK writes responses as SSE: `event: message\ndata: {…}\n\n`
  let rpc: any;
  const m = /^data:\s*(\{.*\})/m.exec(res.text);
  if (m) rpc = JSON.parse(m[1]);
  return { status: res.status, rpc, rawText: res.text };
}

describe("tools — qbo_query", () => {
  it("emits a SELECT against the realm and returns parsed QueryResponse", async () => {
    const fetchSpy = vi.spyOn(global, "fetch").mockResolvedValueOnce(
      new Response(
        JSON.stringify({ QueryResponse: { Customer: [{ Id: "1" }] } }),
        { status: 200, headers: { "Content-Type": "application/json" } },
      ),
    );

    const res = await callTool("qbo_query", { query: "SELECT * FROM Customer" });
    expect(res.status).toBe(200);
    expect(res.rpc?.result).toBeDefined();
    expect(fetchSpy).toHaveBeenCalled();
    const url = String(fetchSpy.mock.calls[0][0]);
    expect(url).toContain("/v3/company/test-realm-99/query");
    expect(url).toContain("query="); // the QBO query string param
  });
});

describe("tools — list_customers", () => {
  it("issues a SELECT * FROM Customer with active filter by default", async () => {
    const fetchSpy = vi.spyOn(global, "fetch").mockResolvedValueOnce(
      new Response(JSON.stringify({ QueryResponse: { Customer: [] } }), {
        status: 200,
      }),
    );
    const res = await callTool("list_customers", {});
    expect(res.status).toBe(200);
    // Decode + back to space (URL form encoding) so the SQL fragment is readable
    const url = decodeURIComponent(String(fetchSpy.mock.calls[0][0])).replace(/\+/g, " ");
    expect(url).toContain("FROM Customer");
    expect(url).toContain("Active = true");
  });

  it("appends a name filter when name_contains is set", async () => {
    const fetchSpy = vi.spyOn(global, "fetch").mockResolvedValueOnce(
      new Response(JSON.stringify({ QueryResponse: { Customer: [] } }), {
        status: 200,
      }),
    );
    await callTool("list_customers", { name_contains: "acme" });
    // Decode + back to space (URL form encoding) so the SQL fragment is readable
    const url = decodeURIComponent(String(fetchSpy.mock.calls[0][0])).replace(/\+/g, " ");
    expect(url).toContain("DisplayName LIKE '%acme%'");
  });
});

describe("tools — get_customer", () => {
  it("calls /customer/<id> and unwraps the Customer field", async () => {
    const fetchSpy = vi.spyOn(global, "fetch").mockResolvedValueOnce(
      new Response(JSON.stringify({ Customer: { Id: "42", DisplayName: "X" } }), {
        status: 200,
      }),
    );
    await callTool("get_customer", { customer_id: "42" });
    const url = String(fetchSpy.mock.calls[0][0]);
    expect(url).toContain("/v3/company/test-realm-99/customer/42");
  });
});

describe("tools — list_invoices", () => {
  it("default query includes ORDER BY TxnDate", async () => {
    const fetchSpy = vi.spyOn(global, "fetch").mockResolvedValueOnce(
      new Response(JSON.stringify({ QueryResponse: { Invoice: [] } }), {
        status: 200,
      }),
    );
    await callTool("list_invoices", {});
    // Decode + back to space (URL form encoding) so the SQL fragment is readable
    const url = decodeURIComponent(String(fetchSpy.mock.calls[0][0])).replace(/\+/g, " ");
    expect(url).toContain("FROM Invoice");
    expect(url).toContain("ORDER BY TxnDate DESC");
  });

  it("filters by customer + dates + open balance", async () => {
    const fetchSpy = vi.spyOn(global, "fetch").mockResolvedValueOnce(
      new Response(JSON.stringify({ QueryResponse: { Invoice: [] } }), {
        status: 200,
      }),
    );
    await callTool("list_invoices", {
      customer_id: "12",
      start_date: "2025-01-01",
      end_date: "2025-12-31",
      only_open: true,
    });
    // Decode + back to space (URL form encoding) so the SQL fragment is readable
    const url = decodeURIComponent(String(fetchSpy.mock.calls[0][0])).replace(/\+/g, " ");
    expect(url).toContain("CustomerRef = '12'");
    expect(url).toContain("TxnDate >= '2025-01-01'");
    expect(url).toContain("TxnDate <= '2025-12-31'");
    expect(url).toContain("Balance > '0'");
  });
});

describe("tools — get_invoice", () => {
  it("hits /invoice/<id>", async () => {
    const fetchSpy = vi.spyOn(global, "fetch").mockResolvedValueOnce(
      new Response(JSON.stringify({ Invoice: { Id: "9" } }), { status: 200 }),
    );
    await callTool("get_invoice", { invoice_id: "9" });
    expect(String(fetchSpy.mock.calls[0][0])).toContain(
      "/v3/company/test-realm-99/invoice/9",
    );
  });
});

describe("tools — reports", () => {
  it("get_profit_and_loss passes start_date + end_date", async () => {
    const fetchSpy = vi.spyOn(global, "fetch").mockResolvedValueOnce(
      new Response(JSON.stringify({ Header: {}, Rows: [] }), { status: 200 }),
    );
    await callTool("get_profit_and_loss", {
      start_date: "2025-01-01",
      end_date: "2025-03-31",
      summarize_by: "Month",
    });
    const url = String(fetchSpy.mock.calls[0][0]);
    expect(url).toContain("/reports/ProfitAndLoss");
    expect(url).toContain("start_date=2025-01-01");
    expect(url).toContain("end_date=2025-03-31");
    expect(url).toContain("summarize_column_by=Month");
  });

  it("get_balance_sheet passes end_date", async () => {
    const fetchSpy = vi.spyOn(global, "fetch").mockResolvedValueOnce(
      new Response(JSON.stringify({ Header: {}, Rows: [] }), { status: 200 }),
    );
    await callTool("get_balance_sheet", { as_of: "2025-06-30", accounting_method: "Accrual" });
    const url = String(fetchSpy.mock.calls[0][0]);
    expect(url).toContain("/reports/BalanceSheet");
    expect(url).toContain("end_date=2025-06-30");
    expect(url).toContain("accounting_method=Accrual");
  });
});

describe("tools — whoami", () => {
  it("returns connected:true when QBO call succeeds", async () => {
    vi.spyOn(global, "fetch").mockResolvedValueOnce(
      new Response(
        JSON.stringify({
          CompanyInfo: { CompanyName: "Test Co", Country: "US", Id: "1" },
        }),
        { status: 200 },
      ),
    );
    const res = await callTool("whoami", {});
    expect(res.status).toBe(200);
    const text = res.rpc?.result?.content?.[0]?.text;
    expect(text).toContain("Test Co");
    expect(text).toContain('"connected": true');
  });

  it("returns connected:false hint when no QBO connection bootstrapped", async () => {
    // Wipe the connection to simulate "not connected"
    db.prepare("DELETE FROM qbo_connections").run();

    const res = await callTool("whoami", {});
    expect(res.status).toBe(200);
    const text = res.rpc?.result?.content?.[0]?.text;
    expect(text).toContain('"connected": false');
  });
});
