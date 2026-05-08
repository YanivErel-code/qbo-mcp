import type { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { z } from "zod";
import { qboQuery } from "../qbo.js";
import { getAuthFromExtra, runTool } from "./helpers.js";

const DESCRIPTION = [
  "Execute a QuickBooks Online query. Uses the QBO query language (SQL-like subset).",
  "",
  "Examples:",
  "  SELECT * FROM Customer MAXRESULTS 50",
  "  SELECT * FROM Invoice WHERE TxnDate >= '2025-01-01' ORDER BY TxnDate DESC MAXRESULTS 100",
  "  SELECT COUNT(*) FROM Invoice WHERE Balance > '0'",
  "",
  "Supported entities include: Customer, Vendor, Employee, Invoice, Bill, Payment, Item,",
  "Account, Deposit, Transfer, JournalEntry, SalesReceipt, Estimate, Purchase, PurchaseOrder,",
  "CreditMemo, RefundReceipt, TimeActivity, CompanyInfo, Preferences, TaxCode, TaxRate.",
  "",
  "Pagination: use STARTPOSITION and MAXRESULTS (max 1000 per page).",
].join("\n");

export function registerQueryTools(server: McpServer) {
  server.registerTool(
    "qbo_query",
    {
      description: DESCRIPTION,
      inputSchema: {
        query: z.string().describe("QBO query string (SELECT-only)"),
      },
    },
    async ({ query }, extra) => {
      const auth = await getAuthFromExtra(extra);
      return runTool(async () => {
        const result = (await qboQuery(auth, query)) as any;
        return result.QueryResponse ?? result;
      });
    },
  );
}
