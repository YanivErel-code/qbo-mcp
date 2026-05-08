import type { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { z } from "zod";
import { qboGet, qboQuery } from "../qbo.js";
import { getAuthFromExtra, runTool } from "./helpers.js";

function sqlEscape(s: string): string {
  return s.replace(/'/g, "''");
}

export function registerInvoiceTools(server: McpServer) {
  server.registerTool(
    "list_invoices",
    {
      description:
        "List QuickBooks invoices, optionally filtered by customer, date range, or balance status.",
      inputSchema: {
        customer_id: z.string().optional().describe("Filter to invoices for this customer"),
        start_date: z.string().optional().describe("YYYY-MM-DD, inclusive"),
        end_date: z.string().optional().describe("YYYY-MM-DD, inclusive"),
        only_open: z
          .boolean()
          .default(false)
          .describe("Only invoices with Balance > 0 (unpaid/partially paid)"),
        max_results: z.number().int().min(1).max(1000).default(100),
      },
    },
    async ({ customer_id, start_date, end_date, only_open, max_results }, extra) => {
      const auth = await getAuthFromExtra(extra);
      return runTool(async () => {
        const where: string[] = [];
        if (customer_id) where.push(`CustomerRef = '${sqlEscape(customer_id)}'`);
        if (start_date) where.push(`TxnDate >= '${sqlEscape(start_date)}'`);
        if (end_date) where.push(`TxnDate <= '${sqlEscape(end_date)}'`);
        if (only_open) where.push("Balance > '0'");
        const whereClause = where.length ? ` WHERE ${where.join(" AND ")}` : "";
        const q = `SELECT * FROM Invoice${whereClause} ORDER BY TxnDate DESC MAXRESULTS ${max_results}`;
        const result = (await qboQuery(auth, q)) as any;
        return result.QueryResponse ?? result;
      });
    },
  );

  server.registerTool(
    "get_invoice",
    {
      description: "Get a single QuickBooks invoice by ID.",
      inputSchema: {
        invoice_id: z.string().describe("Invoice ID"),
      },
    },
    async ({ invoice_id }, extra) => {
      const auth = await getAuthFromExtra(extra);
      return runTool(async () => {
        const result = (await qboGet(auth, `/invoice/${encodeURIComponent(invoice_id)}`)) as any;
        return result.Invoice ?? result;
      });
    },
  );
}
