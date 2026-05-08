import type { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { z } from "zod";
import { qboGet } from "../qbo.js";
import { getAuthFromExtra, runTool } from "./helpers.js";

export function registerReportTools(server: McpServer) {
  server.registerTool(
    "get_profit_and_loss",
    {
      description: "Profit and Loss report for a date range.",
      inputSchema: {
        start_date: z.string().describe("YYYY-MM-DD, inclusive"),
        end_date: z.string().describe("YYYY-MM-DD, inclusive"),
        summarize_by: z
          .enum(["Month", "Quarter", "Year", "Total"])
          .optional()
          .describe("Column grouping. Omit for single-column totals."),
        accounting_method: z
          .enum(["Cash", "Accrual"])
          .optional()
          .describe("Accounting method override"),
      },
    },
    async ({ start_date, end_date, summarize_by, accounting_method }, extra) => {
      await getAuthFromExtra(extra);
      return runTool(async () => {
        const q: Record<string, string> = { start_date, end_date };
        if (summarize_by) q.summarize_column_by = summarize_by;
        if (accounting_method) q.accounting_method = accounting_method;
        return qboGet("/reports/ProfitAndLoss", q);
      });
    },
  );

  server.registerTool(
    "get_balance_sheet",
    {
      description: "Balance Sheet report as of a given date.",
      inputSchema: {
        as_of: z.string().describe("YYYY-MM-DD"),
        accounting_method: z
          .enum(["Cash", "Accrual"])
          .optional()
          .describe("Accounting method override"),
      },
    },
    async ({ as_of, accounting_method }, extra) => {
      await getAuthFromExtra(extra);
      return runTool(async () => {
        const q: Record<string, string> = { end_date: as_of };
        if (accounting_method) q.accounting_method = accounting_method;
        return qboGet("/reports/BalanceSheet", q);
      });
    },
  );
}
