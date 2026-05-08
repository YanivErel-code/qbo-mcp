import type { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { z } from "zod";
import { qboGet, qboQuery } from "../qbo.js";
import { getAuthFromExtra, runTool } from "./helpers.js";

function sqlEscape(s: string): string {
  return s.replace(/'/g, "''");
}

export function registerCustomerTools(server: McpServer) {
  server.registerTool(
    "list_customers",
    {
      description: "List QuickBooks customers, optionally filtered by display-name substring.",
      inputSchema: {
        name_contains: z
          .string()
          .optional()
          .describe("Substring to match in DisplayName (case-insensitive in QBO)"),
        active_only: z.boolean().default(true).describe("Only include active customers"),
        max_results: z.number().int().min(1).max(1000).default(100),
      },
    },
    async ({ name_contains, active_only, max_results }, extra) => {
      await getAuthFromExtra(extra);
      return runTool(async () => {
        const where: string[] = [];
        if (active_only) where.push("Active = true");
        if (name_contains) where.push(`DisplayName LIKE '%${sqlEscape(name_contains)}%'`);
        const whereClause = where.length ? ` WHERE ${where.join(" AND ")}` : "";
        const q = `SELECT * FROM Customer${whereClause} MAXRESULTS ${max_results}`;
        const result = (await qboQuery(q)) as any;
        return result.QueryResponse ?? result;
      });
    },
  );

  server.registerTool(
    "get_customer",
    {
      description: "Get a single QuickBooks customer by ID.",
      inputSchema: {
        customer_id: z.string().describe("Customer ID"),
      },
    },
    async ({ customer_id }, extra) => {
      await getAuthFromExtra(extra);
      return runTool(async () => {
        const result = (await qboGet(`/customer/${encodeURIComponent(customer_id)}`)) as any;
        return result.Customer ?? result;
      });
    },
  );
}
