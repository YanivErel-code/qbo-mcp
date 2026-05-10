import type { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { registerMetaTools } from "./meta.js";
import { registerQueryTools } from "./query.js";
import { registerCustomerTools } from "./customers.js";
import { registerInvoiceTools } from "./invoices.js";
import { registerReportTools } from "./reports.js";

/**
 * Canonical list of tool names. Keep in sync with what the registerXxxTools
 * functions actually register. Used by the admin permissions UI to render
 * a checkbox per tool, and by `isToolAllowed` to validate inbound calls.
 */
export const ALL_TOOL_NAMES = [
  "whoami",
  "qbo_query",
  "list_customers",
  "get_customer",
  "list_invoices",
  "get_invoice",
  "get_profit_and_loss",
  "get_balance_sheet",
] as const;

export type ToolName = (typeof ALL_TOOL_NAMES)[number];

export function registerAllTools(server: McpServer): void {
  registerMetaTools(server);
  registerQueryTools(server);
  registerCustomerTools(server);
  registerInvoiceTools(server);
  registerReportTools(server);
}
