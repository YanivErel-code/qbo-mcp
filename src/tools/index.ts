import type { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { registerMetaTools } from "./meta.js";
import { registerQueryTools } from "./query.js";
import { registerCustomerTools } from "./customers.js";
import { registerInvoiceTools } from "./invoices.js";
import { registerReportTools } from "./reports.js";

export function registerAllTools(server: McpServer): void {
  registerMetaTools(server);
  registerQueryTools(server);
  registerCustomerTools(server);
  registerInvoiceTools(server);
  registerReportTools(server);
}
