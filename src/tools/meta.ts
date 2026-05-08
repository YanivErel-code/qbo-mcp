import type { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { config } from "../config.js";
import { qboGet, QboNotConnectedError } from "../qbo.js";
import { getAuthFromExtra, jsonContent } from "./helpers.js";

export function registerMetaTools(server: McpServer) {
  server.registerTool(
    "whoami",
    {
      description:
        "Returns the authenticated user's ID and the QuickBooks company they've connected (if any).",
      inputSchema: {},
    },
    async (_args, extra) => {
      const auth = await getAuthFromExtra(extra);
      try {
        const info = (await qboGet(auth, "/companyinfo/1")) as any;
        const c = info?.CompanyInfo ?? {};
        return jsonContent({
          userId: auth.user.id,
          label: auth.user.label,
          environment: config.intuit.environment,
          connected: true,
          company: {
            name: c.CompanyName,
            legalName: c.LegalName,
            country: c.Country,
            realmId: c.Id,
            fiscalYearStartMonth: c.FiscalYearStartMonth,
            email: c.Email?.Address,
          },
        });
      } catch (e) {
        if (e instanceof QboNotConnectedError) {
          return jsonContent({
            userId: auth.user.id,
            label: auth.user.label,
            connected: false,
            hint: `Visit ${config.publicBaseUrl}/connect/quickbooks to link a QuickBooks company.`,
          });
        }
        throw e;
      }
    },
  );
}
