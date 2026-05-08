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
        const info = (await qboGet("/companyinfo/1")) as any;
        const c = info?.CompanyInfo ?? {};
        return jsonContent({
          userId: auth.user.id,
          label: auth.user.label,
          authMethod: auth.kind,
          environment: config.intuit.environment,
          connected: true,
          // Reminder: company info comes from the *shared* admin connection,
          // not from this user's own Intuit grant. The admin (whoever ran
          // /connect/quickbooks) is whose tokens are talking to QBO.
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
            authMethod: auth.kind,
            connected: false,
            hint:
              "No QuickBooks admin connection has been bootstrapped yet. " +
              `Whoever has the admin token should visit ${config.publicBaseUrl}/connect/quickbooks.`,
          });
        }
        throw e;
      }
    },
  );
}
