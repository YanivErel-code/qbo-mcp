import "dotenv/config";
import { z } from "zod";

const schema = z.object({
  INTUIT_CLIENT_ID: z.string().min(1),
  INTUIT_CLIENT_SECRET: z.string().min(1),
  INTUIT_ENVIRONMENT: z.enum(["sandbox", "production"]).default("sandbox"),
  PUBLIC_BASE_URL: z.string().url(),
  DATABASE_PATH: z.string().default("./data/qbo-mcp.sqlite"),
  PORT: z.coerce.number().int().min(1).max(65535).default(3000),
  HOST: z.string().default("0.0.0.0"),

  // Shared secret coworkers paste at /team-signup to mint themselves a Bearer.
  // Distribute via Slack/1P; rotate by changing env + restarting. If empty,
  // self-signup is disabled.
  TEAM_SIGNUP_TOKEN: z.string().optional(),

  // Shared secret guarding /connect/quickbooks (the admin-only Intuit OAuth
  // bootstrap). If empty, anyone who can reach the server can run this flow,
  // which means anyone could become the QBO admin (then everyone else's
  // tokens at Intuit get revoked). Strongly recommend setting this.
  ADMIN_BOOTSTRAP_TOKEN: z.string().optional(),
});

const parsed = schema.safeParse(process.env);
if (!parsed.success) {
  console.error("Invalid environment configuration:");
  for (const issue of parsed.error.issues) {
    console.error(`  - ${issue.path.join(".")}: ${issue.message}`);
  }
  process.exit(1);
}
const env = parsed.data;

export const config = {
  intuit: {
    clientId: env.INTUIT_CLIENT_ID,
    clientSecret: env.INTUIT_CLIENT_SECRET,
    environment: env.INTUIT_ENVIRONMENT,
    redirectUri: `${env.PUBLIC_BASE_URL}/connect/callback`,
    scopes: ["com.intuit.quickbooks.accounting"] as const,
  },
  publicBaseUrl: env.PUBLIC_BASE_URL,
  databasePath: env.DATABASE_PATH,
  port: env.PORT,
  host: env.HOST,
  qboApiBase:
    env.INTUIT_ENVIRONMENT === "production"
      ? "https://quickbooks.api.intuit.com"
      : "https://sandbox-quickbooks.api.intuit.com",
  teamSignupToken: env.TEAM_SIGNUP_TOKEN ?? null,
  adminBootstrapToken: env.ADMIN_BOOTSTRAP_TOKEN ?? null,
};
