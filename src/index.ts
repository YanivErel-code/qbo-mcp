import { app } from "./server.js";
import { config } from "./config.js";

const server = app.listen(config.port, config.host, () => {
  console.log(`qbo-mcp listening on http://${config.host}:${config.port}`);
  console.log(`Public URL:   ${config.publicBaseUrl}`);
  console.log(`Environment:  ${config.intuit.environment}`);
  console.log(`DB:           ${config.databasePath}`);
});

function shutdown(signal: string): void {
  console.log(`\n${signal} received, shutting down...`);
  server.close(() => process.exit(0));
  setTimeout(() => process.exit(1), 10_000).unref();
}

process.on("SIGTERM", () => shutdown("SIGTERM"));
process.on("SIGINT", () => shutdown("SIGINT"));
