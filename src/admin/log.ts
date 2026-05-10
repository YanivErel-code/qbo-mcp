import type { Request, Response, NextFunction } from "express";
import { db } from "../db.js";
import type { AuthedUser } from "../auth.js";

const MAX_ERROR_LEN = 240;

// Paths that have no user-attribution semantics (public protocol metadata,
// browser noise, healthchecks). Logging them just produces "—" rows in
// the audit table, which clutters the dashboard without forensic value.
const SKIP_LOG_PATHS = new Set([
  "/health",
  "/favicon.ico",
]);
const SKIP_LOG_PREFIXES = ["/.well-known/"];

function shouldSkipLog(path: string): boolean {
  if (SKIP_LOG_PATHS.has(path)) return true;
  return SKIP_LOG_PREFIXES.some((p) => path.startsWith(p));
}

const insert = db.prepare(
  `INSERT INTO request_log
     (ts, user_id, user_label, auth_kind, method, path, tool_name, rpc_method,
      status, duration_ms, remote_ip, error)
   VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
);

/**
 * Express middleware: writes a row to `request_log` after every response,
 * so the /admin page can show who did what.
 *
 * The handler stashes per-request enrichment on `res.locals`:
 *   - `res.locals.toolName`  set by the /mcp handler from the JSON-RPC body
 *   - `res.locals.errorNote` set by anywhere that wants to attach a short
 *      free-text error description.
 *
 * Auth is read from `(req as any).authedUser`, populated by the same
 * `requireAuth` middleware that gates /mcp. Unauthenticated requests still
 * get logged (with NULL user_id) — useful for spotting brute force attempts.
 */
export function requestLogMiddleware(req: Request, res: Response, next: NextFunction): void {
  const start = Date.now();

  res.on("finish", () => {
    try {
      const path = req.originalUrl.split("?")[0]; // strip query (avoid logging tokens)
      if (shouldSkipLog(path)) return;

      const auth: AuthedUser | undefined = (req as any).authedUser;
      const tool: string | undefined = res.locals.toolName;
      const rpc: string | undefined = res.locals.rpcMethod;
      const err: string | undefined = res.locals.errorNote;
      const remoteIp =
        (req.header("cf-connecting-ip") ??
          (req.header("x-forwarded-for")?.split(",")[0]?.trim()) ??
          req.ip) ||
        null;

      insert.run(
        start,
        auth?.user.id ?? null,
        auth?.user.label ?? null,
        auth?.kind ?? null,
        req.method,
        path,
        tool ?? null,
        rpc ?? null,
        res.statusCode,
        Date.now() - start,
        remoteIp,
        err ? err.slice(0, MAX_ERROR_LEN) : null,
      );
    } catch (e) {
      // Never let a logging error break a real request.
      console.warn("request log insert failed:", (e as Error).message);
    }
  });

  next();
}
