import { type Request, type Response, Router } from "express";
import { db } from "../db.js";
import { config } from "../config.js";
import { identifyFromCfAccess } from "../oauth/cf_access.js";
import { getSharedRealmInfo } from "../qbo.js";
import { findUserById, findUserByLabel, setUserIsAdmin, setUserToolWhitelist } from "../auth.js";
import { ALL_TOOL_NAMES } from "../tools/index.js";

export const adminRouter = Router();

// ---- Admin gate ----
//
// Two ways to be the admin:
//   1. Cloudflare Access JWT whose email matches `config.adminEmail`. Pleasant
//      because the CF Access policy on /admin* automatically enforces that
//      you're an approved user, and the email check pins it to one user.
//   2. `?token=<ADMIN_BOOTSTRAP_TOKEN>` query param. Useful as a break-glass
//      when CF Access is misconfigured or unavailable. Same token used for
//      /connect/quickbooks bootstrap.

type AdminContext = { reason: "cf_access" | "token"; email: string | null };

async function isAdmin(req: Request): Promise<AdminContext | null> {
  // 1. Token bypass — break-glass for when CF Access is broken or for the
  //    initial bootstrap before any admins exist in the DB.
  const tok = (req.query.token as string | undefined) ?? undefined;
  if (config.adminBootstrapToken && tok && tok === config.adminBootstrapToken) {
    return { reason: "token", email: null };
  }

  // 2. CF Access JWT — accepted if either:
  //    a. email matches the env var ADMIN_EMAIL (primary admin, can't be
  //       revoked via UI), OR
  //    b. email matches a `users` row whose is_admin flag is 1 (granted
  //       via the /admin UI by another admin).
  const identity = await identifyFromCfAccess(req);
  if (identity) {
    if (
      config.adminEmail &&
      identity.email.toLowerCase() === config.adminEmail.toLowerCase()
    ) {
      return { reason: "cf_access", email: identity.email };
    }
    const user = findUserByLabel(identity.email);
    if (user?.isAdmin) {
      return { reason: "cf_access", email: identity.email };
    }
  }
  return null;
}

function isPrimaryAdmin(label: string | null): boolean {
  if (!label || !config.adminEmail) return false;
  return label.toLowerCase() === config.adminEmail.toLowerCase();
}

async function requireAdmin(req: Request, res: Response): Promise<AdminContext | null> {
  const ctx = await isAdmin(req);
  if (!ctx) {
    res.status(403).type("html").send(
      page("Forbidden", `<h1>Forbidden</h1>
        <p>This page requires the admin identity. If you have the admin token,
           append <code>?token=…</code> to the URL.</p>`),
    );
    return null;
  }
  // Attribute admin actions to a real user_id so /admin browsing shows up
  // in the audit log under a name instead of anonymous "—".
  //   - cf_access reason: email is the verified CF Access claim; lookup by label.
  //   - token reason:     no email; attribute to the env-var primary admin
  //                       (ADMIN_EMAIL) if their users row exists. Token-auth
  //                       semantically *is* the primary admin, so this is
  //                       the correct attribution.
  if (ctx.email) {
    const user = findUserByLabel(ctx.email);
    if (user) (req as any).authedUser = { user, kind: "oauth" };
  } else if (ctx.reason === "token" && config.adminEmail) {
    const user = findUserByLabel(config.adminEmail);
    if (user) (req as any).authedUser = { user, kind: "static" };
  }
  return ctx;
}

// ---- HTML helpers ----

function page(title: string, body: string): string {
  return `<!doctype html>
<html><head><meta charset="utf-8"><title>${title} · qbo-mcp admin</title>
<style>
  :root { color-scheme: light dark; }
  body { font-family: system-ui, -apple-system, sans-serif; max-width: 1100px;
         margin: 32px auto; padding: 0 16px; line-height: 1.5; }
  h1 { margin-top: 0; }
  h2 { margin-top: 32px; border-bottom: 1px solid #ddd; padding-bottom: 6px; }
  table { width: 100%; border-collapse: collapse; font-size: 13px; }
  th, td { padding: 6px 8px; text-align: left; border-bottom: 1px solid #eee;
           vertical-align: top; }
  th { background: #f7f7f7; font-weight: 600; }
  tr:hover td { background: #fafafa; }
  code, .mono { font-family: ui-monospace, Menlo, monospace; font-size: 13px; }
  .pill { display: inline-block; padding: 2px 8px; border-radius: 10px;
          font-size: 12px; font-weight: 600; background: #eef; color: #225; }
  .pill.static { background: #e6f0ff; color: #134; }
  .pill.oauth  { background: #e7f7ea; color: #163; }
  .pill.err    { background: #fde7e7; color: #722; }
  .pill.ok     { background: #e7f3e7; color: #265; }
  button, .button { background: #b00; color: white; border: 0; padding: 4px 10px;
                    border-radius: 4px; font-size: 13px; cursor: pointer; }
  .muted { color: #888; }
  .nowrap { white-space: nowrap; }
  form.inline { display: inline; }
  .topnav a { margin-right: 16px; font-weight: 600; }
  details summary { cursor: pointer; }
  pre { background: #f3f3f3; padding: 8px; border-radius: 4px; font-size: 12px;
        white-space: pre-wrap; word-break: break-word; max-width: 80ch; }
  .filter-panel { border: 1px solid #ccc; border-radius: 6px; padding: 8px 12px;
                  margin-top: 4px; min-width: 240px; background: #fafafa;
                  max-height: 280px; overflow-y: auto; }
  .filter-details { display: inline-block; vertical-align: middle; }
  .filter-summary { display: inline-block; font-size: 13px; cursor: pointer;
                    padding: 4px 12px; border: 1px solid #ccc; border-radius: 4px;
                    background: #f3f3f3; list-style: none; user-select: none; }
  .filter-summary::-webkit-details-marker { display: none; }
  .filter-summary:hover { background: #e7e7e7; border-color: #999; }
  details[open] > .filter-summary { background: #e0e0e0; }
  @media (prefers-color-scheme: dark) {
    body { background: #1a1a1a; color: #ddd; }
    th { background: #222; } th, td { border-color: #333; }
    tr:hover td { background: #222; }
    pre { background: #222; }
    h2 { border-color: #333; }
    .filter-panel { background: #222; border-color: #444; }
    .filter-summary { background: #2a2a2a; border-color: #444; color: #ddd; }
    .filter-summary:hover { background: #333; border-color: #555; }
    details[open] > .filter-summary { background: #383838; }
  }
</style></head><body>${body}</body></html>`;
}

function fmtTs(ms: number): string {
  if (!ms) return "—";
  const d = new Date(ms);
  // Compact "YYYY-MM-DD HH:MM" — no seconds, no UTC suffix. Both columns
  // and tooltips use this; UTC is implicit (server is UTC) and seconds
  // are rarely useful at the audit-log level.
  return d.toISOString().replace("T", " ").slice(0, 16);
}

function fmtRelative(ms: number): string {
  if (!ms) return "—";
  const delta = Date.now() - ms;
  if (delta < 60_000) return `${Math.round(delta / 1000)}s ago`;
  if (delta < 3600_000) return `${Math.round(delta / 60_000)}m ago`;
  if (delta < 86400_000) return `${Math.round(delta / 3600_000)}h ago`;
  return `${Math.round(delta / 86400_000)}d ago`;
}

function escapeHtml(s: string): string {
  return s
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;");
}

// ---- /admin home ----

adminRouter.get("/admin", async (req: Request, res: Response) => {
  const ctx = await requireAdmin(req, res);
  if (!ctx) return;

  const realm = getSharedRealmInfo();
  const tokenPart = ctx.reason === "token" ? `?token=${req.query.token}` : "";

  const users = db.prepare(
    `SELECT
       u.id, u.label, u.created_at, u.tool_whitelist, u.is_admin,
       (SELECT MAX(ts) FROM request_log WHERE user_id = u.id) AS last_seen,
       (SELECT COUNT(*) FROM request_log WHERE user_id = u.id) AS request_count
     FROM users u
     WHERE u.id != 0       -- hide the shared admin slot sentinel
     ORDER BY last_seen DESC NULLS LAST, u.created_at DESC`,
  ).all() as Array<{
    id: number;
    label: string | null;
    created_at: number;
    tool_whitelist: string | null;
    is_admin: number;
    last_seen: number | null;
    request_count: number;
  }>;

  // ---- log filters via query string ----
  const q = req.query as Record<string, string | undefined>;
  const filters: string[] = [];
  const params: unknown[] = [];

  if (q.failures === "1") {
    filters.push("status >= 400");
  }
  if (q.user) {
    const uid = Number(q.user);
    if (Number.isFinite(uid)) {
      filters.push("user_id = ?");
      params.push(uid);
    }
  }
  // ?label= can be a single string or an array (multiple ?label= params).
  // Match against the denormalized user_label column so filtering survives
  // user_id rotation from email-based dedupe.
  const labelValues = Array.isArray(q.label)
    ? (q.label as string[]).filter((s) => typeof s === "string" && s.length > 0)
    : q.label
      ? [q.label as string]
      : [];
  if (labelValues.length === 1) {
    filters.push("user_label = ?");
    params.push(labelValues[0]);
  } else if (labelValues.length > 1) {
    filters.push(`user_label IN (${labelValues.map(() => "?").join(",")})`);
    labelValues.forEach((l) => params.push(l));
  }
  if (q.since) {
    const m = /^(\d+)([mhd])$/.exec(q.since);
    if (m) {
      const n = parseInt(m[1], 10);
      const mult = { m: 60_000, h: 3_600_000, d: 86_400_000 }[m[2] as "m" | "h" | "d"];
      filters.push("ts >= ?");
      params.push(Date.now() - n * mult);
    }
  }
  if (q.path) {
    filters.push("path LIKE ?");
    params.push(`%${q.path}%`);
  }
  if (q.tool) {
    filters.push("tool_name = ?");
    params.push(q.tool);
  }
  // ?tool_calls=1 — show only real tool invocations, hiding MCP protocol
  // noise (tools/list, initialize, notifications/*).
  if (q.tool_calls === "1") {
    filters.push("tool_name IS NOT NULL");
  }

  const whereSql = filters.length ? `WHERE ${filters.join(" AND ")}` : "";
  const recent = db.prepare(
    `SELECT ts, user_id, user_label, auth_kind, method, path, tool_name, rpc_method,
            status, duration_ms, remote_ip, error
       FROM request_log
       ${whereSql}
       ORDER BY ts DESC
       LIMIT 100`,
  ).all(...params) as Array<{
    ts: number;
    user_id: number | null;
    user_label: string | null;
    auth_kind: string | null;
    method: string;
    path: string;
    tool_name: string | null;
    rpc_method: string | null;
    status: number;
    duration_ms: number | null;
    remote_ip: string | null;
    error: string | null;
  }>;

  const totalRequests = (db.prepare("SELECT COUNT(*) AS c FROM request_log").get() as any).c;
  const filteredCount = filters.length
    ? (db.prepare(`SELECT COUNT(*) AS c FROM request_log ${whereSql}`).get(...params) as any).c
    : totalRequests;

  const userRows = users.map((u) => {
    const label = u.label ? escapeHtml(u.label) : '<span class="muted">—</span>';
    // Relative time as the primary signal; full timestamp on hover. Cuts
    // the column width by ~25 characters per row.
    const lastSeen = u.last_seen
      ? `<span title="${fmtTs(u.last_seen)} UTC">${fmtRelative(u.last_seen)}</span>`
      : '<span class="muted">never</span>';

    // Permissions summary cell: parse tool_whitelist (or null = all tools)
    let permsCell: string;
    if (u.tool_whitelist === null) {
      permsCell = '<span class="muted">All tools</span>';
    } else {
      try {
        const arr = JSON.parse(u.tool_whitelist) as unknown;
        if (!Array.isArray(arr)) throw new Error("not an array");
        const n = arr.length;
        permsCell = n === 0
          ? '<span class="pill err">Locked out</span>'
          : `<span title="${arr.map((s) => escapeHtml(String(s))).join(", ")}">${n} tool${n === 1 ? "" : "s"}</span>`;
      } catch {
        permsCell = '<span class="pill err">malformed</span>';
      }
    }

    // Admin column: show role badge + grant/revoke action where applicable.
    const isPrimary = isPrimaryAdmin(u.label);
    let adminCell: string;
    if (isPrimary) {
      adminCell = `<span class="pill ok" title="Set via ADMIN_EMAIL env var">primary admin</span>`;
    } else if (u.is_admin === 1) {
      adminCell = `<span class="pill ok">admin</span>
        <form method="POST" action="/admin/users/${u.id}/admin/revoke${tokenPart}" class="inline"
              onsubmit="return confirm('Revoke admin from user ${u.id}${u.label ? ` (${u.label})` : ""}?');">
          <button type="submit" style="font-size:11px;padding:2px 8px;background:#888">Revoke admin</button>
        </form>`;
    } else {
      adminCell = `<span class="muted">user</span>
        <form method="POST" action="/admin/users/${u.id}/admin/grant${tokenPart}" class="inline"
              onsubmit="return confirm('Promote user ${u.id}${u.label ? ` (${u.label})` : ""} to admin?');">
          <button type="submit" style="font-size:11px;padding:2px 8px;background:#0a4dad">Make admin</button>
        </form>`;
    }

    // Hide Revoke button on the primary admin to avoid foot-gun (env-var
    // user can't be removed via UI anyway, but the button would be
    // confusing).
    const revokeButton = isPrimary
      ? `<span class="muted" style="font-size:12px">env-protected</span>`
      : `<form method="POST" action="/admin/users/${u.id}/revoke${tokenPart}" class="inline"
              onsubmit="return confirm('Revoke user ${u.id}${u.label ? ` (${u.label})` : ""}? Their key stops working immediately.');">
          <button type="submit">Revoke</button>
        </form>`;

    return `
      <tr>
        <td class="mono">${u.id}</td>
        <td>${label}</td>
        <td>${adminCell}</td>
        <td class="nowrap">${fmtTs(u.created_at)}</td>
        <td class="nowrap">${lastSeen}</td>
        <td>${u.request_count}</td>
        <td>${permsCell} <a href="/admin/users/${u.id}/permissions${tokenPart}" style="font-size:12px;margin-left:6px">edit</a></td>
        <td>${revokeButton}</td>
      </tr>`;
  }).join("");

  const logRows = recent.map((r) => {
    const statusClass = r.status >= 400 ? "err" : "ok";
    const userCell = r.user_id
      ? `<a href="/admin?user=${r.user_id}${tokenPart ? `&token=${req.query.token}` : ""}" class="mono">${r.user_id}</a>${r.user_label ? ` ${escapeHtml(r.user_label)}` : ""}`
      : '<span class="muted">—</span>';
    const kindCell = r.auth_kind
      ? `<span class="pill ${r.auth_kind}">${r.auth_kind}</span>`
      : "";
    // The tool column shows ONLY the real tool name (e.g. qbo_query,
    // list_customers). MCP protocol traffic that isn't a tool call —
    // tools/list, initialize, notifications/*, ping — is hidden from
    // the visible row but kept as a tooltip on the request column for
    // forensics. Use the "Tool calls only" filter to hide those rows
    // entirely.
    const tool = r.tool_name ? `<code>${escapeHtml(r.tool_name)}</code>` : "";
    const pathTitle = !r.tool_name && r.rpc_method
      ? ` title="JSON-RPC: ${escapeHtml(r.rpc_method)}"`
      : "";
    // Visually demote protocol-noise rows (no tool_name) so real tool
    // calls stand out when the filter isn't applied.
    const rowStyle = !r.tool_name && r.rpc_method
      ? ' style="opacity:0.55"'
      : "";
    const errCell = r.error
      ? `<details><summary class="muted">err</summary><pre>${escapeHtml(r.error)}</pre></details>`
      : "";
    const ipCell = r.remote_ip
      ? `<code class="muted" title="${escapeHtml(r.remote_ip)}">${escapeHtml(r.remote_ip.length > 16 ? r.remote_ip.slice(0, 13) + "…" : r.remote_ip)}</code>`
      : "";
    return `
      <tr${rowStyle}>
        <td class="nowrap">${fmtRelative(r.ts)}</td>
        <td>${userCell} ${kindCell}</td>
        <td class="mono"${pathTitle}>${r.method} ${escapeHtml(r.path)}</td>
        <td>${tool}</td>
        <td><span class="pill ${statusClass}">${r.status}</span></td>
        <td class="nowrap">${r.duration_ms ?? "—"} ms</td>
        <td class="nowrap">${ipCell}</td>
        <td>${errCell}</td>
      </tr>`;
  }).join("");

  // Filter chip bar — preserves the admin token (if used) on every link.
  function chip(label: string, qs: string, active: boolean): string {
    const tokenSep = tokenPart ? `&token=${req.query.token}` : "";
    const cls = active ? "pill ok" : "pill";
    return `<a class="${cls}" style="margin-right:6px;text-decoration:none" href="/admin?${qs}${tokenSep}">${label}</a>`;
  }
  const noFilters = filters.length === 0;
  const filterBar =
    chip("All", "", noFilters) +
    chip("Tool calls only", "tool_calls=1", q.tool_calls === "1") +
    chip("Failures", "failures=1", q.failures === "1") +
    chip("Last 1h", "since=1h", q.since === "1h") +
    chip("Last 24h", "since=24h", q.since === "24h") +
    chip("Last 7d", "since=7d", q.since === "7d") +
    (q.user ? chip(`user=${q.user}`, `user=${q.user}`, true) : "") +
    (labelValues.length > 0
      ? chip(
          `label=${labelValues.length === 1 ? escapeHtml(labelValues[0]) : `${labelValues.length} users`}`,
          labelValues.map((v) => `label=${encodeURIComponent(v)}`).join("&"),
          true,
        )
      : "") +
    (q.path ? chip(`path~${escapeHtml(q.path)}`, `path=${encodeURIComponent(q.path)}`, true) : "") +
    (q.tool ? chip(`tool=${escapeHtml(q.tool)}`, `tool=${encodeURIComponent(q.tool)}`, true) : "");

  // Active users only (excludes the user_id=0 sentinel and any revoked rows).
  // For forensics on a revoked user, set ?label=… directly in the URL —
  // the request_log retains their history under the denormalized label.
  const knownLabels = (db.prepare(
    `SELECT DISTINCT label
       FROM users
      WHERE label IS NOT NULL
        AND id != 0
      ORDER BY label`,
  ).all() as Array<{ label: string }>).map((r) => r.label);

  const tokenInput = tokenPart
    ? `<input type="hidden" name="token" value="${escapeHtml(String(req.query.token))}">`
    : "";

  // Multi-select via checkboxes inside <details>. Submitting picks all
  // checked boxes; the form posts back to /admin with each as ?label=…
  // (Express parses multiple identically-named query params into an
  // array for us). One-line label click on a user_id still works as a
  // single-user shortcut.
  const labelCheckboxes = knownLabels.map((l) => {
    const checked = labelValues.includes(l) ? "checked" : "";
    return `
      <label style="display:block;font-weight:normal;font-size:13px;margin:4px 0;cursor:pointer">
        <input type="checkbox" name="label" value="${escapeHtml(l)}" ${checked} style="margin-right:6px">
        ${escapeHtml(l)}
      </label>`;
  }).join("");

  const summary = labelValues.length === 0
    ? "filter by user"
    : labelValues.length === 1
      ? `filter by user (${escapeHtml(labelValues[0])})`
      : `filter by user (${labelValues.length} selected)`;

  const labelDropdown = `
    <form method="GET" action="/admin" style="display:inline-block;margin-right:8px;vertical-align:middle">
      ${tokenInput}
      <details ${labelValues.length > 0 ? "open" : ""} class="filter-details">
        <summary class="filter-summary">${summary} ▾</summary>
        <div class="filter-panel">
          ${labelCheckboxes}
          <div style="margin-top:8px;display:flex;gap:8px;align-items:center">
            <button type="submit" style="background:#2ca01c;color:white;border:0;padding:5px 14px;border-radius:4px;font-size:13px;cursor:pointer">Apply</button>
            <a href="/admin${tokenPart}" style="font-size:12px">Clear</a>
          </div>
        </div>
      </details>
    </form>`;

  res.type("html").send(page(
    "qbo-mcp admin",
    `<div class="topnav">
       <a href="/admin${tokenPart}">Dashboard</a>
       <span class="muted">signed in as</span>
       <span class="mono">${ctx.email ?? "(token-auth)"}</span>
     </div>

     <h1>qbo-mcp admin</h1>

     <h2>QuickBooks connection</h2>
     ${realm
       ? `<p>Connected to QuickBooks · last refreshed
          <strong>${fmtRelative(realm.updatedAt)}</strong> (${fmtTs(realm.updatedAt)}).</p>
          <p><a href="/connect/quickbooks${tokenPart}">Re-link QBO admin</a></p>`
       : `<p><strong>No connection bootstrapped yet.</strong>
          <a href="/connect/quickbooks${tokenPart}">Bootstrap now</a></p>`}

     <h2>Users <span class="muted" style="font-size:14px;font-weight:normal">${users.length} total</span></h2>
     <table>
       <thead><tr><th>id</th><th>label</th><th>role</th><th>created</th><th>last seen</th><th># reqs</th><th>permissions</th><th></th></tr></thead>
       <tbody>${userRows || `<tr><td colspan="8" class="muted">No users yet.</td></tr>`}</tbody>
     </table>

     <h2>Recent activity
       <span class="muted" style="font-size:14px;font-weight:normal">
         showing ${recent.length} of ${filteredCount}${filters.length ? ` matching` : ""}
         ${filters.length ? ` (out of ${totalRequests} total)` : ""}
       </span>
     </h2>
     <p>${labelDropdown}${filterBar}</p>
     <table>
       <thead><tr><th>when</th><th>user</th><th>request</th><th>tool</th><th>status</th><th>dur</th><th>ip</th><th></th></tr></thead>
       <tbody>${logRows || `<tr><td colspan="8" class="muted">No requests match.</td></tr>`}</tbody>
     </table>
     <p class="muted" style="font-size:12px;margin-top:24px">
       Custom filters via query string: <code>?failures=1</code>,
       <code>?tool_calls=1</code> (real tool invocations only),
       <code>?user=8</code>, <code>?label=name@example.com</code>,
       <code>?since=1h</code> (or <code>1d</code>, <code>30m</code>),
       <code>?path=oauth</code>, <code>?tool=qbo_query</code>. Combine freely.
     </p>`,
  ));
});

// ---- Per-user tool permissions ----

adminRouter.get("/admin/users/:id/permissions", async (req: Request, res: Response) => {
  const ctx = await requireAdmin(req, res);
  if (!ctx) return;
  const id = Number(req.params.id);
  const user = Number.isFinite(id) ? findUserById(id) : null;
  if (!user || id <= 0) {
    res.status(404).type("html").send(page("Not found", "<h1>User not found</h1>"));
    return;
  }
  const tokenPart = ctx.reason === "token" ? `?token=${req.query.token}` : "";
  const tokenInput = ctx.reason === "token"
    ? `<input type="hidden" name="token" value="${escapeHtml(String(req.query.token))}">`
    : "";

  const unrestricted = user.toolWhitelist === null;
  const allowedSet = new Set(user.toolWhitelist ?? []);

  const checkboxes = ALL_TOOL_NAMES.map((name) => {
    const checked = unrestricted || allowedSet.has(name) || name === "whoami";
    const disabled = name === "whoami" ? "disabled" : "";
    const note = name === "whoami" ? ' <span class="muted">(always allowed)</span>' : "";
    return `
      <label style="display:block;font-weight:normal;font-size:14px;margin:6px 0">
        <input type="checkbox" name="tool" value="${escapeHtml(name)}" ${checked ? "checked" : ""} ${disabled}>
        <code>${escapeHtml(name)}</code>${note}
      </label>`;
  }).join("");

  res.type("html").send(page(
    "Permissions",
    `<h1>Permissions for user ${user.id}${user.label ? ` (${escapeHtml(user.label)})` : ""}</h1>
     <p><a href="/admin${tokenPart}">← Back to dashboard</a></p>

     <form method="POST" action="/admin/users/${user.id}/permissions${tokenPart}">
       ${tokenInput}
       <fieldset style="border:1px solid #ccc;border-radius:6px;padding:14px 18px;margin-top:12px">
         <legend>Mode</legend>
         <label style="display:block;font-weight:normal;margin:4px 0">
           <input type="radio" name="mode" value="all" ${unrestricted ? "checked" : ""}>
           <strong>All tools</strong> <span class="muted">— no restriction (default)</span>
         </label>
         <label style="display:block;font-weight:normal;margin:4px 0">
           <input type="radio" name="mode" value="restricted" ${unrestricted ? "" : "checked"}>
           <strong>Restrict to specific tools</strong> <span class="muted">— pick below</span>
         </label>
       </fieldset>

       <fieldset style="border:1px solid #ccc;border-radius:6px;padding:14px 18px;margin-top:12px">
         <legend>Allowed tools (when restricted)</legend>
         ${checkboxes}
       </fieldset>

       <p style="margin-top:18px;display:flex;gap:10px;align-items:center">
         <button type="submit" style="background:#2ca01c;color:white;border:0;padding:8px 18px;border-radius:6px;font-size:14px;cursor:pointer">Save</button>
         <a href="/admin${tokenPart}">Cancel</a>
       </p>
       <p class="muted" style="font-size:12px;margin-top:24px">
         <code>whoami</code> is always implicitly allowed so users can always
         self-diagnose their connection. <code>qbo_query</code> is the most
         powerful tool — grants ad-hoc read access to all QBO entities.
       </p>
     </form>`,
  ));
});

adminRouter.post("/admin/users/:id/permissions", async (req: Request, res: Response) => {
  const ctx = await requireAdmin(req, res);
  if (!ctx) return;
  const id = Number(req.params.id);
  if (!Number.isFinite(id) || id <= 0) {
    res.status(400).type("html").send(page("Bad request", "<h1>Invalid user id</h1>"));
    return;
  }
  const body = (req.body ?? {}) as Record<string, string | string[]>;
  const mode = typeof body.mode === "string" ? body.mode : "all";

  if (mode === "all") {
    setUserToolWhitelist(id, null);
  } else {
    // Form submits multiple `tool` checkboxes. Coerce to array; validate
    // against the canonical tool list to refuse unknown names. `whoami`
    // is force-included because it's always implicitly allowed —
    // including it in the persisted list keeps the UI count honest
    // (the disabled checkbox in the rendered form looks ticked, so the
    // saved state should too).
    const raw = body.tool;
    const submitted = Array.isArray(raw) ? raw : raw ? [raw] : [];
    const allowed = (ALL_TOOL_NAMES as readonly string[]).filter(
      (t) => submitted.includes(t) || t === "whoami",
    );
    setUserToolWhitelist(id, allowed);
  }

  const tokenPart = ctx.reason === "token" ? `?token=${req.query.token}` : "";
  res.redirect(`/admin${tokenPart}`);
});

// ---- Grant / revoke admin ----

adminRouter.post("/admin/users/:id/admin/grant", async (req: Request, res: Response) => {
  const ctx = await requireAdmin(req, res);
  if (!ctx) return;
  const id = Number(req.params.id);
  const user = Number.isFinite(id) ? findUserById(id) : null;
  if (!user || id <= 0) {
    res.status(404).type("html").send(page("Not found", "<h1>User not found</h1>"));
    return;
  }
  if (isPrimaryAdmin(user.label)) {
    // Already implicit primary — flag is redundant but harmless. Skip the
    // write.
  } else {
    setUserIsAdmin(id, true);
  }
  const tokenPart = ctx.reason === "token" ? `?token=${req.query.token}` : "";
  res.redirect(`/admin${tokenPart}`);
});

adminRouter.post("/admin/users/:id/admin/revoke", async (req: Request, res: Response) => {
  const ctx = await requireAdmin(req, res);
  if (!ctx) return;
  const id = Number(req.params.id);
  const user = Number.isFinite(id) ? findUserById(id) : null;
  if (!user || id <= 0) {
    res.status(404).type("html").send(page("Not found", "<h1>User not found</h1>"));
    return;
  }
  if (isPrimaryAdmin(user.label)) {
    // Refuse: the primary admin is set via ADMIN_EMAIL env var. Removing
    // the is_admin flag wouldn't actually demote them, and the UI button
    // shouldn't have rendered for this user anyway — defensive 400.
    res.status(400).type("html").send(
      page(
        "Refused",
        `<h1>Refused</h1>
         <p>The primary admin is set via the <code>ADMIN_EMAIL</code> env var
            and can't be revoked through the UI. Change the env var and
            restart the container if you want to demote them.</p>
         <p><a href="/admin${ctx.reason === "token" ? `?token=${req.query.token}` : ""}">Back</a></p>`,
      ),
    );
    return;
  }
  setUserIsAdmin(id, false);
  const tokenPart = ctx.reason === "token" ? `?token=${req.query.token}` : "";
  res.redirect(`/admin${tokenPart}`);
});

// ---- Revoke user ----

adminRouter.post("/admin/users/:id/revoke", async (req: Request, res: Response) => {
  const ctx = await requireAdmin(req, res);
  if (!ctx) return;

  const id = Number(req.params.id);
  if (!Number.isFinite(id) || id < 0) {
    res.status(400).type("html").send(page("Bad request", "<h1>Invalid user id</h1>"));
    return;
  }
  if (id === 0) {
    // user_id 0 is the shared admin slot sentinel. The qbo_connections row
    // FK-references it; deleting it breaks every team member's tool calls
    // until /connect/quickbooks is re-run. Refuse via UI; admin can drop
    // the connection directly via SQL if they really want.
    res.status(400).type("html").send(page(
      "Refused",
      `<h1>Refused</h1>
       <p>user_id 0 is the shared admin slot sentinel — the QBO upstream
          connection depends on it. Removing this row would break tool
          calls for every team member until you re-run
          <code>/connect/quickbooks</code>.</p>
       <p>If you really want to wipe the upstream connection, do it
          directly via SQLite.</p>
       <p><a href="/admin${ctx.reason === "token" ? `?token=${req.query.token}` : ""}">Back</a></p>`,
    ));
    return;
  }

  const info = db.prepare("DELETE FROM users WHERE id = ?").run(id);
  // CASCADE wipes their oauth_refresh_tokens, oauth_codes, etc.

  const tokenPart = ctx.reason === "token" ? `?token=${req.query.token}` : "";
  res.redirect(`/admin${tokenPart}`);
  void info;
});
