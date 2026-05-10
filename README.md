# qbo-mcp

A self-hostable, **read-only** QuickBooks Online server for the
[Model Context Protocol](https://modelcontextprotocol.io/). Lets your
team query QBO data from Claude (Desktop, Code, or claude.ai web)
through a shared admin connection, with per-user audit and zero-friction
team signup via Cloudflare Access.

```
   ┌──────────────┐                ┌──────────────┐
   │ claude.ai web│ ─────┐         │  Claude      │
   └──────────────┘      │         │  Desktop     │
                         │         └──────┬───────┘
   ┌──────────────┐      │                │
   │  Claude Code │ ─────┤  HTTP Bearer   │
   └──────────────┘      │                │
                         ▼                ▼
                ┌────────────────────────────┐
                │     qbo-mcp (Express)      │
                │  • OAuth 2.1 + DCR         │
                │  • Per-user Bearer auth    │
                │  • /admin dashboard        │
                │  • Per-request audit log   │
                └────────────┬───────────────┘
                             │ shared admin connection
                             ▼
                    QuickBooks Online API
```

## Features

- **MCP-spec OAuth 2.1** — `claude.ai` web's "Add custom connector" works with just the URL. Implements RFC 9728 (resource metadata), RFC 8414 (AS metadata), RFC 7591 (Dynamic Client Registration), PKCE.
- **Two auth paths**, same backend: static `qbo_…` keys for desktop clients, JWT Bearer tokens for OAuth-flow clients. Both gate `/mcp` identically.
- **Cloudflare Access integration** — gate `/team-signup`, `/oauth/authorize`, `/admin`, and `/connect/quickbooks` at the edge with a `@yourdomain.com` allowlist. Once configured, signing up is one click for anyone in your domain.
- **Encryption at rest** — Intuit refresh tokens encrypted with AES-256-GCM in SQLite. Server-side master in `data/jwt-secret.bin`.
- **Per-user audit** — every MCP request logged with user, tool name, JSON-RPC method, status, IP, duration. Admin dashboard at `/admin` with filtering by user / failures / time window.
- **Single Docker container, single SQLite file** — no external DB, no cache, no message queue.

## Tools (read-only)

| Tool | Purpose |
| ---- | ------- |
| `whoami` | Authenticated user + connected QBO company |
| `qbo_query` | Run any QBO query-language statement (`SELECT … FROM Customer …`) |
| `list_customers`, `get_customer` | Customer lookups |
| `list_invoices`, `get_invoice` | Invoice lookups (filter by customer / date / open) |
| `get_profit_and_loss` | P&L report for a date range |
| `get_balance_sheet` | Balance sheet as of a date |

Write tools (create invoice, record payment, etc.) are deliberately out of scope.

## Architectural choice: shared admin connection

Intuit's OAuth model allows **only one admin connection per app per QBO realm at any time**. A second user authorizing the same app for the same company replaces the first. This makes the obvious "per-user OAuth tokens" architecture unworkable for a multi-user MCP server.

`qbo-mcp` works around this by holding **one shared upstream connection** at the QBO realm level. Every team member authenticates to *this* server with their own Bearer (static or OAuth-issued JWT), but all upstream API calls use the single admin's refresh token. From Intuit's audit log perspective every API call appears as the admin; from this server's audit log perspective each call is attributed to the calling user.

Trade-offs documented in the [security model](#security-model) section.

## Quick start (sandbox, ~5 min)

### 1. Create an Intuit app

1. Sign in at <https://developer.intuit.com/app/developer/myapps>.
2. **Create an app** → "QuickBooks Online and Payments" → scope `com.intuit.quickbooks.accounting`.
3. **Keys & OAuth → Development Settings** → copy Client ID and Client Secret.
4. **Redirect URIs** → add `http://localhost:3000/connect/callback`.
5. Optional: create a sandbox company from the **Sandboxes** menu so you have demo data to query.

### 2. Configure and run

```bash
git clone <your-fork>.git qbo-mcp
cd qbo-mcp
cp .env.example .env
# Fill in INTUIT_CLIENT_ID and INTUIT_CLIENT_SECRET.
# Generate a strong ADMIN_BOOTSTRAP_TOKEN: `openssl rand -base64 32`
# (TEAM_SIGNUP_TOKEN can be left empty in dev; not needed if you'll use CF Access in prod.)

docker compose up --build -d
docker compose logs -f
```

### 3. Bootstrap the QBO admin connection

In a browser, open:

```
http://localhost:3000/connect/quickbooks?token=<your-ADMIN_BOOTSTRAP_TOKEN>
```

Sign in with Intuit, pick your sandbox company, click **Connect**. You should land on a "QBO admin connection established" page.

### 4. Mint your first user key

```
http://localhost:3000/team-signup
```

Enter the team token (or whatever you have set). The page returns a one-time `qbo_…` Bearer key.

### 5. Add to a Claude client

```bash
claude mcp add --scope user --transport http quickbooks \
  http://localhost:3000/mcp \
  --header "Authorization: Bearer qbo_…"
```

Or for Claude Desktop (`~/Library/Application Support/Claude/claude_desktop_config.json`):

```json
{
  "mcpServers": {
    "quickbooks": {
      "command": "npx",
      "args": [
        "-y", "mcp-remote",
        "http://localhost:3000/mcp",
        "--header", "Authorization:Bearer qbo_…"
      ]
    }
  }
}
```

Restart Claude. Ask it *"run whoami"* — should return your sandbox company.

## Production deployment

The recommended pattern: run the container on any machine, expose it through **Cloudflare Tunnel** with **Cloudflare Access** policies on the sensitive paths.

### 1. Switch Intuit to production

Intuit production apps require **HTTPS** redirect URIs. Either:
- Get production credentials (separate Client ID/Secret, requires going through Intuit's production readiness checklist), OR
- Stay in sandbox and use a public HTTPS URL anyway

Add your production redirect URI to the Intuit app: `https://your-mcp.example.com/connect/callback`.

### 2. Stand up Cloudflare Tunnel

In Cloudflare Zero Trust → **Networks → Tunnels**, create or pick an existing tunnel running on the host, and add a Public Hostname:

- Subdomain: e.g. `qbo-mcp`
- Domain: your CF-managed domain
- Service: HTTP, `localhost:3000`

### 3. Cloudflare Access policies

In Zero Trust → **Access → Applications → Add an application** (Self-hosted):

- **Application domain:** `qbo-mcp.example.com`
- **Add four destinations** (or one app per path), all sharing the same Cloudflare Access AUD:
  - `oauth/authorize` — OAuth flow
  - `team-signup` — coworker self-service
  - `connect/quickbooks` — admin re-link (high-sensitivity)
  - `admin` — admin dashboard
- **Identity providers:** any (Google OAuth, One-Time PIN, Okta, etc.)
- **Policy:** Allow → "Emails in a list" → reference a [Cloudflare List](https://developers.cloudflare.com/cloudflare-one/policies/access/lists/) of approved emails

Leave `/mcp`, `/health`, `/`, and `/.well-known/oauth-*` **unprotected** by Access:
- `/mcp` is gated by Bearer auth (Claude Desktop's `mcp-remote` can't do browser SSO)
- `/.well-known/*` must be public per OAuth spec
- `/health` is for monitoring

### 4. Server config for production

Set in `.env`:

```ini
INTUIT_ENVIRONMENT=production
PUBLIC_BASE_URL=https://qbo-mcp.example.com
ADMIN_BOOTSTRAP_TOKEN=<strong random>
ADMIN_EMAIL=admin@example.com               # for /admin email-match auth
CF_ACCESS_TEAM_DOMAIN=yourteam.cloudflareaccess.com
CF_ACCESS_AUD=<from CF Access app overview>
TEAM_SIGNUP_TOKEN=                          # optional fallback if CF Access fails
```

When both `CF_ACCESS_TEAM_DOMAIN` and `CF_ACCESS_AUD` are set, the server verifies Cloudflare's `Cf-Access-Jwt-Assertion` header against the team's JWKS and auto-mints user records labeled with the verified email. No team-token paste required from end users.

### 5. Bootstrap admin

Visit `https://qbo-mcp.example.com/connect/quickbooks?token=<ADMIN_BOOTSTRAP_TOKEN>` (Cloudflare will OTP-gate first, then your server prompts the admin token). Complete the Intuit OAuth dance.

### 6. Coworkers self-onboard

Send them: `https://qbo-mcp.example.com/team-signup`. Cloudflare emails them an OTP, they sign in, the success page shows a personal `qbo_…` key plus a copy-pasteable Claude Desktop config snippet.

## Authentication model

Three independent auth contexts:

| Context | Mechanism | Where |
| --- | --- | --- |
| **MCP requests** (`/mcp`) | Bearer token (static `qbo_…` or OAuth-issued JWT) | Header `Authorization: Bearer …` |
| **Coworker signup** (`/team-signup`, `/oauth/authorize`) | Cloudflare Access OTP/SSO + email allowlist | Network edge (Cloudflare) |
| **Admin** (`/admin`, `/connect/quickbooks`) | CF Access email-match OR `ADMIN_BOOTSTRAP_TOKEN` | Both: edge + server |

`/mcp` returns 401 with a proper `WWW-Authenticate: Bearer resource_metadata="…"` challenge so OAuth-aware MCP clients (claude.ai web) can self-discover the server's OAuth endpoints and complete a Dynamic Client Registration + auth-code flow without any pre-shared secret.

## Configuration reference

All config via environment variables (see `.env.example` for an annotated template).

| Variable | Required | Default | Purpose |
| --- | --- | --- | --- |
| `INTUIT_CLIENT_ID` | yes | — | From Intuit app keys |
| `INTUIT_CLIENT_SECRET` | yes | — | From Intuit app keys |
| `INTUIT_ENVIRONMENT` | no | `sandbox` | `sandbox` or `production` |
| `PUBLIC_BASE_URL` | yes | — | Where users reach this server (must match Intuit redirect URI host) |
| `DATABASE_PATH` | no | `./data/qbo-mcp.sqlite` | SQLite file path |
| `PORT` | no | `3000` | HTTP bind port |
| `HOST` | no | `0.0.0.0` | HTTP bind host |
| `ADMIN_BOOTSTRAP_TOKEN` | recommended | — | Gates `/connect/quickbooks` (admin Intuit-link) |
| `TEAM_SIGNUP_TOKEN` | no | — | Fallback gate for `/team-signup` when CF Access not used |
| `CF_ACCESS_TEAM_DOMAIN` | no | — | e.g. `yourteam.cloudflareaccess.com` |
| `CF_ACCESS_AUD` | no | — | Per-app AUD tag from CF Access dashboard |
| `ADMIN_EMAIL` | no | — | Email that gets `/admin` access via CF Access (defaults to token-only) |

`data/jwt-secret.bin` is auto-generated on first start (32 random bytes) and signs OAuth JWT access tokens. Persisted; rotating it invalidates all OAuth-flow user sessions.

## Admin dashboard

Visit `/admin` (gated by CF Access email match if `ADMIN_EMAIL` is set, or `?token=<ADMIN_BOOTSTRAP_TOKEN>`).

Shows:
- **QBO connection status** with last-refresh timestamp
- **Users table** — every active user with id, label (typically email), creation/last-seen, request count, **Revoke** button
- **Recent activity** — last 100 requests with chip filters (Failures only, Last 1h/24h/7d), multi-select user dropdown, and query-string filters (`?failures=1`, `?since=24h`, `?label=user@example.com`, `?path=oauth`, `?tool=qbo_query`)

## Security model

**What's protected and how:**

- **Static `qbo_…` keys** stored as SHA-256 hashes (`users.api_key_hash`). Plaintext only ever displayed once on `/team-signup` success.
- **Intuit refresh tokens** (in `qbo_connections`) encrypted with AES-256-GCM. Encryption key derived from `data/jwt-secret.bin` via HKDF.
- **OAuth access tokens** are short-lived JWTs signed with `data/jwt-secret.bin` (HS256, 1-hour expiry). Refresh tokens are opaque and single-use.
- **Cloudflare Access** gates the four user-facing UI paths at the edge. JWTs verified against Cloudflare's published JWKS.

**What's NOT protected:**

- The `.env` file holds Intuit `client_secret` in plaintext on disk. Standard config-file precautions apply.
- A full server compromise (root/file read) yields the JWT signing key, which would let an attacker forge OAuth JWTs and decrypt the SQLite-stored Intuit tokens. The encryption-at-rest defends only against partial leaks (e.g. a stolen SQLite copy without `.env`).
- The QBO realm ID is leaked in OAuth redirect URLs (Intuit's behavior, not ours).

**Auditing:**

- Every HTTP request logged with user attribution (`request_log` table). Survives container rebuilds.
- Per-user revoke from `/admin` invalidates their Bearer token immediately. Cloudflare Access seat counts are independent — see your CF Access dashboard to release seats.

## Development

```bash
npm install
cp .env.example .env
npm run dev   # tsx watch, rebuilds on save
npm run typecheck
```

The project is TypeScript on Node 20+, Express 4 with `@modelcontextprotocol/sdk` for the MCP transport, `better-sqlite3` for the data store, `jose` for JWT/JWKS, and zod for env-var schema validation.

`src/` layout:
- `server.ts` — Express app + `/mcp` handler
- `tools/*.ts` — MCP tool implementations
- `qbo.ts` — QBO API client + token refresh + encryption-at-rest
- `auth.ts` — Bearer parsing + user lookup + dedupe-by-email
- `oauth/` — OAuth 2.1 endpoints, JWT signing, CF Access verification
- `admin/` — admin dashboard + per-request audit log middleware

## Database

Single SQLite file, schema in `src/db.ts`:

| Table | Purpose |
| --- | --- |
| `users` | One row per Bearer holder (api_key_hash, label, created_at) |
| `qbo_connections` | The shared upstream Intuit refresh token (one row per realm; user_id=0 sentinel) |
| `linking_sessions` | Short-lived CSRF state for `/connect/quickbooks` (15 min TTL) |
| `oauth_clients` | Dynamically-registered MCP clients (claude.ai web etc.) |
| `oauth_pending` | In-flight `/oauth/authorize` requests (15 min TTL) |
| `oauth_codes` | One-time auth codes (10 min TTL) |
| `oauth_refresh_tokens` | Opaque, single-use refresh tokens for the `/oauth/token` endpoint |
| `request_log` | Per-request audit (user, path, tool name, JSON-RPC method, status, IP, duration) |

To wipe all user state: `DELETE FROM users WHERE id != 0;` (preserves the shared QBO connection sentinel).

## Contributing

PRs welcome. Useful directions:

- **Write tools** (create invoice, record payment, etc.) — needs a confirmation/audit-trail design first.
- **Multi-realm support** — the schema already keys connections by realm; just needs a UI to pick which realm a user is operating against.
- **Pruning the request log** — currently grows unbounded. ~150 rows/day is fine for years; eventually a cron-like cleanup would be nice.
- **Replacing the user_id=0 sentinel** with a proper `realms` table to drop the FK foot-gun.

## License

MIT — see `LICENSE`.
