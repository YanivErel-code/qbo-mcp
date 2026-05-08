# qbo-mcp

A remote MCP server that exposes **read-only** QuickBooks Online access over
Streamable HTTP. Runs in Docker on a single host and is designed to be reachable
over a Tailscale tailnet, with per-user API keys gating access.

## What's here

```
Claude Code ──(Bearer API key over Tailscale)──▶ qbo-mcp ──(Intuit OAuth)──▶ QBO API
                                                   │
                                          SQLite (users + QBO tokens)
```

- **MCP transport:** Streamable HTTP (stateless), `POST /mcp`.
- **Per-user isolation:** each user's Intuit refresh token lives in SQLite keyed
  by an API key that only they hold.
- **Network auth:** Tailscale (only tailnet members can reach the port).
- **App-level auth:** API key in `Authorization: Bearer qbo_...`.

## Tools exposed (v1, read-only)

| Tool | Purpose |
| ---- | ------- |
| `whoami` | Show authenticated user + connected QBO company |
| `qbo_query` | Run any QBO query-language statement (`SELECT ... FROM Customer ...`) |
| `list_customers`, `get_customer` | Customer lookups |
| `list_invoices`, `get_invoice` | Invoice lookups (with date/customer/open filters) |
| `get_profit_and_loss` | P&L report for a date range |
| `get_balance_sheet` | Balance sheet as of a given date |

Write tools (create invoice, record payment, etc.) are deliberately out of
scope for v1.

---

## 1. Create an Intuit app

1. Sign in at <https://developer.intuit.com/app/developer/myapps>.
2. **Create an app** → "QuickBooks Online and Payments" → scopes:
   `com.intuit.quickbooks.accounting`.
3. In the app, open **Keys & OAuth**:
   - Under **Development Settings** (sandbox), copy the **Client ID** and
     **Client Secret**.
   - Under **Redirect URIs**, add:
     - `http://localhost:3000/connect/callback` (for local testing)
     - `http://<your-machine>.<your-tailnet>.ts.net:3000/connect/callback`
       (for Tailscale)
   - Intuit only accepts HTTPS redirect URIs for **production** apps. Sandbox
     allows HTTP, which is what we use here.
4. Create a **sandbox company** from the "Sandbox" menu — this gives you a test
   QBO account populated with demo data to query.

## 2. Configure

```bash
cp .env.example .env
# fill in INTUIT_CLIENT_ID, INTUIT_CLIENT_SECRET
# set PUBLIC_BASE_URL to whatever URL users (including yourself) will reach
# the server at — this must match a redirect URI you registered.
```

## 3. Run (Docker)

```bash
docker compose up --build -d
docker compose logs -f
```

The SQLite database is stored in `./data/qbo-mcp.sqlite` on the host via a
bind-mounted volume, so it survives container rebuilds.

## 4. Link QuickBooks & get an API key

1. Open `http://localhost:3000/` (or your Tailscale URL) in a browser.
2. Click **Connect QuickBooks** → sign in → pick the sandbox company.
3. On success the page displays a one-time API key starting with `qbo_` plus a
   drop-in MCP config snippet. **Save the key immediately** — it's shown once.

Each user who wants access repeats this flow to get their own key.

## 5. Add to Claude Code / Claude Desktop

Via CLI:

```bash
claude mcp add --transport http quickbooks http://localhost:3000/mcp \
  --header "Authorization: Bearer qbo_xxxxxxxxxxxx"
```

Or edit `~/.claude.json` / `~/.config/claude-desktop/config.json`:

```json
{
  "mcpServers": {
    "quickbooks": {
      "url": "http://localhost:3000/mcp",
      "headers": { "Authorization": "Bearer qbo_xxxxxxxxxxxx" }
    }
  }
}
```

Then in Claude: *"what's my Q1 profit and loss?"* or *"list my 10 largest open
invoices"*.

---

## Development (no Docker)

```bash
npm install
cp .env.example .env   # set PUBLIC_BASE_URL=http://localhost:3000
npm run dev            # tsx watch, rebuilds on save
```

## Deploying over Tailscale

The quickest path: run the container on a machine that's on your tailnet, then
reach it from other tailnet members via the machine's MagicDNS name.

```bash
# On the host machine (already on the tailnet):
docker compose up -d

# PUBLIC_BASE_URL in .env must match what clients reach:
#   PUBLIC_BASE_URL=http://<machine>.<tailnet>.ts.net:3000
#
# Add that same URL (plus /connect/callback) to your Intuit app's redirect URIs.
```

If you want HTTPS, put the container behind `tailscale serve --bg --https=443
http://localhost:3000` on the host, then set
`PUBLIC_BASE_URL=https://<machine>.<tailnet>.ts.net` and update Intuit
redirect URIs accordingly.

## Database layout

- `users` — one row per API key (hashed).
- `qbo_connections` — QBO tokens keyed by `(user_id, realm_id)`.
- `linking_sessions` — short-lived CSRF state for the OAuth dance (15-min TTL).

The database is a single SQLite file. To wipe a user, delete their rows or
delete the whole file and let them re-link.

## Security notes

- API keys are stored as SHA-256 hashes. Only the plaintext shown on the
  connect-success page can authenticate.
- Intuit client secret lives in `.env` — keep that out of git (it's
  `.gitignore`d already).
- This server has **no brute-force protection** on API keys; the assumption is
  that it's only reachable via Tailscale. Do not expose it to the public
  internet without adding a reverse-proxy rate limiter and ideally replacing
  the Bearer scheme with OIDC (see future-work below).

## Future work

- Write tools (create invoice, record payment, etc.) — needs an audit trail
  table and per-tool confirmations on the Claude side.
- Replace static API keys with Okta OIDC bearer tokens (planned path B of the
  original design — keep the transport, swap the auth middleware).
- Support multiple QBO companies per user (the schema already keys on
  `(user_id, realm_id)` — we just need a company-picker).
