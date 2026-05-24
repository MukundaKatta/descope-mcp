# descope-mcp

An MCP server for [Descope](https://descope.com) authentication. Lets any LLM agent verify session tokens, check user roles, look up user records, and trigger magic-link flows — without baking auth logic into the agent's prompt.

Built for the **Global MCP Hackathon 2026** sponsored by Descope.

## Tools

| Tool | What it does |
|---|---|
| `validate_session` | Verify a Descope JWT via JWKS. Returns claims (sub, email, roles, tenants) and expiry info. |
| `check_roles` | Given claims from `validate_session`, check if required roles are granted (global or per-tenant). Returns `allowed` + `missing[]`. |
| `get_user` | Fetch a user record by login ID (needs management key). |
| `send_magic_link` | Trigger a magic-link email. Returns `pendingRef` for polling + masked email for display. |

## Quick start

```bash
npx -y @mukundakatta/descope-mcp
```

### Claude Desktop / Cursor / Cline

```json
{
  "mcpServers": {
    "descope": {
      "command": "npx",
      "args": ["-y", "@mukundakatta/descope-mcp"],
      "env": {
        "DESCOPE_PROJECT_ID": "P...",
        "DESCOPE_MANAGEMENT_KEY": "K..."
      }
    }
  }
}
```

Get your Project ID at [app.descope.com](https://app.descope.com/settings/project). Management key is optional — only needed for `get_user`.

## Environment variables

| Variable | Required | Description |
|---|---|---|
| `DESCOPE_PROJECT_ID` | Yes | Your Descope project ID (starts with `P`). |
| `DESCOPE_MANAGEMENT_KEY` | No | Management key for admin operations. |
| `DESCOPE_BASE_URL` | No | Override for self-hosted Descope. |

## Example agent flow

```
User: "Can Alice access the billing dashboard?"

Agent calls:
1. validate_session(session_token=alice_jwt)
   → { valid: true, claims: { sub: "u_abc", roles: ["viewer"], ... } }

2. check_roles(claims_json=..., required_roles=["billing"])
   → { allowed: false, missing: ["billing"] }

Agent replies: "Alice doesn't have the billing role. She has: viewer."
```

## How it works

- **No Descope SDK dependency** — JWKS fetch + RS256 verification via WebCrypto (`crypto.subtle`), so the server stays small and auditable.
- **Offline-safe** — pass a custom `fetchFn` in tests; all 15 unit tests run without any network calls.
- **Tenant-aware** — `check_roles` supports multi-tenant role checks (pass `tenant_id`).

## Tests

```bash
npm test   # 15 tests, all offline
```

## Related

- [mcp-stack](https://github.com/MukundaKatta/mcp-stack) — 14 utility MCP servers for workflow automation agents
