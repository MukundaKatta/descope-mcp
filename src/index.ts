/**
 * descope-mcp — MCP server for Descope authentication.
 *
 * Tools:
 *   validate_session   Verify a Descope session JWT. Returns claims + validity.
 *   check_roles        Given claims JSON, check if required roles are granted.
 *   get_user           Fetch a user record (requires management key).
 *   send_magic_link    Trigger a magic-link email for a user.
 *
 * Configuration (env vars):
 *   DESCOPE_PROJECT_ID   Required.
 *   DESCOPE_MANAGEMENT_KEY   Optional; needed for get_user.
 *   DESCOPE_BASE_URL     Optional; override for self-hosted Descope.
 *
 * Usage:
 *   npx -y @mukundakatta/descope-mcp
 *
 * Add to Claude Desktop / Cursor / Cline:
 *   {
 *     "mcpServers": {
 *       "descope": {
 *         "command": "npx",
 *         "args": ["-y", "@mukundakatta/descope-mcp"],
 *         "env": {
 *           "DESCOPE_PROJECT_ID": "P...",
 *           "DESCOPE_MANAGEMENT_KEY": "K..."
 *         }
 *       }
 *     }
 *   }
 */

import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { z } from "zod";
import {
  validateSession,
  checkRoles,
  getUser,
  sendMagicLink,
  type DescopeConfig,
  type TokenClaims,
} from "./descope.js";

// ── Config from env ───────────────────────────────────────────────────────────

function getConfig(): DescopeConfig {
  const projectId = process.env["DESCOPE_PROJECT_ID"];
  if (!projectId) {
    throw new Error(
      "DESCOPE_PROJECT_ID env var is required. Get it from app.descope.com."
    );
  }
  return {
    projectId,
    managementKey: process.env["DESCOPE_MANAGEMENT_KEY"],
    baseUrl: process.env["DESCOPE_BASE_URL"],
  };
}

// ── Server ───────────────────────────────────────────────────────────────────

const server = new McpServer({
  name: "descope-mcp",
  version: "0.1.0",
});

// ── validate_session ─────────────────────────────────────────────────────────

server.tool(
  "validate_session",
  "Verify a Descope session JWT. Returns claims (sub, email, roles, tenants) and validity. Use this before allowing any authenticated action.",
  {
    session_token: z.string().describe("The Descope session JWT to verify."),
  },
  async ({ session_token }) => {
    const cfg = getConfig();
    const result = await validateSession(session_token, cfg);
    return {
      content: [
        {
          type: "text",
          text: JSON.stringify(result, null, 2),
        },
      ],
    };
  }
);

// ── check_roles ───────────────────────────────────────────────────────────────

server.tool(
  "check_roles",
  "Check whether a user's token claims grant all required roles. Pass the claims JSON from validate_session. Returns allowed=true/false and missing roles.",
  {
    claims_json: z
      .string()
      .describe("JSON string of TokenClaims from validate_session.claims."),
    required_roles: z
      .array(z.string())
      .describe("List of role names the user must have."),
    tenant_id: z
      .string()
      .optional()
      .describe("Check tenant-scoped roles instead of global roles."),
  },
  async ({ claims_json, required_roles, tenant_id }) => {
    let claims: TokenClaims;
    try {
      claims = JSON.parse(claims_json) as TokenClaims;
    } catch {
      return {
        content: [
          { type: "text", text: JSON.stringify({ error: "Invalid claims JSON." }) },
        ],
      };
    }
    const result = checkRoles(claims, required_roles, tenant_id);
    return {
      content: [
        {
          type: "text",
          text: JSON.stringify(result, null, 2),
        },
      ],
    };
  }
);

// ── get_user ──────────────────────────────────────────────────────────────────

server.tool(
  "get_user",
  "Fetch a Descope user record by login ID (email/phone/userId). Requires DESCOPE_MANAGEMENT_KEY.",
  {
    login_id: z
      .string()
      .describe("User's login ID — email, phone, or Descope userId."),
  },
  async ({ login_id }) => {
    const cfg = getConfig();
    try {
      const user = await getUser(login_id, cfg);
      return {
        content: [
          { type: "text", text: JSON.stringify(user, null, 2) },
        ],
      };
    } catch (err) {
      return {
        content: [
          {
            type: "text",
            text: JSON.stringify({
              error: err instanceof Error ? err.message : String(err),
            }),
          },
        ],
      };
    }
  }
);

// ── send_magic_link ───────────────────────────────────────────────────────────

server.tool(
  "send_magic_link",
  "Send a Descope magic-link email to a user. Returns a pendingRef for polling and a masked email for display. Use this to add passwordless login to any agent-facing flow.",
  {
    email: z.string().email().describe("User's email address."),
    redirect_url: z
      .string()
      .url()
      .describe("URL where Descope redirects after the user clicks the link."),
  },
  async ({ email, redirect_url }) => {
    const cfg = getConfig();
    try {
      const result = await sendMagicLink(email, redirect_url, cfg);
      return {
        content: [
          { type: "text", text: JSON.stringify(result, null, 2) },
        ],
      };
    } catch (err) {
      return {
        content: [
          {
            type: "text",
            text: JSON.stringify({
              error: err instanceof Error ? err.message : String(err),
            }),
          },
        ],
      };
    }
  }
);

// ── Start ─────────────────────────────────────────────────────────────────────

const transport = new StdioServerTransport();
await server.connect(transport);
