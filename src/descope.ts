/**
 * Descope auth helpers — thin wrappers that validate JWTs and session
 * tokens using Descope's public-key endpoint. No SDK dependency required:
 * we do the JWKS fetch + RS256 verification manually so the MCP server
 * stays small and auditable.
 *
 * All functions accept an optional `baseUrl` for self-hosted Descope or
 * testing. In tests pass a mock fetch; in production leave it undefined.
 */

export interface DescopeConfig {
  projectId: string;
  baseUrl?: string; // default: https://api.descope.com
  managementKey?: string; // only needed for admin tools
}

export interface TokenClaims {
  sub: string;
  iss: string;
  aud: string | string[];
  exp: number;
  iat: number;
  email?: string;
  name?: string;
  roles?: string[];
  tenants?: Record<string, { roles: string[] }>;
  [key: string]: unknown;
}

export interface SessionValidation {
  valid: boolean;
  claims?: TokenClaims;
  error?: string;
  expiredAt?: string;
}

export interface UserRecord {
  userId: string;
  email?: string;
  phone?: string;
  name?: string;
  roles?: string[];
  tenants?: string[];
  createdTime?: number;
  status?: string;
}

export interface MagicLinkResult {
  pendingRef: string;
  maskedEmail: string;
}

// ── JWT utilities (no third-party dep) ──────────────────────────────────────

function b64urlDecode(s: string): Uint8Array {
  const padded = s.replace(/-/g, "+").replace(/_/g, "/");
  const bin = atob(padded);
  return Uint8Array.from(bin, (c) => c.charCodeAt(0));
}

function parseJwtPayload(token: string): TokenClaims {
  const [, payload] = token.split(".");
  if (!payload) throw new Error("Malformed JWT — no payload segment.");
  const json = new TextDecoder().decode(b64urlDecode(payload));
  return JSON.parse(json) as TokenClaims;
}

// ── JWKS-based RS256 verification (WebCrypto) ────────────────────────────────

async function verifyJwt(
  token: string,
  projectId: string,
  baseUrl = "https://api.descope.com",
  fetchFn: typeof fetch = fetch
): Promise<TokenClaims> {
  // 1. Parse header to get kid
  const [headerB64, payloadB64, sigB64] = token.split(".");
  if (!headerB64 || !payloadB64 || !sigB64) throw new Error("Malformed JWT.");

  const header = JSON.parse(
    new TextDecoder().decode(b64urlDecode(headerB64))
  ) as { kid?: string; alg?: string };

  // 2. Fetch JWKS
  const jwksUrl = `${baseUrl}/${projectId}/.well-known/jwks.json`;
  const res = await fetchFn(jwksUrl);
  if (!res.ok) throw new Error(`JWKS fetch failed: ${res.status}`);
  const jwks = (await res.json()) as { keys: JsonWebKey[] };

  const jwk = jwks.keys.find((k) => (k as { kid?: string }).kid === header.kid) ?? jwks.keys[0];
  if (!jwk) throw new Error("No matching JWK found.");

  // 3. Import key and verify
  const cryptoKey = await crypto.subtle.importKey(
    "jwk",
    jwk,
    { name: "RSASSA-PKCS1-v1_5", hash: "SHA-256" },
    false,
    ["verify"]
  );

  const data = new TextEncoder().encode(`${headerB64}.${payloadB64}`);
  const sigBytes = b64urlDecode(sigB64);
  const ok = await crypto.subtle.verify("RSASSA-PKCS1-v1_5", cryptoKey, sigBytes.buffer as ArrayBuffer, data);
  if (!ok) throw new Error("JWT signature invalid.");

  // 4. Validate expiry
  const claims = parseJwtPayload(token);
  if (claims.exp < Math.floor(Date.now() / 1000)) {
    throw new Error(`JWT expired at ${new Date(claims.exp * 1000).toISOString()}`);
  }
  return claims;
}

// ── Public helpers ────────────────────────────────────────────────────────────

export async function validateSession(
  sessionToken: string,
  cfg: DescopeConfig,
  fetchFn: typeof fetch = fetch
): Promise<SessionValidation> {
  try {
    const claims = await verifyJwt(
      sessionToken,
      cfg.projectId,
      cfg.baseUrl,
      fetchFn
    );
    return { valid: true, claims };
  } catch (err) {
    const msg = err instanceof Error ? err.message : String(err);
    const isExpired = msg.toLowerCase().includes("expired");
    return {
      valid: false,
      error: msg,
      ...(isExpired
        ? {
            expiredAt: new Date(
              parseJwtPayload(sessionToken).exp * 1000
            ).toISOString(),
          }
        : {}),
    };
  }
}

export function checkRoles(
  claims: TokenClaims,
  requiredRoles: string[],
  tenantId?: string
): { allowed: boolean; missing: string[] } {
  let grantedRoles: string[] = [];

  if (tenantId && claims.tenants?.[tenantId]) {
    grantedRoles = claims.tenants[tenantId].roles ?? [];
  } else {
    grantedRoles = claims.roles ?? [];
  }

  const missing = requiredRoles.filter((r) => !grantedRoles.includes(r));
  return { allowed: missing.length === 0, missing };
}

export async function getUser(
  userId: string,
  cfg: DescopeConfig,
  fetchFn: typeof fetch = fetch
): Promise<UserRecord> {
  if (!cfg.managementKey) throw new Error("managementKey required for user lookup.");
  const base = cfg.baseUrl ?? "https://api.descope.com";
  const url = `${base}/v1/mgmt/user?loginId=${encodeURIComponent(userId)}`;
  const res = await fetchFn(url, {
    headers: {
      Authorization: `Bearer ${cfg.projectId}:${cfg.managementKey}`,
    },
  });
  if (!res.ok) throw new Error(`Descope user API error ${res.status}`);
  const data = (await res.json()) as {
    user: {
      userId?: string;
      email?: string;
      phone?: string;
      name?: string;
      roleNames?: string[];
      userTenants?: Array<{ tenantId: string }>;
      createdTime?: number;
      status?: string;
    };
  };
  const u = data.user;
  return {
    userId: u.userId ?? userId,
    email: u.email,
    phone: u.phone,
    name: u.name,
    roles: u.roleNames,
    tenants: u.userTenants?.map((t) => t.tenantId),
    createdTime: u.createdTime,
    status: u.status,
  };
}

export async function sendMagicLink(
  email: string,
  redirectUrl: string,
  cfg: DescopeConfig,
  fetchFn: typeof fetch = fetch
): Promise<MagicLinkResult> {
  const base = cfg.baseUrl ?? "https://api.descope.com";
  const url = `${base}/v1/auth/magiclink/signup-or-in/email`;
  const res = await fetchFn(url, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      Authorization: `Bearer ${cfg.projectId}`,
    },
    body: JSON.stringify({ loginId: email, uri: redirectUrl }),
  });
  if (!res.ok) throw new Error(`Descope magic-link error ${res.status}: ${await res.text()}`);
  const data = (await res.json()) as { pendingRef?: string; maskedEmail?: string };
  return {
    pendingRef: data.pendingRef ?? "",
    maskedEmail: data.maskedEmail ?? email.replace(/(.{2}).*(@.*)/, "$1***$2"),
  };
}
