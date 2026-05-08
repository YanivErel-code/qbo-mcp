import { createRemoteJWKSet, jwtVerify } from "jose";
import type { Request } from "express";

// Cloudflare Access signs JWTs with team-specific keys at:
//   https://<team>.cloudflareaccess.com/cdn-cgi/access/certs
// and asserts the JWT to the origin via the `Cf-Access-Jwt-Assertion`
// header on every request that passed an Access policy. We verify the
// signature + audience + issuer; if it checks out, the request was made
// by a user the policy allowed (e.g. @ditto.com Google login) and we
// trust the embedded `email` claim as their identity.

const teamDomain = process.env.CF_ACCESS_TEAM_DOMAIN?.trim() || null;
const audTag = process.env.CF_ACCESS_AUD?.trim() || null;

let jwks: ReturnType<typeof createRemoteJWKSet> | null = null;
if (teamDomain) {
  jwks = createRemoteJWKSet(
    new URL(`https://${teamDomain}/cdn-cgi/access/certs`),
    // jose's defaults: 30s cooldown, 5min cache
  );
}

export const cfAccessEnabled = !!(teamDomain && audTag && jwks);

export type CfAccessIdentity = {
  email: string;
  sub: string;
};

export async function verifyCfAccessJwt(token: string): Promise<CfAccessIdentity | null> {
  if (!cfAccessEnabled || !jwks || !audTag || !teamDomain) return null;
  try {
    const { payload } = await jwtVerify(token, jwks, {
      issuer: `https://${teamDomain}`,
      audience: audTag,
    });
    const email = typeof payload.email === "string" ? payload.email.toLowerCase() : null;
    const sub = typeof payload.sub === "string" ? payload.sub : null;
    if (!email || !sub) return null;
    return { email, sub };
  } catch {
    return null;
  }
}

export function readCfAccessHeader(req: Request): string | null {
  const header = req.header("cf-access-jwt-assertion");
  if (header) return header;
  // Browsers also receive a CF_Authorization cookie that contains the same
  // JWT — only useful when the user navigates directly (not when CF is
  // forwarding the request to origin, since the header is preferred).
  const cookies = req.header("cookie");
  if (!cookies) return null;
  const m = /(?:^|;\s*)CF_Authorization=([^;]+)/.exec(cookies);
  return m ? decodeURIComponent(m[1]) : null;
}

/** Convenience: read header, verify, return identity (or null on any failure). */
export async function identifyFromCfAccess(req: Request): Promise<CfAccessIdentity | null> {
  const tok = readCfAccessHeader(req);
  if (!tok) return null;
  return verifyCfAccessJwt(tok);
}
