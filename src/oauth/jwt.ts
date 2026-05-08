import { SignJWT, jwtVerify } from "jose";
import { config } from "../config.js";
import { jwtSecret } from "./secret.js";

const ALG = "HS256";
const ISSUER = () => config.publicBaseUrl;
const AUDIENCE = () => `${config.publicBaseUrl}/mcp`;

const ACCESS_TTL_SECONDS = 60 * 60; // 1 hour

export type AccessTokenClaims = {
  sub: string; // user_id as string
  client_id: string;
  scope: string;
};

export async function signAccessToken(claims: AccessTokenClaims): Promise<{
  token: string;
  expiresIn: number;
}> {
  const token = await new SignJWT({
    client_id: claims.client_id,
    scope: claims.scope,
  })
    .setProtectedHeader({ alg: ALG, typ: "JWT" })
    .setSubject(claims.sub)
    .setIssuer(ISSUER())
    .setAudience(AUDIENCE())
    .setIssuedAt()
    .setExpirationTime(`${ACCESS_TTL_SECONDS}s`)
    .sign(jwtSecret);
  return { token, expiresIn: ACCESS_TTL_SECONDS };
}

export type VerifiedAccessToken = {
  userId: number;
  clientId: string;
  scope: string;
};

export async function verifyAccessToken(token: string): Promise<VerifiedAccessToken> {
  const { payload } = await jwtVerify(token, jwtSecret, {
    issuer: ISSUER(),
    audience: AUDIENCE(),
    algorithms: [ALG],
  });
  if (!payload.sub) throw new Error("missing sub");
  const userId = parseInt(payload.sub, 10);
  if (!Number.isFinite(userId)) throw new Error("invalid sub");
  return {
    userId,
    clientId: typeof payload.client_id === "string" ? payload.client_id : "",
    scope: typeof payload.scope === "string" ? payload.scope : "",
  };
}
