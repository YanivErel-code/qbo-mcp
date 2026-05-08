import { config } from "./config.js";

const AUTH_URL = "https://appcenter.intuit.com/connect/oauth2";
const TOKEN_URL = "https://oauth.platform.intuit.com/oauth2/v1/tokens/bearer";

export type IntuitTokens = {
  accessToken: string;
  refreshToken: string;
  accessExpiresAt: number;
  refreshExpiresAt: number;
};

export function buildAuthUrl(state: string): string {
  const params = new URLSearchParams({
    client_id: config.intuit.clientId,
    response_type: "code",
    scope: config.intuit.scopes.join(" "),
    redirect_uri: config.intuit.redirectUri,
    state,
  });
  return `${AUTH_URL}?${params.toString()}`;
}

async function postTokenRequest(body: URLSearchParams): Promise<IntuitTokens> {
  const basic = Buffer.from(
    `${config.intuit.clientId}:${config.intuit.clientSecret}`,
  ).toString("base64");
  const res = await fetch(TOKEN_URL, {
    method: "POST",
    headers: {
      Authorization: `Basic ${basic}`,
      Accept: "application/json",
      "Content-Type": "application/x-www-form-urlencoded",
    },
    body,
  });
  if (!res.ok) {
    const txt = await res.text();
    throw new Error(`Intuit token request failed: ${res.status} ${txt}`);
  }
  const json = (await res.json()) as {
    access_token: string;
    refresh_token: string;
    expires_in: number;
    x_refresh_token_expires_in: number;
  };
  const now = Date.now();
  return {
    accessToken: json.access_token,
    refreshToken: json.refresh_token,
    accessExpiresAt: now + json.expires_in * 1000,
    refreshExpiresAt: now + json.x_refresh_token_expires_in * 1000,
  };
}

export async function exchangeCode(code: string): Promise<IntuitTokens> {
  const body = new URLSearchParams({
    grant_type: "authorization_code",
    code,
    redirect_uri: config.intuit.redirectUri,
  });
  return postTokenRequest(body);
}

export async function refreshTokens(refreshToken: string): Promise<IntuitTokens> {
  const body = new URLSearchParams({
    grant_type: "refresh_token",
    refresh_token: refreshToken,
  });
  return postTokenRequest(body);
}
