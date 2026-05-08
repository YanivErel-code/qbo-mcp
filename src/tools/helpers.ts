import { authenticate, type AuthedUser } from "../auth.js";
import { QboApiError, QboNotConnectedError } from "../qbo.js";
import { config } from "../config.js";

export async function getAuthFromExtra(extra: any): Promise<AuthedUser> {
  const headers = extra?.requestInfo?.headers;
  const auth = await authenticate(
    headers?.["authorization"] ?? headers?.["Authorization"],
  );
  if (!auth) {
    throw new Error(
      "Unauthorized: missing or unknown Bearer. Visit " +
        `${config.publicBaseUrl}/connect/quickbooks to generate a static key, ` +
        "or have your MCP client perform the OAuth dance.",
    );
  }
  return auth;
}

export function jsonContent(value: unknown) {
  return {
    content: [{ type: "text" as const, text: JSON.stringify(value, null, 2) }],
  };
}

export function errorContent(message: string) {
  return {
    isError: true,
    content: [{ type: "text" as const, text: message }],
  };
}

export async function runTool<T>(
  fn: () => Promise<T>,
): Promise<{ content: Array<{ type: "text"; text: string }>; isError?: boolean }> {
  try {
    const result = await fn();
    return jsonContent(result);
  } catch (e) {
    if (e instanceof QboNotConnectedError) {
      return errorContent(
        `No QuickBooks company linked for this user. Visit ${config.publicBaseUrl}/connect/quickbooks`,
      );
    }
    if (e instanceof QboApiError) {
      return errorContent(
        `QuickBooks API error (${e.status}): ${JSON.stringify(e.body ?? e.message)}`,
      );
    }
    return errorContent((e as Error).message ?? String(e));
  }
}
