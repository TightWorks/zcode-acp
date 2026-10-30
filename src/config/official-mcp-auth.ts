/**
 * `interaction/requestOfficialMcpAuthHeaders` (Desktop 3.17).
 *
 * Model setup asks the host for official MCP identity headers. The reply is
 * `{ok, headers}`, not `requestProviderRuntimeHeaders`'s
 * `{headersApplied, requestAuth}`. Upstream puts the ZCode login JWT on
 * `Authorization` and the family's OAuth access token (MaaS JWT) on
 * `X-Bigmodel-Authorization`. A Coding Plan API key or project access token
 * must not be substituted: the server still honors `X-Coding-Plan-Api-Key`,
 * and sending it next to the JWT 403s.
 *
 * Missing, expired, or cross-family oauth fails closed. Tokens are not logged.
 */

import { readCredentialStoreSync } from "../backend/credential-store.js";
import { readOauthCodingPlan, type CodingPlanFamily } from "./oauth-coding-plan.js";

const DEFAULT_ZCODE_ORIGIN = "https://zcode.z.ai";

export const OFFICIAL_MCP_AUTH_METHOD = "interaction/requestOfficialMcpAuthHeaders";

export type OfficialMcpAuthReason =
  "official_auth_unavailable" | "official_auth_plan_required" | "official_mcp_origin_untrusted";

export type OfficialMcpAuthReply =
  { ok: true; headers: Record<string, string> } | { ok: false; reason: OfficialMcpAuthReason };

function bearer(token: string): string {
  return `Bearer ${token.trim().replace(/^Bearer\s+/i, "")}`;
}

function jwtExpired(token: string, nowMs: number): boolean {
  const payload = token.split(".")[1];
  if (!payload) return false;
  try {
    const decoded = JSON.parse(Buffer.from(payload, "base64url").toString("utf8")) as {
      exp?: unknown;
    };
    return typeof decoded.exp === "number" && decoded.exp * 1000 <= nowMs;
  } catch {
    return token.split(".").length === 3;
  }
}

function allowedOrigins(): Set<string> {
  const out = new Set<string>();
  for (const raw of [
    process.env.ZCODE_ENDPOINT_ORIGIN,
    process.env.ZCODE_BASE_URL,
    DEFAULT_ZCODE_ORIGIN,
  ]) {
    if (!raw?.trim()) continue;
    try {
      out.add(new URL(raw.trim()).origin);
    } catch {
      // A bad override must not drop the default origin.
    }
  }
  return out;
}

function originTrusted(targetOrigin: unknown): boolean {
  if (typeof targetOrigin !== "string" || !targetOrigin.trim()) return false;
  try {
    return allowedOrigins().has(new URL(targetOrigin).origin);
  } catch {
    return false;
  }
}

function activeProvider(): CodingPlanFamily | null {
  const raw = readCredentialStoreSync()["oauth:active_provider"]?.trim();
  return raw === "bigmodel" || raw === "zai" ? raw : null;
}

function familyUsable(family: CodingPlanFamily, nowMs: number): boolean {
  const session = readOauthCodingPlan(family, nowMs);
  return (
    session.authSource !== "manual" &&
    Boolean(session.accessToken) &&
    !session.expired &&
    Boolean(session.accountId)
  );
}

/**
 * `oauth:active_provider` selects the family. Without it, a single usable
 * family is used. Two usable families are not guessed, and a marked family
 * whose token is missing or expired is not replaced by the other family.
 */
function codingPlanFamily(nowMs: number): CodingPlanFamily | null {
  const marked = activeProvider();
  if (marked) return familyUsable(marked, nowMs) ? marked : null;
  const usable = (["bigmodel", "zai"] as const).filter((family) => familyUsable(family, nowMs));
  return usable.length === 1 ? usable[0]! : null;
}

/**
 * Host reply for one Official MCP auth request. Both JWTs are already in
 * the credential store, so this does not call the project-token exchange.
 */
export function officialMcpAuthReply(
  params: Record<string, unknown>,
  nowMs: number = Date.now(),
): OfficialMcpAuthReply {
  if (!originTrusted(params.targetOrigin)) {
    return { ok: false, reason: "official_mcp_origin_untrusted" };
  }
  const zcodeJwt = readCredentialStoreSync()["zcodejwttoken"]?.trim() ?? "";
  if (!zcodeJwt || jwtExpired(zcodeJwt, nowMs)) {
    return { ok: false, reason: "official_auth_unavailable" };
  }
  const family = codingPlanFamily(nowMs);
  const session = family ? readOauthCodingPlan(family, nowMs) : null;
  const planReady =
    Boolean(session?.accessToken) && session?.expired === false && session?.authSource !== "manual";
  if (!planReady || !session?.accessToken) {
    // Plugin commands may proceed with the login identity alone. Official MCP
    // servers need the coding-plan JWT; do not invent a key for them.
    if (params.consumer === "plugin-command") {
      return { ok: true, headers: { Authorization: bearer(zcodeJwt) } };
    }
    return { ok: false, reason: "official_auth_unavailable" };
  }
  return {
    ok: true,
    headers: {
      Authorization: bearer(zcodeJwt),
      "X-Bigmodel-Authorization": bearer(session.accessToken),
      "Bigmodel-Target-Type": "PERSONAL",
    },
  };
}
