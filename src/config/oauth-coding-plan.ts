/**
 * Desktop Coding Plan OAuth → project access token.
 *
 * Desktop 3.12+ OAuth login persists `auth-source=oauth`, a login JWT, and a
 * stable identity. It does NOT write `account-provider:coding-plan:…:api-key`
 * (observed Desktop 3.17.1, zcode-acp#344). Upstream's host
 * (`AccountProviderRequestAuthService.resolveCurrent`) exchanges that login
 * JWT for a short-lived Project Access Token and puts the token in
 * `requestAuth.apiKey` — the field name is legacy; the value is not the
 * OAuth JWT and not a copied API-key secret.
 *
 * This module mirrors that personal-plan exchange (non-team project
 * selection, raw login JWT for customerInfo, Bearer for access_tokens).
 * Manual `auth-source=manual` and the #320 stored api-key stay on their own
 * path. An explicit oauth source never falls back to a leftover api-key.
 * Tokens are memory-only; this module does not write credentials.json.
 */

import { createHash } from "node:crypto";

import { readCredentialStoreSync } from "../backend/credential-store.js";
import { AGENT_INFO, log, warn } from "../utils.js";

export type CodingPlanFamily = "bigmodel" | "zai";

export type OauthAuthSource = "oauth" | "manual" | "absent";

export interface OauthCodingPlanSession {
  family: CodingPlanFamily;
  authSource: OauthAuthSource;
  /** Login JWT as stored. Null when the family has no access token. */
  accessToken: string | null;
  /** True when the login JWT carries an `exp` that is already past. */
  expired: boolean;
  /** Desktop user-profile id, else the persisted account-provider identity. */
  accountId: string | null;
  zcodeJwt: string | null;
}

export interface OauthCodingPlanRequestAuth {
  /** Project Access Token. The protocol field is still named `apiKey`. */
  apiKey: string;
  apiKeyId?: string;
  /** sha256 scope the backend echoes on the next headers refresh. */
  accountScope: string;
}

const PERSONAL_KEY_NAME = "zcode-api-key";
const USAGE_SCENE_CODING_PLAN = 1;
const REQUEST_TIMEOUT_MS = 15_000;
const DEFAULT_ORGANIZATION_NAME = "默认机构";
const DEFAULT_PROJECT_NAME = "默认项目";
const ZCODE_JWT_KEY = "zcodejwttoken";

const SUCCESS_CODES = new Set<unknown>([0, 200, "0", "200"]);

interface KeyLocation {
  organizationId: string;
  projectId: string;
  apiKeyId: string;
}

interface IssuedToken {
  token: string;
  apiKeyId: string;
  expiresAt: number;
  fingerprint: string;
}

interface TokenCacheEntry {
  loginToken: string;
  issued?: IssuedToken;
  pending?: Promise<IssuedToken>;
}

const tokenCache = new Map<string, TokenCacheEntry>();
const rejectedLocations = new Set<string>();

/** Drop in-memory project tokens. Tests call this between fixtures. */
export function clearOauthCodingPlanCache(): void {
  tokenCache.clear();
  rejectedLocations.clear();
}

export function codingPlanFamilyOf(accountProviderId: string | undefined): CodingPlanFamily | null {
  const match = /^account:(bigmodel|zai)-individual-coding-plan$/.exec(accountProviderId ?? "");
  return match ? (match[1] as CodingPlanFamily) : null;
}

function providerIdFor(family: CodingPlanFamily): string {
  return `account:${family}-individual-coding-plan`;
}

function readStore(): Record<string, string> {
  return readCredentialStoreSync();
}

function jwtExpired(token: string, nowMs: number): boolean {
  const parts = token.split(".");
  if (parts.length < 2 || !parts[1]) return false;
  try {
    const payload = JSON.parse(Buffer.from(parts[1], "base64url").toString("utf8")) as {
      exp?: unknown;
    };
    if (typeof payload.exp !== "number" || !Number.isFinite(payload.exp)) return false;
    return payload.exp * 1000 <= nowMs;
  } catch {
    // Three-segment token whose payload is not JSON is not a usable login JWT.
    return parts.length === 3;
  }
}

function accountIdFromUserInfo(family: CodingPlanFamily, raw: string | undefined): string | null {
  if (!raw?.trim()) return null;
  let parsed: unknown;
  try {
    parsed = JSON.parse(raw);
  } catch {
    return null;
  }
  if (!parsed || typeof parsed !== "object") return null;
  const record = parsed as Record<string, unknown>;
  if (
    typeof record.id === "string" &&
    record.id.trim() &&
    typeof record.username === "string" &&
    typeof record.displayName === "string"
  ) {
    return record.id.trim();
  }
  if (family === "zai") {
    const id = typeof record.user_id === "string" ? record.user_id.trim() : "";
    const name = typeof record.name === "string" ? record.name.trim() : "";
    const email = typeof record.email === "string" ? record.email.trim() : "";
    if (id && (id !== "unknown" || name || email)) return id === "unknown" ? null : id;
  }
  return null;
}

/** One family's oauth/manual markers, read from the decrypted credential store. */
export function readOauthCodingPlan(
  family: CodingPlanFamily,
  nowMs: number = Date.now(),
): OauthCodingPlanSession {
  const store = readStore();
  const providerId = providerIdFor(family);
  const sourceRaw = store[`account-provider:${providerId}:auth-source`]?.trim() ?? "";
  const authSource: OauthAuthSource =
    sourceRaw === "oauth" || sourceRaw === "manual" ? sourceRaw : "absent";
  const accessToken = store[`oauth:${family}:access_token`]?.trim() || null;
  const profileId = accountIdFromUserInfo(family, store[`oauth:${family}:user_info`]);
  const identity = store[`account-provider:${providerId}:identity`]?.trim() || null;
  return {
    family,
    authSource,
    accessToken,
    expired: accessToken ? jwtExpired(accessToken, nowMs) : false,
    accountId: profileId || identity,
    zcodeJwt: store[ZCODE_JWT_KEY]?.trim() || null,
  };
}

export function oauthSessionUsable(session: OauthCodingPlanSession): boolean {
  return (
    session.authSource !== "manual" &&
    Boolean(session.accessToken) &&
    !session.expired &&
    Boolean(session.accountId)
  );
}

/**
 * Families whose oauth login is itself entitlement evidence: explicit
 * `auth-source=oauth`, or a legacy record with no source marker. Manual
 * mode is excluded. Callers still decide whether a stored api-key owns the
 * no-marker case (#320).
 */
export function oauthEntitlementCandidate(session: OauthCodingPlanSession): boolean {
  if (!oauthSessionUsable(session)) return false;
  return session.authSource === "oauth" || session.authSource === "absent";
}

function accountScopeFor(session: OauthCodingPlanSession): string {
  return createHash("sha256")
    .update(
      JSON.stringify([
        session.family,
        "individual-coding-plan",
        null,
        session.accessToken,
        session.zcodeJwt,
      ]),
    )
    .digest("hex");
}

function tokenFingerprint(token: string): string {
  return createHash("sha256").update(token).digest("hex");
}

function managementOrigin(family: CodingPlanFamily): string {
  const raw =
    family === "zai"
      ? process.env.ZAI_BUSINESS_BASE_URL?.trim() || "https://api.z.ai"
      : process.env.BIGMODEL_API_BASE_URL?.trim() || "https://bigmodel.cn";
  return raw.replace(/\/+$/, "");
}

function locationStorageKey(origin: string, session: OauthCodingPlanSession): string {
  return `project-key-location:v1:${encodeURIComponent(
    JSON.stringify([
      origin,
      session.family,
      session.accountId,
      null,
      USAGE_SCENE_CODING_PLAN,
      "non-team",
    ]),
  )}`;
}

function readSavedLocation(origin: string, session: OauthCodingPlanSession): KeyLocation | null {
  const key = locationStorageKey(origin, session);
  if (rejectedLocations.has(key)) return null;
  const raw = readStore()[key];
  if (!raw) return null;
  try {
    const parsed = JSON.parse(raw) as Partial<KeyLocation>;
    if (parsed.organizationId?.trim() && parsed.projectId?.trim() && parsed.apiKeyId?.trim()) {
      return {
        organizationId: parsed.organizationId.trim(),
        projectId: parsed.projectId.trim(),
        apiKeyId: parsed.apiKeyId.trim(),
      };
    }
  } catch {
    // A damaged location record is rebuilt from customerInfo. It is not a login.
  }
  return null;
}

interface HttpResult {
  status: number;
  json: unknown;
}

async function defaultFetch(url: string, init: RequestInit): Promise<HttpResult> {
  const response = await fetch(url, {
    method: init.method,
    headers: init.headers,
    body: init.body,
    signal: AbortSignal.timeout(REQUEST_TIMEOUT_MS),
  });
  const text = await response.text();
  if (!text) return { status: response.status, json: null };
  try {
    return { status: response.status, json: JSON.parse(text) as unknown };
  } catch {
    if (response.status >= 200 && response.status < 300) {
      throw new Error("project_token_invalid_response");
    }
    return { status: response.status, json: null };
  }
}

let fetchImpl: (url: string, init: RequestInit) => Promise<HttpResult> = defaultFetch;

/** Test seam. Pass null to restore the real fetch. */
export function setOauthCodingPlanFetchForTests(
  next: ((url: string, init: RequestInit) => Promise<HttpResult>) | null,
): void {
  fetchImpl = next ?? defaultFetch;
}

function envelopeData(raw: unknown): unknown {
  if (!raw || typeof raw !== "object" || !("code" in raw)) {
    throw new Error("project_token_invalid_response");
  }
  const code = (raw as { code?: unknown }).code;
  if (code === 404) return undefined;
  if (!SUCCESS_CODES.has(code) || !("data" in raw))
    throw new Error("project_token_invalid_response");
  return (raw as { data?: unknown }).data;
}

async function callJson(url: string, init: RequestInit): Promise<unknown> {
  let result: HttpResult;
  try {
    result = await fetchImpl(url, init);
  } catch (error) {
    if (error instanceof Error && error.message === "project_token_invalid_response") throw error;
    throw new Error("project_token_network_error");
  }
  if (result.status === 404) return { code: 404 };
  if (result.status < 200 || result.status >= 300) {
    throw new Error(
      Number.isInteger(result.status) && result.status >= 100 && result.status <= 599
        ? `project_token_http_${result.status}`
        : "project_token_request_failed",
    );
  }
  return result.json;
}

function loginAuthorization(token: string, bearer: boolean): string {
  const bare = token.trim().replace(/^Bearer\s+/i, "");
  return bearer ? `Bearer ${bare}` : bare;
}

function pickPersonalProject(data: unknown): { organizationId: string; projectId: string } {
  const organizations = (data as { organizations?: unknown } | null)?.organizations;
  if (!Array.isArray(organizations)) throw new Error("project_token_invalid_response");
  const personal = organizations
    .map((organization) => {
      if (!organization || typeof organization !== "object") return null;
      const org = organization as {
        organizationId?: unknown;
        organizationName?: unknown;
        projects?: unknown;
      };
      const organizationId =
        typeof org.organizationId === "string" ? org.organizationId.trim() : "";
      const projects = Array.isArray(org.projects) ? org.projects : [];
      const kept = projects.filter((project) => {
        if (!project || typeof project !== "object") return false;
        const kind = (project as { projectType?: unknown }).projectType;
        return String(kind ?? "").trim() !== "2";
      });
      if (!organizationId || kept.length === 0) return null;
      return {
        organizationId,
        organizationName: typeof org.organizationName === "string" ? org.organizationName : "",
        projects: kept as Array<{ projectId?: unknown; projectName?: unknown }>,
      };
    })
    .filter((org): org is NonNullable<typeof org> => org !== null);
  const selected =
    personal.find((org) => org.organizationName.includes(DEFAULT_ORGANIZATION_NAME)) ?? personal[0];
  const project =
    selected?.projects.find(
      (item) =>
        typeof item.projectName === "string" && item.projectName.includes(DEFAULT_PROJECT_NAME),
    ) ?? selected?.projects[0];
  const projectId = typeof project?.projectId === "string" ? project.projectId.trim() : "";
  if (!selected?.organizationId || !projectId) throw new Error("project_token_project_unavailable");
  return { organizationId: selected.organizationId, projectId };
}

function keyIdFromEntry(entry: unknown): string | null {
  if (!entry || typeof entry !== "object") return null;
  const apiKey = (entry as { apiKey?: unknown }).apiKey;
  return typeof apiKey === "string" && apiKey.trim() ? apiKey.trim() : null;
}

async function resolveLocation(
  origin: string,
  session: OauthCodingPlanSession,
): Promise<KeyLocation> {
  const saved = readSavedLocation(origin, session);
  if (saved) return saved;
  const login = session.accessToken ?? "";
  const customer = envelopeData(
    await callJson(`${origin}/api/biz/customer/getCustomerInfo`, {
      method: "GET",
      headers: {
        Authorization: loginAuthorization(login, false),
        "Content-Type": "application/json",
      },
    }),
  );
  const place = pickPersonalProject(customer);
  const listUrl = `${origin}/api/biz/v1/organization/${encodeURIComponent(place.organizationId)}/projects/${encodeURIComponent(place.projectId)}/api_keys`;
  const keyHeaders = {
    Authorization: loginAuthorization(login, session.family === "zai"),
    "Content-Type": "application/json",
  };
  const listed = envelopeData(await callJson(listUrl, { method: "GET", headers: keyHeaders }));
  if (!Array.isArray(listed)) throw new Error("project_token_invalid_response");
  const named = listed.find(
    (entry) =>
      entry &&
      typeof entry === "object" &&
      (entry as { name?: unknown }).name === PERSONAL_KEY_NAME,
  );
  let apiKeyId = named ? keyIdFromEntry(named) : null;
  if (named && !apiKeyId) throw new Error("project_token_invalid_response");
  if (!apiKeyId) {
    const created = envelopeData(
      await callJson(listUrl, {
        method: "POST",
        headers: keyHeaders,
        body: JSON.stringify({ name: PERSONAL_KEY_NAME, usageScene: USAGE_SCENE_CODING_PLAN }),
      }),
    );
    apiKeyId = keyIdFromEntry(created);
    if (!apiKeyId) throw new Error("project_token_invalid_response");
  }
  return { ...place, apiKeyId };
}

function readIssuedToken(raw: unknown, startedAt: number): { token: string; expiresAt: number } {
  const data = envelopeData(raw);
  if (!data || typeof data !== "object") throw new Error("project_token_invalid_response");
  const record = data as {
    enable?: unknown;
    accessToken?: unknown;
    tokenType?: unknown;
    expiresIn?: unknown;
    expiresAt?: unknown;
  };
  if (record.enable === false) throw new Error("project_token_disabled");
  if (
    record.tokenType !== "Bearer" ||
    typeof record.accessToken !== "string" ||
    !record.accessToken.trim()
  ) {
    throw new Error("project_token_invalid_response");
  }
  if (typeof record.expiresIn !== "number" || typeof record.expiresAt !== "number") {
    throw new Error("project_token_invalid_response");
  }
  const expiresAt = Math.min(record.expiresAt * 1000, startedAt + record.expiresIn * 1000);
  if (!Number.isFinite(expiresAt) || expiresAt <= Date.now()) {
    throw new Error("project_token_invalid_response");
  }
  return { token: record.accessToken.trim(), expiresAt };
}

async function issueProjectToken(session: OauthCodingPlanSession): Promise<IssuedToken> {
  const origin = managementOrigin(session.family);
  const startedAt = Date.now();
  const issueAt = async (location: KeyLocation): Promise<IssuedToken> => {
    const url = `${origin}/api/biz/v1/organization/${encodeURIComponent(location.organizationId)}/projects/${encodeURIComponent(location.projectId)}/api_keys/${encodeURIComponent(location.apiKeyId)}/access_tokens`;
    const raw = await callJson(url, {
      method: "POST",
      headers: {
        Authorization: loginAuthorization(session.accessToken ?? "", true),
        "Content-Type": "application/json",
      },
      body: JSON.stringify({ clientType: "zcode", clientVersion: AGENT_INFO.version }),
    });
    if (
      raw &&
      typeof raw === "object" &&
      "code" in raw &&
      (raw as { code?: unknown }).code === 404
    ) {
      rejectedLocations.add(locationStorageKey(origin, session));
      throw new Error("project_token_http_404");
    }
    const issued = readIssuedToken(raw, startedAt);
    return { ...issued, apiKeyId: location.apiKeyId, fingerprint: tokenFingerprint(issued.token) };
  };
  try {
    return await issueAt(await resolveLocation(origin, session));
  } catch (error) {
    if (!(error instanceof Error) || error.message !== "project_token_http_404") throw error;
    return issueAt(await resolveLocation(origin, session));
  }
}

function cacheKey(session: OauthCodingPlanSession): string {
  return JSON.stringify([session.family, session.accountId, session.accessToken]);
}

async function cachedProjectToken(
  session: OauthCodingPlanSession,
  rejectedFingerprint?: string,
): Promise<IssuedToken> {
  const key = cacheKey(session);
  let entry = tokenCache.get(key);
  if (rejectedFingerprint && entry?.issued?.fingerprint === rejectedFingerprint) {
    entry.issued = undefined;
  }
  if (entry?.pending) return entry.pending;
  if (entry?.issued && Date.now() < entry.issued.expiresAt - 120_000) return entry.issued;
  if (!entry || entry.loginToken !== session.accessToken) {
    entry = { loginToken: session.accessToken ?? "" };
    tokenCache.set(key, entry);
  }
  const current = entry;
  const pending = issueProjectToken(session).then(
    (issued) => {
      if (tokenCache.get(key) === current) current.issued = issued;
      return issued;
    },
    (error: unknown) => {
      if (tokenCache.get(key) === current && current.pending) {
        // Leave a failed entry without a token so the next call retries.
        current.issued = undefined;
      }
      throw error;
    },
  );
  current.pending = pending;
  try {
    return await pending;
  } finally {
    if (current.pending === pending) current.pending = undefined;
  }
}

export interface OauthCodingPlanAuthOptions {
  expectedAccountScope?: string;
  rejectedProjectTokenFingerprint?: string;
  nowMs?: number;
}

/**
 * Resolve the request-auth material for an individual coding-plan provider
 * signed in with Desktop oauth. Returns null when oauth does not own the
 * provider, the login JWT is missing or expired, the scope check fails, or
 * token issuance fails. Never returns the login JWT or a stored api-key.
 */
export async function resolveOauthCodingPlanRequestAuth(
  accountProviderId: string | undefined,
  options: OauthCodingPlanAuthOptions = {},
): Promise<OauthCodingPlanRequestAuth | null> {
  const family = codingPlanFamilyOf(accountProviderId);
  if (!family) return null;
  const session = readOauthCodingPlan(family, options.nowMs);
  if (session.authSource === "manual") return null;
  if (!oauthSessionUsable(session)) return null;
  if (options.rejectedProjectTokenFingerprint && options.expectedAccountScope === undefined) {
    warn("oauth coding-plan: project_token_scope_invalidated");
    return null;
  }
  const accountScope = accountScopeFor(session);
  if (options.expectedAccountScope !== undefined && options.expectedAccountScope !== accountScope) {
    warn("oauth coding-plan: project_token_scope_invalidated");
    return null;
  }
  const loginToken = session.accessToken;
  try {
    const issued = await cachedProjectToken(session, options.rejectedProjectTokenFingerprint);
    const latest = readOauthCodingPlan(family, options.nowMs);
    if (latest.accessToken !== loginToken || latest.accountId !== session.accountId) {
      clearOauthCodingPlanCache();
      warn("oauth coding-plan: project_token_scope_invalidated");
      return null;
    }
    log(`oauth coding-plan: issued project token for ${family}`);
    return { apiKey: issued.token, apiKeyId: issued.apiKeyId, accountScope };
  } catch (error) {
    const code = error instanceof Error ? error.message : "project_token_request_failed";
    warn(
      `oauth coding-plan: ${code.startsWith("project_token_") ? code : "project_token_request_failed"}`,
    );
    return null;
  }
}
