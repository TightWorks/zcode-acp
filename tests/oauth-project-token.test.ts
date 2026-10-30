/**
 * Desktop OAuth coding-plan request auth (#344).
 *
 * The host does not put the login JWT on the model request. It exchanges that
 * JWT for a project access token and answers runtime headers with
 * `{ apiKey: <token>, apiKeyId, accountScope }`. These tests use fake tokens
 * and a scripted fetch — nothing calls bigmodel.cn.
 */

import { createCipheriv, createHash, randomBytes } from "node:crypto";
import { mkdirSync, mkdtempSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";

import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import { resolveCredentialSecret } from "../src/backend/credential-store.js";
import type { ZcodeBackend } from "../src/backend/client.js";
import { AGENT_INFO } from "../src/utils.js";

const { zcodeCfgPath, zcodeStorePath, dataRoot } = vi.hoisted(() => ({
  zcodeCfgPath: { value: "" },
  zcodeStorePath: { value: "" },
  dataRoot: { value: "" },
}));

vi.mock("../src/utils.js", async (importOriginal) => {
  const actual = await importOriginal<typeof import("../src/utils.js")>();
  return {
    ...actual,
    get ZCODE_CREDS_PATH() {
      return zcodeCfgPath.value;
    },
    zcodeCredentialsPath: () => zcodeStorePath.value,
    zcodePersonalProviderPath: () => path.join(dataRoot.value, "provider_config.json"),
  };
});

import { answerProviderRuntimeHeaders } from "../src/handlers/server-requests.js";
import {
  clearOauthCodingPlanCache,
  resolveOauthCodingPlanRequestAuth,
  setOauthCodingPlanFetchForTests,
} from "../src/config/oauth-coding-plan.js";

const PROVIDER = "account:bigmodel-individual-coding-plan";
const LOGIN = fakeJwt(4_000_000_000);

function fakeJwt(exp: number): string {
  const header = Buffer.from(JSON.stringify({ alg: "none", typ: "JWT" })).toString("base64url");
  const payload = Buffer.from(JSON.stringify({ exp })).toString("base64url");
  return `${header}.${payload}.sig`;
}

function encryptCredential(plain: string): string {
  const key = createHash("sha256").update(resolveCredentialSecret()).digest();
  const iv = randomBytes(12);
  const cipher = createCipheriv("aes-256-gcm", key, iv);
  const cipherText = Buffer.concat([cipher.update(plain, "utf8"), cipher.final()]);
  return `enc:v1:${iv.toString("base64url")}.${cipher.getAuthTag().toString("base64url")}.${cipherText.toString("base64url")}`;
}

function writeCredentialStore(entries: Record<string, string>): void {
  writeFileSync(
    zcodeStorePath.value,
    JSON.stringify(
      Object.fromEntries(
        Object.entries(entries).map(([key, value]) => [key, encryptCredential(value)]),
      ),
    ),
  );
}

function oauthStore(overrides: Record<string, string> = {}): void {
  writeCredentialStore({
    "oauth:bigmodel:access_token": LOGIN,
    "oauth:bigmodel:user_info": JSON.stringify({
      id: "user-bigmodel",
      username: "owner",
      displayName: "Owner",
    }),
    "oauth:active_provider": "bigmodel",
    zcodejwttoken: fakeJwt(4_000_000_000),
    [`account-provider:${PROVIDER}:auth-source`]: "oauth",
    [`account-provider:${PROVIDER}:identity`]: "key-3dc7cb82",
    ...overrides,
  });
}

interface Recorded {
  url: string;
  init: RequestInit;
}

function authHeader(init: RequestInit): string {
  const headers = new Headers(init.headers);
  return headers.get("authorization") ?? "";
}

function customerInfoBody() {
  return {
    code: 200,
    data: {
      organizations: [
        {
          organizationId: "org-team",
          organizationName: "Team Org",
          projects: [{ projectId: "proj-team", projectName: "Team", projectType: "2" }],
        },
        {
          organizationId: "org-1",
          organizationName: "默认机构",
          projects: [
            { projectId: "proj-other", projectName: "Other", projectType: 1 },
            { projectId: "proj-1", projectName: "默认项目", projectType: "1" },
          ],
        },
      ],
    },
  };
}

function tokenBody() {
  return {
    code: 200,
    data: {
      accessToken: "pat-test-token",
      tokenType: "Bearer",
      expiresIn: 3600,
      expiresAt: 4_000_000_000,
    },
  };
}

let calls: Recorded[];

function installFetch(options?: { list?: unknown[]; status?: number }): void {
  calls = [];
  setOauthCodingPlanFetchForTests(async (url, init) => {
    calls.push({ url, init });
    if (options?.status) return { status: options.status, json: { code: options.status } };
    const pathname = new URL(url).pathname;
    if (pathname.endsWith("/getCustomerInfo")) return { status: 200, json: customerInfoBody() };
    if (pathname.endsWith("/api_keys") && init.method === "GET") {
      return {
        status: 200,
        json: { code: 0, data: options?.list ?? [{ name: "zcode-api-key", apiKey: "key-id-1" }] },
      };
    }
    if (pathname.endsWith("/api_keys") && init.method === "POST") {
      return {
        status: 200,
        json: { code: 200, data: { name: "zcode-api-key", apiKey: "key-created" } },
      };
    }
    if (pathname.endsWith("/access_tokens")) return { status: 200, json: tokenBody() };
    return { status: 500, json: null };
  });
}

function makeBackend() {
  return { sendReply: vi.fn(), sendError: vi.fn() } as unknown as ZcodeBackend;
}

beforeEach(() => {
  const root = mkdtempSync(path.join(tmpdir(), "oauth-pat-"));
  const v2 = path.join(root, ".zcode", "v2");
  mkdirSync(v2, { recursive: true });
  zcodeCfgPath.value = path.join(v2, "config.json");
  zcodeStorePath.value = path.join(v2, "credentials.json");
  dataRoot.value = v2;
  clearOauthCodingPlanCache();
  calls = [];
});

afterEach(() => {
  clearOauthCodingPlanCache();
  setOauthCodingPlanFetchForTests(null);
});

describe("oauth project access token", () => {
  it("answers runtime headers with the project token, not the login JWT", async () => {
    oauthStore();
    installFetch();
    const backend = makeBackend();
    expect(
      answerProviderRuntimeHeaders(backend, 7, "interaction/requestProviderRuntimeHeaders", {
        providerId: PROVIDER,
        modelSelection: { providerId: PROVIDER, modelId: "GLM-5.3" },
      }),
    ).toBe(true);
    await vi.waitFor(() => expect(backend.sendReply).toHaveBeenCalled());
    const reply = vi.mocked(backend.sendReply).mock.calls[0]![1] as {
      headersApplied: boolean;
      requestAuth: { apiKey: string; apiKeyId?: string; accountScope?: string };
    };
    expect(reply.headersApplied).toBe(true);
    expect(reply.requestAuth.apiKey).toBe("pat-test-token");
    expect(reply.requestAuth.apiKey).not.toBe(LOGIN);
    expect(reply.requestAuth.apiKeyId).toBe("key-id-1");
    expect(reply.requestAuth.accountScope).toMatch(/^[a-f0-9]{64}$/);

    const customer = calls.find((call) => call.url.endsWith("/getCustomerInfo"))!;
    expect(authHeader(customer.init)).toBe(LOGIN);
    const list = calls.find(
      (call) => call.url.endsWith("/api_keys") && call.init.method === "GET",
    )!;
    expect(authHeader(list.init)).toBe(LOGIN);
    expect(list.url).toContain("/organization/org-1/projects/proj-1/api_keys");
    const issued = calls.find((call) => call.url.endsWith("/access_tokens"))!;
    expect(authHeader(issued.init)).toBe(`Bearer ${LOGIN}`);
    expect(issued.init.body).toBe(
      JSON.stringify({ clientType: "zcode", clientVersion: AGENT_INFO.version }),
    );
    expect(calls.some((call) => call.url.includes("/copy/"))).toBe(false);
  });

  it("creates zcode-api-key when the personal project has none", async () => {
    oauthStore();
    installFetch({ list: [] });
    const auth = await resolveOauthCodingPlanRequestAuth(PROVIDER);
    expect(auth?.apiKey).toBe("pat-test-token");
    expect(auth?.apiKeyId).toBe("key-created");
    const created = calls.find(
      (call) => call.init.method === "POST" && call.url.endsWith("/api_keys"),
    )!;
    expect(created.init.body).toBe(JSON.stringify({ name: "zcode-api-key", usageScene: 1 }));
  });

  it("reuses a persisted project-key location and skips customer lookup", async () => {
    const storageKey = `project-key-location:v1:${encodeURIComponent(
      JSON.stringify(["https://bigmodel.cn", "bigmodel", "user-bigmodel", null, 1, "non-team"]),
    )}`;
    oauthStore({
      [storageKey]: JSON.stringify({
        organizationId: "org-saved",
        projectId: "proj-saved",
        apiKeyId: "key-saved",
      }),
    });
    installFetch();
    const auth = await resolveOauthCodingPlanRequestAuth(PROVIDER);
    expect(auth?.apiKeyId).toBe("key-saved");
    expect(calls.map((call) => new URL(call.url).pathname)).toEqual([
      "/api/biz/v1/organization/org-saved/projects/proj-saved/api_keys/key-saved/access_tokens",
    ]);
  });

  it("uses Bearer for Z.AI key management and the raw token for customerInfo", async () => {
    const zaiLogin = fakeJwt(4_000_000_000);
    writeCredentialStore({
      "oauth:zai:access_token": zaiLogin,
      "oauth:zai:user_info": JSON.stringify({ user_id: "zai-user", name: "Zai" }),
      "account-provider:account:zai-individual-coding-plan:auth-source": "oauth",
    });
    installFetch();
    const auth = await resolveOauthCodingPlanRequestAuth("account:zai-individual-coding-plan");
    expect(auth?.apiKey).toBe("pat-test-token");
    const customer = calls.find((call) => call.url.startsWith("https://api.z.ai/"))!;
    expect(customer.url).toContain("/api/biz/customer/getCustomerInfo");
    expect(authHeader(customer.init)).toBe(zaiLogin);
    const list = calls.find(
      (call) => call.url.includes("api.z.ai") && call.url.endsWith("/api_keys"),
    )!;
    expect(authHeader(list.init)).toBe(`Bearer ${zaiLogin}`);
  });

  it("fails closed on an expired login without calling the token API", async () => {
    oauthStore({ "oauth:bigmodel:access_token": fakeJwt(1_000_000_000) });
    installFetch();
    const backend = makeBackend();
    answerProviderRuntimeHeaders(backend, 8, "interaction/requestProviderRuntimeHeaders", {
      providerId: PROVIDER,
    });
    await vi.waitFor(() => expect(backend.sendReply).toHaveBeenCalled());
    const reply = vi.mocked(backend.sendReply).mock.calls[0]![1] as {
      headersApplied: boolean;
      errorMessage?: string;
      requestAuth?: { apiKey?: string };
    };
    expect(reply.headersApplied).toBe(false);
    expect(reply.requestAuth).toBeUndefined();
    expect(reply.errorMessage).toContain("OAuth");
    expect(calls).toHaveLength(0);
  });

  it("fails closed when the oauth access token is missing", async () => {
    writeCredentialStore({
      "oauth:bigmodel:user_info": JSON.stringify({
        id: "user-bigmodel",
        username: "owner",
        displayName: "Owner",
      }),
      [`account-provider:${PROVIDER}:auth-source`]: "oauth",
    });
    installFetch();
    expect(await resolveOauthCodingPlanRequestAuth(PROVIDER)).toBeNull();
    expect(calls).toHaveLength(0);
  });

  it("fails closed on HTTP 401 and does not fall back to a leftover api-key", async () => {
    oauthStore({
      "account-provider:coding-plan:account:bigmodel-individual-coding-plan:account:108:api-key":
        "leftover-key",
    });
    installFetch({ status: 401 });
    const backend = makeBackend();
    answerProviderRuntimeHeaders(backend, 9, "interaction/requestProviderRuntimeHeaders", {
      providerId: PROVIDER,
    });
    await vi.waitFor(() => expect(backend.sendReply).toHaveBeenCalled());
    const reply = vi.mocked(backend.sendReply).mock.calls[0]![1] as {
      headersApplied: boolean;
      requestAuth?: { apiKey?: string };
    };
    expect(reply.headersApplied).toBe(false);
    expect(JSON.stringify(reply)).not.toContain("leftover-key");
    expect(JSON.stringify(reply)).not.toContain(LOGIN);
  });

  it("fails closed when the echoed account scope does not match", async () => {
    oauthStore();
    installFetch();
    const auth = await resolveOauthCodingPlanRequestAuth(PROVIDER, {
      expectedAccountScope: "a".repeat(64),
    });
    expect(auth).toBeNull();
    expect(calls).toHaveLength(0);
  });
});
