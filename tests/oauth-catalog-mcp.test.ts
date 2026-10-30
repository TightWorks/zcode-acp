/**
 * Desktop 3.17 follow-ups on an oauth-only home (no config.json):
 *
 * - model setup asks `interaction/requestOfficialMcpAuthHeaders`; the reply
 *   is identity headers, not a project-token `requestAuth`
 * - Coding Plan / Coding Max advertises every enabled builtin model, including
 *   GLM-5.3-Flash, instead of the single GLM-5.3 default
 * - registry sync does not throw when config.json is absent
 *
 * Tokens here are fake JWTs. Nothing calls the network.
 */

import { createCipheriv, createHash, randomBytes } from "node:crypto";
import { mkdirSync, mkdtempSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";

import type * as acp from "@agentclientprotocol/sdk";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import { resolveCredentialSecret } from "../src/backend/credential-store.js";
import type { ServerRequest, ZcodeBackend } from "../src/backend/client.js";
import type { ZcodeAcpServer } from "../src/server.js";

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

const { builtinProviderEnv } = vi.hoisted(() => ({ builtinProviderEnv: vi.fn() }));
vi.mock("../src/backend/resolve.js", () => ({
  builtinProviderEnv,
  BUILTIN_PROVIDER_ENV: "ZCODE_BUILTIN_PROVIDER_CONFIG_FILE",
}));

import { loadAllModels } from "../src/config/options.js";
import { buildProviderRegistry } from "../src/config/provider-registry.js";
import {
  answerOfficialMcpAuthHeaders,
  handleServerRequests,
} from "../src/handlers/server-requests.js";

const TABLE = {
  revision: 28,
  config: {
    providerConfigRules: {
      providerRules: [
        {
          providerId: "account:bigmodel-individual-coding-plan",
          config: {
            access: {
              type: "zhipu-account",
              mode: "individual-coding-plan",
              accountType: "bigmodel",
            },
            builtinModelIds: ["GLM-5.3", "GLM-5.3-Flash"],
          },
        },
        {
          providerId: "account:bigmodel-start-plan",
          config: {
            access: { type: "zhipu-account", mode: "start-plan", accountType: "bigmodel" },
            builtinModelIds: ["GLM-5.2"],
          },
        },
      ],
    },
  },
};

function fakeJwt(exp: number): string {
  const header = Buffer.from(JSON.stringify({ alg: "none", typ: "JWT" })).toString("base64url");
  const payload = Buffer.from(JSON.stringify({ exp })).toString("base64url");
  return `${header}.${payload}.sig`;
}

const LOGIN = fakeJwt(4_000_000_000);
const ZCODE_JWT = fakeJwt(4_000_000_000);

function encryptCredential(plain: string): string {
  const key = createHash("sha256").update(resolveCredentialSecret()).digest();
  const iv = randomBytes(12);
  const cipher = createCipheriv("aes-256-gcm", key, iv);
  const cipherText = Buffer.concat([cipher.update(plain, "utf8"), cipher.final()]);
  return `enc:v1:${iv.toString("base64url")}.${cipher.getAuthTag().toString("base64url")}.${cipherText.toString("base64url")}`;
}

function writeStore(entries: Record<string, string>): void {
  writeFileSync(
    zcodeStorePath.value,
    JSON.stringify(
      Object.fromEntries(
        Object.entries(entries).map(([key, value]) => [key, encryptCredential(value)]),
      ),
    ),
  );
}

function writeOauth(): void {
  writeStore({
    "oauth:active_provider": "bigmodel",
    "oauth:bigmodel:access_token": LOGIN,
    "oauth:bigmodel:user_info": JSON.stringify({
      id: "user-bigmodel",
      username: "owner",
      displayName: "Owner",
    }),
    zcodejwttoken: ZCODE_JWT,
    "account-provider:account:bigmodel-individual-coding-plan:auth-source": "oauth",
    "account-provider:account:bigmodel-individual-coding-plan:identity": "key-3dc7cb82",
  });
}

let tablePath: string;

beforeEach(() => {
  const root = mkdtempSync(path.join(tmpdir(), "oauth-catalog-"));
  const v2 = path.join(root, ".zcode", "v2");
  mkdirSync(v2, { recursive: true });
  zcodeCfgPath.value = path.join(v2, "config.json");
  zcodeStorePath.value = path.join(v2, "credentials.json");
  dataRoot.value = v2;
  tablePath = path.join(root, "zcode-builtin.json");
  writeFileSync(tablePath, JSON.stringify(TABLE));
  builtinProviderEnv.mockReturnValue({ ZCODE_BUILTIN_PROVIDER_CONFIG_FILE: tablePath });
});

afterEach(() => {
  vi.clearAllMocks();
});

describe("Official MCP auth headers", () => {
  const params = {
    requestId: "req-1",
    pluginId: "plugin",
    mcpKey: "mcp",
    targetOrigin: "https://zcode.z.ai",
    workspace: { workspaceKey: "w", workspacePath: "/work" },
  };

  it("answers the method with oauth identity headers, not a project token", () => {
    writeOauth();
    const backend = { sendReply: vi.fn(), sendError: vi.fn() } as unknown as ZcodeBackend;
    expect(
      answerOfficialMcpAuthHeaders(backend, 4, "interaction/requestOfficialMcpAuthHeaders", params),
    ).toBe(true);
    expect(backend.sendReply).toHaveBeenCalledWith(4, {
      ok: true,
      headers: {
        Authorization: `Bearer ${ZCODE_JWT}`,
        "X-Bigmodel-Authorization": `Bearer ${LOGIN}`,
        "Bigmodel-Target-Type": "PERSONAL",
      },
    });
    const body = JSON.stringify(vi.mocked(backend.sendReply).mock.calls[0]![1]);
    expect(body).not.toContain("headersApplied");
    expect(body).not.toContain("apiKey");
    expect(body).not.toContain("X-Coding-Plan-Api-Key");
  });

  it("is handled inside the turn loop instead of method-not-found", async () => {
    writeOauth();
    const queue: ServerRequest[] = [
      {
        id: 11,
        method: "interaction/requestOfficialMcpAuthHeaders",
        params,
      },
    ];
    const backend = {
      pollServerRequests: () => queue.splice(0, queue.length),
      requeueServerRequests: (reqs: ServerRequest[]) => queue.unshift(...reqs),
      sendReply: vi.fn(),
      sendError: vi.fn(),
    } as unknown as ZcodeBackend;
    const server = { nextId: () => 1, resolveSid: () => undefined } as unknown as ZcodeAcpServer;
    const handled = await handleServerRequests(
      server,
      backend,
      { request: vi.fn() } as unknown as acp.AgentContext,
      "s1",
    );
    expect(handled).toBe(true);
    expect(backend.sendError).not.toHaveBeenCalled();
    expect(vi.mocked(backend.sendReply).mock.calls[0]?.[1]).toMatchObject({ ok: true });
  });

  it("fails closed when the oauth access token is expired", () => {
    writeOauth();
    writeStore({
      "oauth:active_provider": "bigmodel",
      "oauth:bigmodel:access_token": fakeJwt(1_000_000_000),
      "oauth:bigmodel:user_info": JSON.stringify({
        id: "user-bigmodel",
        username: "owner",
        displayName: "Owner",
      }),
      zcodejwttoken: ZCODE_JWT,
      "account-provider:account:bigmodel-individual-coding-plan:auth-source": "oauth",
      "account-provider:account:bigmodel-individual-coding-plan:identity": "key-3dc7cb82",
    });
    const backend = { sendReply: vi.fn(), sendError: vi.fn() } as unknown as ZcodeBackend;
    answerOfficialMcpAuthHeaders(backend, 5, "interaction/requestOfficialMcpAuthHeaders", params);
    expect(backend.sendReply).toHaveBeenCalledWith(5, {
      ok: false,
      reason: "official_auth_unavailable",
    });
  });

  it("refuses an untrusted target origin without echoing tokens", () => {
    writeOauth();
    const backend = { sendReply: vi.fn(), sendError: vi.fn() } as unknown as ZcodeBackend;
    answerOfficialMcpAuthHeaders(backend, 6, "interaction/requestOfficialMcpAuthHeaders", {
      ...params,
      targetOrigin: "https://evil.example",
    });
    const reply = vi.mocked(backend.sendReply).mock.calls[0]![1];
    expect(reply).toEqual({ ok: false, reason: "official_mcp_origin_untrusted" });
    expect(JSON.stringify(reply)).not.toContain(LOGIN);
    expect(JSON.stringify(reply)).not.toContain(ZCODE_JWT);
  });
});

describe("Coding Plan catalog without config.json", () => {
  it("lists GLM-5.3 and GLM-5.3-Flash for an entitled Coding Plan, not start-plan", () => {
    writeOauth();
    expect(loadAllModels()).toEqual([
      {
        providerId: "builtin:bigmodel-coding-plan",
        providerName: "BigModel Coding Plan",
        modelId: "GLM-5.3",
      },
      {
        providerId: "builtin:bigmodel-coding-plan",
        providerName: "BigModel Coding Plan",
        modelId: "GLM-5.3-Flash",
      },
    ]);
  });

  it("hides a model Desktop toggled off", () => {
    writeOauth();
    writeFileSync(
      path.join(dataRoot.value, "provider_config.json"),
      JSON.stringify({
        config: {
          modelConfigRules: {
            providerModelRules: [
              {
                providerId: "account:bigmodel-individual-coding-plan",
                modelId: "GLM-5.3-Flash",
                config: { enabled: false },
              },
            ],
          },
        },
      }),
    );
    expect(loadAllModels().map((model) => model.modelId)).toEqual(["GLM-5.3"]);
  });

  it("keeps the single default model when nothing is entitled", () => {
    expect(loadAllModels()).toEqual([
      { providerId: "builtin:bigmodel-coding-plan", providerName: "BigModel", modelId: "GLM-5.3" },
    ]);
  });

  it("does not throw registry sync when config.json is missing", () => {
    writeOauth();
    expect(buildProviderRegistry().providers).toEqual([]);
  });
});
