// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

import assert from "node:assert/strict";
import { mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";

import {
  evaluateOpenCodeTool,
  loadPolicy,
} from "../lib/opencode-policy.mjs";

function makePolicy(overrides = {}) {
  const toolPolicies = {
    allowedTools: ["bash", "webfetch"],
    blockedTools: [],
    defaultEffect: "allow",
    reviewTools: [],
    ...(overrides.toolPolicies ?? {}),
  };
  const directResourcePolicies = {
    pathRules: [],
    urlRules: [],
    ...(overrides.directResourcePolicies ?? {}),
  };

  return {
    schemaVersion: 1,
    version: 1,
    mode: "enforce",
    denyOnPolicyError: true,
    minimumPromptDefenseGrade: "B",
    additionalContext: [],
    blockedToolCalls: [],
    poisoningPatterns: [],
    ...overrides,
    toolPolicies,
    directResourcePolicies,
  };
}

async function withPolicy(raw, callback) {
  const root = await mkdtemp(join(tmpdir(), "agt-opencode-allowlist-"));
  const policyPath = join(root, "policy.json");
  const auditPath = join(root, "audit.json");
  await writeFile(policyPath, JSON.stringify(raw, null, 2), "utf8");

  try {
    const state = await loadPolicy({ policyPath, auditPath, homeDirectory: root });
    await callback(state, root);
  } finally {
    await rm(root, { recursive: true, force: true });
  }
}

test("command allowlist normalizes outer whitespace and denies unmatched commands", async () => {
  await withPolicy(
    makePolicy({
      toolPolicies: {
        commandDefaultEffect: "deny",
        allowedCommandPatterns: [
          { source: "^git\\s+status$", flags: "i" },
        ],
      },
    }),
    async (state, root) => {
      const allowed = await evaluateOpenCodeTool(state, {
        tool: "bash",
        args: { command: "  \r\ngit status\r\n  " },
        cwd: root,
        sessionId: "command-allow",
      });
      assert.equal(allowed.effect, "allow");

      const denied = await evaluateOpenCodeTool(state, {
        tool: "bash",
        args: { command: "npm publish" },
        cwd: root,
        sessionId: "command-deny",
      });
      assert.equal(denied.effect, "deny");
      assert.match(denied.reason, /command allowlist denied/i);
    },
  );
});

test("command allowlist is limited to command-bearing tool calls", async () => {
  await withPolicy(
    makePolicy({
      toolPolicies: {
        commandDefaultEffect: "deny",
        allowedCommandPatterns: [{ source: "^git\\s+status$", flags: "i" }],
      },
      directResourcePolicies: {
        urlDefaultEffect: "deny",
        allowedDomains: ["api.github.com"],
      },
    }),
    async (state, root) => {
      const webfetch = await evaluateOpenCodeTool(state, {
        tool: "webfetch",
        args: { url: "https://api.github.com/repos/microsoft/agent-governance-toolkit" },
        cwd: root,
        sessionId: "command-scope-webfetch",
      });
      assert.equal(webfetch.effect, "allow");

      const allowedInput = await evaluateOpenCodeTool(state, {
        tool: "bash",
        args: { input: "git status" },
        cwd: root,
        sessionId: "command-scope-bash-input-allow",
      });
      assert.equal(allowedInput.effect, "allow");

      const deniedInput = await evaluateOpenCodeTool(state, {
        tool: "bash",
        args: { input: "npm publish" },
        cwd: root,
        sessionId: "command-scope-bash-input-deny",
      });
      assert.equal(deniedInput.effect, "deny");
      assert.match(deniedInput.reason, /command allowlist denied/i);
    },
  );
});

test("command allowlist does not override an existing deny rule", async () => {
  await withPolicy(
    makePolicy({
      toolPolicies: {
        commandDefaultEffect: "deny",
        allowedCommandPatterns: [{ source: "^[\\s\\S]+$" }],
      },
      blockedToolCalls: [
        {
          id: "blocked-marker",
          tool: "bash",
          effect: "deny",
          reason: "Custom deny rule won.",
          commandPatterns: [{ source: "forbidden-marker", flags: "i" }],
        },
      ],
    }),
    async (state, root) => {
      const result = await evaluateOpenCodeTool(state, {
        tool: "bash",
        args: { command: "echo forbidden-marker" },
        cwd: root,
        sessionId: "deny-wins",
      });

      assert.equal(result.effect, "deny");
      assert.match(result.reason, /custom deny rule won/i);
    },
  );
});

test("URL allowlist supports exact hosts, wildcard subdomains, URL patterns, and ports", async () => {
  await withPolicy(
    makePolicy({
      directResourcePolicies: {
        urlDefaultEffect: "deny",
        allowedDomains: [
          "api.github.com",
          "*.example.com",
          "internal.example.net:8443",
        ],
        allowedUrlPatterns: [
          { source: "^https://status\\.example\\.net/health(?:\\?|$)", flags: "i" },
        ],
      },
    }),
    async (state, root) => {
      for (const url of [
        "https://api.github.com/repos/microsoft/agent-governance-toolkit",
        "https://build.example.com/artifacts",
        "https://deep.build.example.com/artifacts",
        "https://internal.example.net:8443/v1",
        "https://status.example.net/health?full=1",
      ]) {
        const result = await evaluateOpenCodeTool(state, {
          tool: "webfetch",
          args: { url },
          cwd: root,
          sessionId: `allowed-${url}`,
        });
        assert.equal(result.effect, "allow", url);
      }

      for (const url of [
        "https://example.com/",
        "https://api.github.com.evil.invalid/",
        "https://internal.example.net:9443/v1",
        "https://status.example.net/private",
      ]) {
        const result = await evaluateOpenCodeTool(state, {
          tool: "webfetch",
          args: { url },
          cwd: root,
          sessionId: `denied-${url}`,
        });
        assert.equal(result.effect, "deny", url);
        assert.match(result.reason, /url allowlist denied/i);
      }
    },
  );
});

test("URL default deny canonicalizes alternate HTTP(S) spellings", async () => {
  await withPolicy(
    makePolicy({
      directResourcePolicies: {
        urlDefaultEffect: "deny",
        allowedDomains: ["api.github.com"],
      },
    }),
    async (state, root) => {
      const allowed = await evaluateOpenCodeTool(state, {
        tool: "webfetch",
        args: { url: String.raw`https:\\api.github.com/repos/microsoft/agent-governance-toolkit` },
        cwd: root,
        sessionId: "url-canonicalized-allow",
      });
      assert.equal(allowed.effect, "allow");

      for (const url of [
        String.raw`https:\\collector.invalid/next`,
        "https:/collector.invalid/next",
      ]) {
        const denied = await evaluateOpenCodeTool(state, {
          tool: "webfetch",
          args: { url },
          cwd: root,
          sessionId: `url-canonicalized-deny-${url}`,
        });
        assert.equal(denied.effect, "deny", url);
        assert.match(denied.reason, /collector\.invalid/i);
      }
    },
  );
});

test("URL default deny checks every URL-valued argument including redirect targets", async () => {
  await withPolicy(
    makePolicy({
      directResourcePolicies: {
        urlDefaultEffect: "deny",
        allowedDomains: ["api.github.com"],
      },
    }),
    async (state, root) => {
      const result = await evaluateOpenCodeTool(state, {
        tool: "webfetch",
        args: {
          url: "https://api.github.com/start",
          redirectUrl: "https://collector.invalid/next",
        },
        cwd: root,
        sessionId: "redirect-deny",
      });

      assert.equal(result.effect, "deny");
      assert.match(result.reason, /collector\.invalid/i);
    },
  );
});

test("URL allowlist cannot override a direct-resource deny", async () => {
  await withPolicy(
    makePolicy({
      directResourcePolicies: {
        urlDefaultEffect: "deny",
        allowedDomains: ["169.254.169.254"],
        urlRules: [
          {
            id: "metadata",
            effect: "deny",
            reason: "Metadata endpoint remains blocked.",
            urlPatterns: [
              { source: "^http://169\\.254\\.169\\.254(?:/|$)", flags: "i" },
            ],
          },
        ],
      },
    }),
    async (state, root) => {
      for (const url of [
        "http://169.254.169.254/latest/meta-data/",
        String.raw`http:\\169.254.169.254\latest\meta-data`,
      ]) {
        const result = await evaluateOpenCodeTool(state, {
          tool: "webfetch",
          args: { url },
          cwd: root,
          sessionId: `metadata-deny-${url}`,
        });

        assert.equal(result.effect, "deny", url);
        assert.match(result.reason, /metadata endpoint remains blocked/i);
      }
    },
  );
});

test("invalid positive-allowlist configuration is a fail-closed policy error", async () => {
  await withPolicy(
    makePolicy({
      directResourcePolicies: {
        urlDefaultEffect: "deny",
        allowedDomains: ["https://example.com"],
      },
    }),
    async (state, root) => {
      assert.match(
        state.configuredPolicyError?.message ?? "",
        /allowedDomains.*host and optional port/i,
      );

      const result = await evaluateOpenCodeTool(state, {
        tool: "webfetch",
        args: { url: "https://example.com/" },
        cwd: root,
        sessionId: "invalid-policy",
      });
      assert.equal(result.effect, "deny");
      assert.match(result.reason, /policy could not be loaded/i);
    },
  );
});

test("domain validation rejects URL-parser separator ambiguities", async () => {
  await withPolicy(
    makePolicy({
      directResourcePolicies: {
        urlDefaultEffect: "deny",
        allowedDomains: [String.raw`example.com\unexpected`],
      },
    }),
    async (state) => {
      assert.match(
        state.configuredPolicyError?.message ?? "",
        /allowedDomains.*host and optional port/i,
      );
    },
  );
});

test("stateful regex flags are rejected to keep allowlist decisions deterministic", async () => {
  await withPolicy(
    makePolicy({
      toolPolicies: {
        commandDefaultEffect: "deny",
        allowedCommandPatterns: [{ source: "^git status$", flags: "g" }],
      },
    }),
    async (state) => {
      assert.match(
        state.configuredPolicyError?.message ?? "",
        /must not use stateful g\/y regex flags/i,
      );
    },
  );
});
