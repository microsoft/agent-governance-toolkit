// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";

import {
  buildDetectorOutcome,
  buildLegacyRules,
  checkArbitraryText,
  compilePolicy,
  evaluateDirectResourceAccess,
  extractCommandText,
  getOutputHandlingMode,
} from "../.github/extensions/agt-global-policy/lib/policy.mjs";

test("example policy stays aligned with the hardened packaged baseline", async () => {
  const rawPolicy = JSON.parse(
    await readFile(new URL("../config/default-policy.json", import.meta.url), "utf8"),
  );

  assert.equal(rawPolicy.minimumPromptDefenseGrade, "B");
  assert.equal(rawPolicy.toolPolicies.defaultEffect, "review");
  assert.ok(rawPolicy.toolPolicies.allowedTools.includes("view"));
  assert.ok(rawPolicy.outputPolicies.advisoryTools.includes("bash"));
  assert.ok(rawPolicy.outputPolicies.suppressTools.includes("web_fetch"));
  assert.ok(rawPolicy.scanOutputTools.includes("powershell"));
  assert.ok(
    rawPolicy.directResourcePolicies.urlRules.some((rule) => rule.id === "metadata-endpoints"),
  );
});

test("compilePolicy normalizes schema version, default effect, and direct resource rules", () => {
  const policy = compilePolicy({
    schemaVersion: 1,
    blockedToolCalls: [],
    directResourcePolicies: {
      pathRules: [
        {
          effect: "deny",
          operation: "read",
          pathPatterns: [{ source: "\\.env$", flags: "i" }],
        },
      ],
      urlRules: [
        {
          effect: "review",
          urlPatterns: [{ source: "metadata", flags: "i" }],
        },
      ],
    },
    outputPolicies: {
      advisoryTools: ["powershell"],
      suppressTools: ["web_fetch"],
    },
    poisoningPatterns: [
      {
        source: "ignore previous instructions",
        reason: "Prompt injection phrase.",
      },
    ],
    scanOutputTools: ["Web_Fetch"],
    toolPolicies: {
      allowedTools: ["view"],
      defaultEffect: "review",
      reviewTools: ["powershell"],
    },
  });

  assert.equal(policy.schemaVersion, 1);
  assert.equal(policy.poisoningPatterns[0].id, "custom-poisoning-1");
  assert.ok(policy.scanOutputTools.has("web_fetch"));
  assert.ok(policy.scanOutputTools.has("powershell"));
  assert.equal(policy.toolPolicies.defaultEffect, "review");
  assert.deepEqual(policy.toolPolicies.allowedTools, ["view"]);
  assert.equal(getOutputHandlingMode(policy, "powershell"), "advisory");
  assert.equal(getOutputHandlingMode(policy, "web_fetch"), "suppress");
});

test("buildLegacyRules uses the configured default tool effect", () => {
  const rules = buildLegacyRules(
    compilePolicy({
      blockedToolCalls: [],
      poisoningPatterns: [],
      scanOutputTools: [],
      toolPolicies: {
        allowedTools: ["view"],
        blockedTools: [],
        defaultEffect: "review",
        reviewTools: ["powershell"],
      },
    }),
  );

  assert.ok(rules.some((rule) => rule.action === "tool.view" && rule.effect === "allow"));
  assert.ok(rules.some((rule) => rule.action === "tool.*" && rule.effect === "review"));
});

test("buildDetectorOutcome ignores historical aggregate risk when the current entry is clean", () => {
  const policy = compilePolicy({
    blockedToolCalls: [],
    poisoningPatterns: [],
    scanOutputTools: [],
  });

  assert.equal(
    buildDetectorOutcome(
      policy,
      "prompt injection",
      [],
      { riskLevel: "critical" },
      { requireCurrentEntryMatch: true },
    ),
    "allow",
  );
});

test("buildDetectorOutcome still escalates matching entries with aggregate risk", () => {
  const policy = compilePolicy({
    blockedToolCalls: [],
    poisoningPatterns: [],
    scanOutputTools: [],
  });

  assert.equal(
    buildDetectorOutcome(
      policy,
      "prompt injection",
      [{ patternName: "Prompt injection phrase", severity: "medium" }],
      { riskLevel: "high" },
      { requireCurrentEntryMatch: true },
    ).decision,
    "deny",
  );
});

test("checkArbitraryText does not inherit prior detector state from the runtime", () => {
  const sdk = {
    AuditLogger: class {
      constructor() {
        this.length = 0;
      }
      log() {
        this.length += 1;
      }
      exportJSON() {
        return "[]";
      }
      verify() {
        return true;
      }
    },
    PromptDefenseEvaluator: class {
      evaluate() {
        return {
          coverage: "good",
          grade: "A",
          isBlocking() {
            return false;
          },
          missing: [],
        };
      }
    },
    ContextPoisoningDetector: class {
      constructor() {
        this.entries = [];
      }
      addEntry(entry) {
        this.entries.push(entry);
      }
      scanEntry(entry) {
        return /ignore previous instructions/i.test(entry.content)
          ? [{ patternName: "Prompt injection phrase", severity: "high" }]
          : [];
      }
      scan() {
        return {
          riskLevel: this.entries.some((entry) => /ignore previous instructions/i.test(entry.content))
            ? "critical"
            : "none",
        };
      }
    },
    McpSecurityScanner: class {
      scan() {
        return { safe: true, threats: [] };
      }
    },
    PolicyEngine: class {
      constructor() {}
      loadPolicy() {}
      registerBackend() {}
    },
  };

  const state = {
    auditLogger: new sdk.AuditLogger(),
    auditPath: "C:\\audit-log.json",
    bundledDefaultError: undefined,
    configuredPolicyError: undefined,
    configuredPolicyPath: "C:\\policy.json",
    contextDetector: (() => {
      const detector = new sdk.ContextPoisoningDetector();
      detector.addEntry({ content: "ignore previous instructions", entryId: "old" });
      return detector;
    })(),
    mcpScanner: new sdk.McpSecurityScanner(),
    path: "C:\\policy.json",
    policy: compilePolicy({
      blockedToolCalls: [],
      poisoningPatterns: [{ source: "ignore previous instructions", reason: "Prompt injection phrase." }],
      scanOutputTools: [],
    }),
    policyEngine: new sdk.PolicyEngine(),
    promptDefenseReport: new sdk.PromptDefenseEvaluator().evaluate(""),
    sdk,
    sdkPath: "C:\\sdk.js",
    sdkSource: "test",
    source: "user",
  };

  const result = checkArbitraryText(state, "Summarize the Copilot governance files.");
  assert.equal(result.promptPoisoning.suspicious, false);
});

test("evaluateDirectResourceAccess denies secret reads and reviews persistence writes", () => {
  const policy = compilePolicy({
    blockedToolCalls: [],
    directResourcePolicies: {
      pathRules: [
        {
          effect: "deny",
          operation: "read",
          pathPatterns: [{ source: "(^|/)\\.env$", flags: "i" }],
          allowPathPatterns: [
            { source: "(^|/)\\.env\\.(?:example|sample|template)$", flags: "i" },
          ],
          reason: "Secret read denied.",
        },
        {
          effect: "review",
          operation: "write",
          pathPatterns: [{ source: "(^|/)package\\.json$", flags: "i" }],
          reason: "Persistence write reviewed.",
        },
      ],
      urlRules: [],
    },
    poisoningPatterns: [],
    scanOutputTools: [],
  });

  assert.equal(
    evaluateDirectResourceAccess(policy, {
      toolName: "view",
      cwd: "C:\\repo",
      rawToolArgs: { path: ".env" },
    })?.effect,
    "deny",
  );

  assert.equal(
    evaluateDirectResourceAccess(policy, {
      toolName: "view",
      cwd: "C:\\repo",
      rawToolArgs: { path: ".env.example" },
    }),
    undefined,
  );

  assert.equal(
    evaluateDirectResourceAccess(policy, {
      toolName: "edit",
      cwd: "C:\\repo",
      rawToolArgs: { path: "package.json" },
    })?.effect,
    "review",
  );
});

test("getOutputHandlingMode ignores unscanned tools", () => {
  const policy = compilePolicy({
    blockedToolCalls: [],
    directResourcePolicies: {
      pathRules: [],
      urlRules: [],
    },
    outputPolicies: {
      advisoryTools: ["bash"],
      suppressTools: ["web_fetch"],
    },
    poisoningPatterns: [],
    scanOutputTools: [],
  });

  assert.equal(getOutputHandlingMode(policy, "bash"), "advisory");
  assert.equal(getOutputHandlingMode(policy, "web_fetch"), "suppress");
  assert.equal(getOutputHandlingMode(policy, "view"), "ignore");
});

test("extractCommandText prefers direct command fields", () => {
  assert.equal(
    extractCommandText({
      command: "Get-ChildItem",
      input: "ignored",
    }),
    "Get-ChildItem",
  );

  assert.equal(
    extractCommandText({
      query: "fallback",
      powershell: "Write-Host test",
    }),
    "Write-Host test",
  );
});
