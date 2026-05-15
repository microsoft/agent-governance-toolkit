// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";
import { PromptDefenseEvaluator } from "@microsoft/agent-governance-sdk";

import {
  buildDetectorOutcome,
  buildLegacyRules,
  checkArbitraryText,
  compilePolicy,
  evaluateDirectResourceAccess,
  extractCommandText,
  formatPolicySummary,
  getOutputHandlingMode,
} from "../assets/extensions/agt-global-policy/lib/policy.mjs";

test("default packaged policy keeps the hardened developer-protection baseline", async () => {
  const rawPolicy = JSON.parse(
    await readFile(
      new URL("../assets/extensions/agt-global-policy/config/default-policy.json", import.meta.url),
      "utf8",
    ),
  );

  assert.equal(rawPolicy.minimumPromptDefenseGrade, "B");
  assert.equal(rawPolicy.toolPolicies.defaultEffect, "review");
  assert.ok(rawPolicy.toolPolicies.allowedTools.includes("view"));
  assert.ok(rawPolicy.outputPolicies.advisoryTools.includes("bash"));
  assert.ok(rawPolicy.outputPolicies.suppressTools.includes("web_fetch"));
  assert.ok(rawPolicy.scanOutputTools.includes("powershell"));
  assert.ok(rawPolicy.scanOutputTools.includes("read_powershell"));
  assert.ok(rawPolicy.scanOutputTools.includes("list_powershell"));
  assert.ok(
    rawPolicy.directResourcePolicies.urlRules.some((rule) => rule.id === "metadata-endpoints"),
  );
  assert.ok(
    rawPolicy.poisoningPatterns.some((pattern) => pattern.reason === "Persistence establishment cue."),
  );
});

test("default runtime guard context meets the configured prompt defense floor", async () => {
  const evaluator = new PromptDefenseEvaluator();
  const rawPolicy = JSON.parse(
    await readFile(
      new URL("../assets/extensions/agt-global-policy/config/default-policy.json", import.meta.url),
      "utf8",
    ),
  );
  const compiledPolicy = compilePolicy(rawPolicy);
  const report = evaluator.evaluate(compiledPolicy.additionalContext.join("\n"));

  assert.equal(report.isBlocking(compiledPolicy.minimumPromptDefenseGrade), false);
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
  assert.equal(policy.poisoningPatterns[0].detector, "regex");
  assert.ok(policy.scanOutputTools.has("web_fetch"));
  assert.ok(policy.scanOutputTools.has("powershell"));
  assert.equal(policy.toolPolicies.defaultEffect, "review");
  assert.deepEqual(policy.toolPolicies.allowedTools, ["view"]);
  assert.equal(policy.directResourcePolicies.pathRules[0].operation, "read");
  assert.equal(getOutputHandlingMode(policy, "powershell"), "advisory");
  assert.equal(getOutputHandlingMode(policy, "web_fetch"), "suppress");
});

test("compilePolicy rejects unsupported schema versions", () => {
  assert.throws(() => compilePolicy({ schemaVersion: 99 }), /Unsupported policy schemaVersion 99/);
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

  assert.ok(rules.some((rule) => rule.action === "tool.powershell" && rule.effect === "review"));
  assert.ok(rules.some((rule) => rule.action === "tool.view" && rule.effect === "allow"));
  assert.ok(rules.some((rule) => rule.action === "tool.*" && rule.effect === "review"));
  assert.ok(rules.some((rule) => rule.action === "prompt.*" && rule.effect === "allow"));
  assert.ok(rules.some((rule) => rule.action === "tool_output.*" && rule.effect === "allow"));
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

test("formatPolicySummary groups the status output into readable sections", () => {
  const summary = formatPolicySummary({
    auditLogger: {
      length: 0,
      verify() {
        return true;
      },
    },
    auditPath: "C:\\audit-log.json",
    bundledDefaultError: undefined,
    configuredPolicyError: undefined,
    path: "C:\\policy.json",
    policy: compilePolicy({
      blockedToolCalls: [],
      outputPolicies: {
        advisoryTools: ["bash"],
      },
      poisoningPatterns: [],
      scanOutputTools: ["bash"],
      schemaVersion: 1,
      toolPolicies: {
        allowedTools: ["view"],
      },
    }),
    promptDefenseReport: {
      coverage: "10/12",
      grade: "B",
      isBlocking() {
        return false;
      },
      missing: ["unicode-attack", "social-engineering"],
    },
    sdkPath: "C:\\sdk.js",
    sdkSource: "vendored",
    source: "user",
  });

  assert.match(summary, /Runtime/);
  assert.match(summary, /Prompt defense/);
  assert.match(summary, /- Verdict: passing/);
  assert.match(summary, /- Missing vectors: unicode-attack, social-engineering/);
});

test("evaluateDirectResourceAccess denies secret reads, allows env templates, reviews persistence writes, and blocks metadata URLs", () => {
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
      urlRules: [
        {
          effect: "deny",
          reason: "Metadata denied.",
          urlPatterns: [
            { source: "^https?://169\\.254\\.169\\.254(?:/|$)", flags: "i" },
          ],
        },
      ],
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

  assert.equal(
    evaluateDirectResourceAccess(policy, {
      toolName: "web_fetch",
      cwd: "C:\\repo",
      rawToolArgs: { url: "http://169.254.169.254/latest/meta-data/" },
    })?.effect,
    "deny",
  );

  assert.equal(
    evaluateDirectResourceAccess(policy, {
      toolName: "powershell",
      commandText: "Get-Content '.env'",
      cwd: "C:\\repo",
      rawToolArgs: {},
    })?.effect,
    "deny",
  );

  assert.equal(
    evaluateDirectResourceAccess(policy, {
      toolName: "powershell",
      commandText: "curl http://169.254.169.254/latest/meta-data/",
      cwd: "C:\\repo",
      rawToolArgs: {},
    })?.effect,
    "deny",
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
