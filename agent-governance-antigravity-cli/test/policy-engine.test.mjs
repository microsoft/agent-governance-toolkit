// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

import assert from "node:assert/strict";
import { cp, mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";
import { PromptDefenseEvaluator } from "@microsoft/agent-governance-sdk";

import {
  buildDetectorOutcome,
  buildLegacyRules,
  checkArbitraryText,
  compilePolicy,
  evaluatePreToolUse,
  evaluateDirectResourceAccess,
  extractCommandText,
  formatPolicySummary,
  getOutputHandlingMode,
  loadPolicy,
} from "../assets/extensions/agt-global-policy/lib/policy.mjs";

const DEFAULT_POLICY_URL = new URL(
  "../assets/extensions/agt-global-policy/config/default-policy.json",
  import.meta.url,
);

async function withPackagedPolicyState(customizePolicy, callback) {
  const root = await mkdtemp(join(tmpdir(), "agt-antigravity-policy-"));
  const nodeModulesSource = fileURLToPath(new URL("../node_modules", import.meta.url));
  const nodeModulesTarget = join(root, "vendor", "agent-governance-sdk", "node_modules");
  await cp(nodeModulesSource, nodeModulesTarget, { recursive: true });

  const rawPolicy = JSON.parse(await readFile(DEFAULT_POLICY_URL, "utf8"));
  const policy = customizePolicy(rawPolicy);
  const policyPath = join(root, "policy.json");
  await writeFile(policyPath, `${JSON.stringify(policy, null, 2)}\n`, "utf8");

  try {
    const state = await loadPolicy({
      defaultPolicyPath: DEFAULT_POLICY_URL,
      extensionRoot: root,
      homeDirectory: root,
      policyPath,
      env: {
        AGT_ANTIGRAVITY_AUDIT_PATH: join(root, "audit.json"),
      },
    });
    return await callback(state);
  } finally {
    await rm(root, { recursive: true, force: true });
  }
}

test("default packaged policy keeps the hardened Antigravity developer-protection baseline", async () => {
  const rawPolicy = JSON.parse(
    await readFile(
      new URL("../assets/extensions/agt-global-policy/config/default-policy.json", import.meta.url),
      "utf8",
    ),
  );

  assert.equal(rawPolicy.minimumPromptDefenseGrade, "B");
  assert.equal(rawPolicy.toolPolicies.defaultEffect, "review");
  assert.ok(rawPolicy.toolPolicies.allowedTools.includes("read_file"));
  assert.ok(rawPolicy.outputPolicies.advisoryTools.includes("run_shell_command"));
  assert.ok(rawPolicy.outputPolicies.suppressTools.includes("web_fetch"));
  assert.ok(rawPolicy.scanOutputTools.includes("run_shell_command"));
  assert.ok(rawPolicy.scanOutputTools.includes("google_web_search"));
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
      advisoryTools: ["run_shell_command"],
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
      allowedTools: ["read_file"],
      defaultEffect: "review",
      reviewTools: ["run_shell_command"],
    },
  });

  assert.equal(policy.schemaVersion, 1);
  assert.equal(policy.poisoningPatterns[0].id, "custom-poisoning-1");
  assert.equal(policy.poisoningPatterns[0].detector, "regex");
  assert.ok(policy.scanOutputTools.has("web_fetch"));
  assert.ok(policy.scanOutputTools.has("run_shell_command"));
  assert.equal(policy.toolPolicies.defaultEffect, "review");
  assert.deepEqual(policy.toolPolicies.allowedTools, ["read_file"]);
  assert.equal(policy.directResourcePolicies.pathRules[0].operation, "read");
  assert.equal(getOutputHandlingMode(policy, "run_shell_command"), "advisory");
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
        allowedTools: ["read_file"],
        blockedTools: [],
        defaultEffect: "review",
        reviewTools: ["run_shell_command"],
      },
    }),
  );

  assert.ok(
    rules.some((rule) => rule.action === "tool.run_shell_command" && rule.effect === "review"),
  );
  assert.ok(rules.some((rule) => rule.action === "tool.read_file" && rule.effect === "allow"));
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
    auditPath: join(tmpdir(), "agt-antigravity-policy-engine-audit.json"),
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

  const result = checkArbitraryText(state, "Summarize the Antigravity governance files.");
  assert.equal(result.promptPoisoning.suspicious, false);
});

test("extractCommandText prefers command fields from Antigravity shell invocations", () => {
  assert.equal(
    extractCommandText({ command: "git status", dir_path: "C:\\repo" }),
    "git status",
  );
});

test("evaluatePreToolUse denies review-only tools because Antigravity hooks cannot pause for approval", async () => {
  const state = {
    auditLogger: {
      length: 0,
      log() {
        this.length += 1;
      },
      exportJSON() {
        return "[]";
      },
      verify() {
        return true;
      },
    },
    auditPath: join(tmpdir(), "agt-antigravity-policy-engine-review-audit.json"),
    bundledDefaultError: undefined,
    configuredPolicyError: undefined,
    policy: compilePolicy({
      blockedToolCalls: [],
      poisoningPatterns: [],
      scanOutputTools: [],
      toolPolicies: {
        allowedTools: [],
        blockedTools: [],
        defaultEffect: "review",
        reviewTools: [],
      },
    }),
    policyEngine: {
      async evaluateWithBackends() {
        return {
          backendResults: [{ backend: "test", decision: "review", reason: "needs approval" }],
          effectiveDecision: "review",
        };
      },
    },
  };

  const result = await evaluatePreToolUse(
    state,
    {
      toolArgs: { command: "git push" },
      toolName: "run_shell_command",
    },
    { sessionId: "session-1" },
  );

  assert.equal(result.permissionDecision, "deny");
  assert.match(result.permissionDecisionReason, /cannot pause for manual approval/i);
});

test("evaluatePreToolUse denies recursive force deletes", async () => {
  await withPackagedPolicyState(
    (policy) => ({
      ...policy,
      mode: "enforce",
      toolPolicies: {
        ...policy.toolPolicies,
        allowedTools: ["run_shell_command"],
        defaultEffect: "allow",
        reviewTools: [],
      },
    }),
    async (state) => {
      for (const command of [
        "rm -r -f important-data",
        "rm -rf important-data",
        "rm -fr important-data",
        "rm -rfv important-data",
        "rm -rvf important-data",
        "rm --recursive --force important-data",
        "rm --force --recursive important-data",
        "rm important-data -rf",
        "rm -rf /",
        "rm -rf ~/.ssh",
        "npm test && rm -rf important-data",
        "rm -r -fo important-data",
        "Remove-Item -Recurse -Force important-data",
        "Remove-Item -r -fo important-data",
        "ri -r -fo important-data",
        "rd /s /q important-data",
      ]) {
        const result = await evaluatePreToolUse(state, {
          toolArgs: { command },
          toolName: "run_shell_command",
        });

        assert.equal(result?.permissionDecision, "deny", command);
      }
    },
  );
});

test("evaluatePreToolUse does not deny safe cleanup or non-recursive force deletes", async () => {
  await withPackagedPolicyState(
    (policy) => ({
      ...policy,
      mode: "enforce",
      toolPolicies: {
        ...policy.toolPolicies,
        allowedTools: ["run_shell_command"],
        defaultEffect: "allow",
        reviewTools: [],
      },
    }),
    async (state) => {
      for (const command of [
        "rm -rf node_modules",
        "rm -rfv node_modules",
        "rm -rf build",
        "rm -fr dist",
        "rm -f important-data",
        "rm --force important-data",
        "rm --recursive important-data",
        "rm important-data -Confirm",
        "Remove-Item -Filter *.tmp important-data",
        "Remove-Item important-data -Confirm",
        "Remove-Item -Recurse -Force build",
        "rd /s /q node_modules",
      ]) {
        const result = await evaluatePreToolUse(state, {
          toolArgs: { command },
          toolName: "run_shell_command",
        });

        assert.notEqual(result?.permissionDecision, "deny", command);
      }
    },
  );
});

test("evaluateDirectResourceAccess blocks metadata and secret-path reads", () => {
  const policy = compilePolicy(
    JSON.parse(`{
      "blockedToolCalls": [],
      "directResourcePolicies": {
        "pathRules": [
          {
            "id": "credential-read-paths",
            "operation": "read",
            "effect": "deny",
            "pathPatterns": [{ "source": "\\\\.env$", "flags": "i" }],
            "allowPathPatterns": []
          }
        ],
        "urlRules": [
          {
            "id": "metadata-endpoints",
            "effect": "deny",
            "urlPatterns": [{ "source": "169\\\\.254\\\\.169\\\\.254", "flags": "i" }]
          }
        ]
      },
      "poisoningPatterns": [],
      "scanOutputTools": []
    }`),
  );

  assert.equal(
    evaluateDirectResourceAccess(policy, {
      actionType: "tool",
      rawToolArgs: { file_path: "C:\\repo\\.env" },
      toolName: "read_file",
    })?.effect,
    "deny",
  );
  assert.equal(
    evaluateDirectResourceAccess(policy, {
      actionType: "tool",
      rawToolArgs: { url: "http://169.254.169.254/latest/meta-data/" },
      toolName: "web_fetch",
    })?.effect,
    "deny",
  );
});

test("formatPolicySummary reports Antigravity runtime context", () => {
  const summary = formatPolicySummary({
    auditLogger: { length: 1, verify() { return true; } },
    auditPath: "C:\\audit-log.json",
    bundledDefaultError: undefined,
    configuredPolicyError: undefined,
    configuredPolicyPath: "C:\\policy.json",
    path: "C:\\policy.json",
    policy: compilePolicy({ blockedToolCalls: [], poisoningPatterns: [], scanOutputTools: [] }),
    promptDefenseReport: {
      coverage: "good",
      grade: "A",
      isBlocking() {
        return false;
      },
      missing: [],
    },
    sdkPath: "C:\\sdk.js",
    sdkSource: "vendored",
    source: "user",
  });

  assert.match(summary, /AGT global policy/);
  assert.match(summary, /SDK: vendored/);
});
