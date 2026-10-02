// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

import assert from "node:assert/strict";
import { cp, mkdir, mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";
import { isSafeShellCleanupCommand, matchesRecursiveDeleteCommand } from "../assets/extensions/agt-global-policy/lib/recursive-delete.mjs";
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
  loadPolicy,
  evaluatePreToolUse,
} from "../assets/extensions/agt-global-policy/lib/policy.mjs";

// Cases and expected behavior supplied by the contributor; encoded with AI assistance.
const CONTRIBUTOR_DELETE_COMMANDS = [
  'rm --recursive "$(pwd)/src" -f',
  'echo "$(rm -r "$(pwd)/src" -f)"',
];
const CONTRIBUTOR_TEXT_COMMANDS = [
  'echo rm "-r" "-f" src',
  'echo "rm --recursive --force src"',
];

// Review regression inputs specify shell behavior independently of the parser.
const SUBSTITUTION_DELETE_COMMANDS = [
  ...CONTRIBUTOR_DELETE_COMMANDS,
  "rm -r \"$(pwd)/src\" -f",
  "rm -r x$(pwd) -f",
  "rm \"$(pwd)/src\" -rf",
  "rm -r \"`pwd`/src\" -f",
  "rm -r x`pwd` -f",
  "rm \"`pwd`/src\" -rf",
  "rm -r \"$(echo \"$(pwd)\")/src\" -f",
  "sudo rm -r \"$(pwd)/src\" -f",
  "rm -r <(pwd) -f",
  "rm -r >(pwd) -f",
  "rm -r >\"$(pwd)/log\" -f src",
  "rm -r >$(pwd)/log -f src",
  "rm -rf \"$(pwd)/node_modules\"",
  "echo `rm -r \"$(pwd)/src\" -f`",
  "echo \"$(echo ready; rm -rf src)\"",
  "echo \"$(rm -rf src)\"",
  "rm -rf $(pwd",
  "rm -rf \"$(pwd",
  "rm -rf `pwd",
  "rm -r \"$(pwd)/src\" -f; echo done",
  "rm -r \"$(pwd)$(pwd)/src\" -f"
];
const SUBSTITUTION_TEXT_COMMANDS = [
  ...CONTRIBUTOR_TEXT_COMMANDS,
  "echo $(pwd) rm -rf src",
  "echo `pwd` rm -rf src",
  "echo \"$(pwd)\" rm -rf src",
  "echo \"$(echo \"$(pwd)\")\" rm -rf src",
  "echo x$(pwd) rm -rf src",
  "echo <(pwd) rm -rf src",
  "echo >(pwd) rm -rf src",
  "echo >$(pwd)/log rm -rf src",
  "echo \"$(pwd)rm -rf src\"",
  "echo \"$(pwd)$(pwd)\" rm -rf src",
  "rm -r$(pwd) -f src",
  "rm -r \"$(pwd)-f\" src",
  "$(pwd)rm -rf src",
  "\"$(pwd)/rm\" -rf src",
  "echo '$(rm -rf src)'",
  "echo \"$(pwd # ignored rm -rf src\n)\" rm -rf src"
];

// cspell:ignore uroot ualice Huroot
const RECURSIVE_DELETE_DENY_COMMANDS = [
  ...SUBSTITUTION_DELETE_COMMANDS,
  "rm -rf src",
  "rm -fr src",
  "rm -r -f src",
  "rm -f -r src",
  "rm -rfv src",
  "rm -rvf src",
  "rm -vrf src",
  "rm -R -f src",
  "rm --recursive --force src",
  "rm --force --recursive src",
  "rm --recursive -f src",
  "rm -r --force src",
  "rm --rec --fo src",
  "rm \"-rf\" src",
  "rm '-rf' src",
  "rm -r'f' src",
  "rm -r\\f src",
  "r\\m -rf src",
  "/bin/rm -rf src",
  "sudo -u root rm -rf src",
  "env FOO=1 rm -rf src",
  "command rm -rf src",
  "timeout 5 rm -rf src",
  "cd x && rm -rf src",
  "echo ready; rm -rf src",
  "false || rm -rf src",
  "echo \"$(rm -rf src)\"",
  "echo \"$(echo \"$(rm -rf src)\")\"",
  "# don't delete\nrm -rf src",
  "rm -rf node_modules src",
  "rm -rf node_modules src/*",
  "rm -rf node_modules src/**",
  "rm -rf node_modules src/?",
  "rm -rf node_modules src/[ab]",
  "rm -rf node_modules \"$TARGET\"",
  "rm -rf \"$TARGET/node_modules\"",
  "rm -rf node_modules,dist",
  "rm -rf node_modules ../src",
  "rm -rf /tmp/node_modules",
  "rm -rf node_modules 2>/dev/null",
  "rm -rf node_modules && rm -rf src",
  "rm -rf -- src",
  "rm -rf --bogus node_modules",
  "rm -rf 'node_modules",
  "rm -rf node_modules \"\"",
  "rm -rf node_modules \"$(pwd)/node_modules\"",
  "rm > -- -rf src",
  "> /tmp/log rm -rf src",
  "2>/tmp/log rm -rf src",
  "rm -r '>' -f src",
  "rm -r \\> -f src",
  "rm -rf node_modules > dist",
  "rm -rf node_modules 2>&1",
  "rm -rf node_modules &>/tmp/log",
  "command -- rm -rf src",
  "echo >$(rm -rf src)",
  "echo >\"$(echo \"$(rm -rf src)\")\"",
  "cat <(rm -rf src)",
  "# don't run it\nrm -rf src",
  "rm -rf node_modules # quote ' doesn't swallow the next line\nrm -rf src",
  "sudo -uroot rm -rf src",
  "sudo -ualice rm -rf src",
  "sudo -Huroot rm -rf src",
  "sudo --user=alice rm -rf src",
  "sudo -D/tmp rm -rf src",
  "2>log rm -rf src"
];
const RECURSIVE_DELETE_SAFE_COMMANDS = [
  ...SUBSTITUTION_TEXT_COMMANDS,
  "echo hello",
  "rm -f file",
  "rm -r src",
  "rm --recursive src",
  "rm -- -rf src",
  "rm '--' -rf src",
  "rm -rf node_modules",
  "rm -fr ./dist",
  "rm -r -f packages/app/node_modules",
  "rm --recursive --force node_modules dist",
  "rm -rf -- node_modules",
  "rm -rf node_modules # safe cleanup",
  "git rm -rf --cached src",
  "echo \"rm -rf src\"",
  "printf '%s\\n' 'rm -rf src'",
  "# rm -rf src",
  "rm -f file; echo -rf",
  "echo rm; echo -rf",
  "grep -rf patterns src",
  "ls -rf src",
  "rm report-rf",
  "echo rm-rf",
  "echo \"rm x-rf\"",
  "rm -r > -f src",
  "rm -f > -r src",
  "rm > '-rf' -r src",
  "rm > --recursive -f src",
  "rm --recursive > --force src",
  "command -v rm -rf src",
  "command -V rm -rf src",
  "command -pv rm -rf src",
  "env --help rm -rf src",
  "env --version rm -rf src",
  "busybox --list rm -rf src",
  "sudo -l rm -rf src",
  "sudo --list rm -rf src",
  "nohup --help rm -rf src",
  "rm\u00a0-rf src",
  "rm\u2003-rf src",
  "echo '$(rm -rf src)'",
  "echo '# rm -rf src'",
  "'2'>log rm -rf src",
  "\"2\">log rm -rf src",
  "\\2>log rm -rf src"
];

test("all bundled Bash policies parse recursive deletion with the real SDK", async (t) => {
  const root = await mkdtemp(join(tmpdir(), "agt-copilot-recursive-delete-"));
  t.after(() => rm(root, { recursive: true, force: true }));
  const extensionRoot = join(root, "extension");
  const vendorRoot = join(extensionRoot, "vendor", "agent-governance-sdk");
  await mkdir(vendorRoot, { recursive: true });
  await cp(new URL("../node_modules", import.meta.url), join(vendorRoot, "node_modules"), { recursive: true });
  const previousAuditPath = process.env.AGT_COPILOT_AUDIT_PATH;
  process.env.AGT_COPILOT_AUDIT_PATH = join(root, "audit.json");
  t.after(() => {
    if (previousAuditPath === undefined) delete process.env.AGT_COPILOT_AUDIT_PATH;
    else process.env.AGT_COPILOT_AUDIT_PATH = previousAuditPath;
  });
  for (const profile of ["default-policy.json", "profiles/advisory.json", "profiles/balanced.json", "profiles/strict.json"]) {
    await t.test(profile, async () => {
      const state = await loadPolicy({
        defaultPolicyPath: new URL("../assets/extensions/agt-global-policy/config/" + profile, import.meta.url),
        extensionRoot, policyPath: join(root, "no-user-policy.json"), homeDirectory: root,
      });
      assert.equal(state.sdkSource, "vendored");
      for (const command of RECURSIVE_DELETE_DENY_COMMANDS) {
        const result = await evaluatePreToolUse(state, { toolName: "bash", toolArgs: { command } }, { sessionId: "recursive-delete" });
        assert.equal(result?.permissionDecision, "deny", command);
        assert.match(result.permissionDecisionReason, /Recursive delete commands/, command);
      }
      for (const command of RECURSIVE_DELETE_SAFE_COMMANDS) {
        const result = await evaluatePreToolUse(state, { toolName: "bash", toolArgs: { command } }, { sessionId: "recursive-delete" });
        assert.equal(result?.permissionDecision, "ask", command);
        assert.doesNotMatch(result.permissionDecisionReason, /Recursive delete commands/, command);
      }
      const policy = JSON.parse(await readFile(new URL("../assets/extensions/agt-global-policy/config/" + profile, import.meta.url), "utf8"));
      policy.toolPolicies.reviewTools = [];
      policy.toolPolicies.defaultEffect = "allow";
      const policyPath = join(root, profile.replaceAll("/", "-") + "-allow.json");
      await writeFile(policyPath, JSON.stringify(policy));
      const allowState = await loadPolicy({ extensionRoot, policyPath, homeDirectory: root });
      for (const command of SUBSTITUTION_DELETE_COMMANDS) {
        const result = await evaluatePreToolUse(allowState, { toolName: "bash", toolArgs: { command } });
        assert.equal(result?.permissionDecision, "deny", command);
        assert.match(result.permissionDecisionReason, /Recursive delete commands/, command);
      }
      for (const command of SUBSTITUTION_TEXT_COMMANDS) {
        const result = await evaluatePreToolUse(allowState, { toolName: "bash", toolArgs: { command } });
        assert.equal(result?.permissionDecision, undefined, command);
      }
    });
  }
  await t.test("allow fallback and user patterns", async () => {
    const policy = JSON.parse(await readFile(new URL("../assets/extensions/agt-global-policy/config/default-policy.json", import.meta.url), "utf8"));
    policy.toolPolicies.reviewTools = [];
    policy.toolPolicies.defaultEffect = "allow";
    const rule = policy.blockedToolCalls.find((entry) => entry.id === "recursive-delete" && entry.tool === "bash");
    rule.commandPatterns = [{ source: "\\brimraf\\b", flags: "i" }];
    const policyPath = join(root, "custom-policy.json");
    await writeFile(policyPath, JSON.stringify(policy));
    const state = await loadPolicy({
      defaultPolicyPath: new URL("../assets/extensions/agt-global-policy/config/default-policy.json", import.meta.url),
      extensionRoot, policyPath, homeDirectory: root,
    });
    for (const command of [...SUBSTITUTION_DELETE_COMMANDS, "rm -rf src", "rm -rf node_modules src/*", "npx rimraf src"]) {
      const result = await evaluatePreToolUse(state, { toolName: "bash", toolArgs: { command } });
      assert.equal(result?.permissionDecision, "deny", command);
      assert.match(result.permissionDecisionReason, /Recursive delete commands/, command);
    }
    for (const command of [...SUBSTITUTION_TEXT_COMMANDS, 'echo "rm -rf src"', "rm -rf node_modules"]) {
      const result = await evaluatePreToolUse(state, { toolName: "bash", toolArgs: { command } });
      assert.equal(result?.permissionDecision, undefined, command);
    }
    const start = performance.now();
    const command = Array.from({ length: 1000 }, (_, index) => "echo command-" + index).join("\n");
    const result = await evaluatePreToolUse(state, { toolName: "bash", toolArgs: { command } });
    assert.equal(result?.permissionDecision, undefined);
    assert.ok(performance.now() - start < 2000, "1000-command script must not backtrack");
  });
});


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
      toolName: "web_fetch",
      cwd: "C:\\repo",
      rawToolArgs: { link: "http://169.254.169.254/latest/meta-data/" },
    })?.effect,
    "deny",
  );

  assert.equal(
    evaluateDirectResourceAccess(policy, {
      toolName: "web_fetch",
      cwd: "C:\\repo",
      rawToolArgs: { target: "http://169.254.169.254/latest/meta-data/" },
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

test("recursive-delete stays bounded on deeply nested malformed comments", () => {
  const command = "$(".repeat(50000) + "# comment\n".repeat(50000);
  const start = performance.now();
  assert.equal(matchesRecursiveDeleteCommand(command), false);
  assert.equal(isSafeShellCleanupCommand(command), false);
  assert.ok(performance.now() - start < 2000, "nested comment scanning must stay bounded");
});

test("substitutions preserve outer invocations and scan inner commands", () => {
  const failures = [];
  for (const [commands, expected] of [[SUBSTITUTION_DELETE_COMMANDS, true], [SUBSTITUTION_TEXT_COMMANDS, false]]) {
    for (const command of commands) {
      const actual = matchesRecursiveDeleteCommand(command);
      if (actual !== expected) failures.push({ command, expected, actual });
      assert.equal(isSafeShellCleanupCommand(command), false, command);
    }
  }
  assert.deepEqual(failures, []);
});

test("deeply nested substitutions restore state without repeated stack copies", () => {
  const nested = "$(".repeat(20000) + "pwd" + ")".repeat(20000);
  const start = performance.now();
  assert.equal(matchesRecursiveDeleteCommand("echo " + nested + " rm -rf src"), false);
  assert.equal(matchesRecursiveDeleteCommand("rm -r " + nested + "/src -f"), true);
  assert.equal(matchesRecursiveDeleteCommand("echo " + "$(".repeat(20000) + "rm -rf src" + ")".repeat(20000)), true);
  assert.ok(performance.now() - start < 2000, "substitution restoration must stay bounded");
});

test("contributor cases detect recursive deletion across substitutions", () => {
  for (const command of CONTRIBUTOR_DELETE_COMMANDS) {
    assert.equal(matchesRecursiveDeleteCommand(command), true, command);
    assert.equal(isSafeShellCleanupCommand(command), false, command);
  }
});

test("contributor cases leave quoted echo arguments unmatched", () => {
  for (const command of CONTRIBUTOR_TEXT_COMMANDS) {
    assert.equal(matchesRecursiveDeleteCommand(command), false, command);
  }
});
