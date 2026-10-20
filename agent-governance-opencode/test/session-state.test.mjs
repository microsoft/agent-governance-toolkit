// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

import assert from "node:assert/strict";
import { mkdtemp, readFile, rm, rmdir, unlink, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";

import {
  cleanupOpenCodeSessionState,
  evaluateOpenCodeTool,
  evaluateOpenCodeToolOutput,
  finalizeOpenCodeSessionState,
  getOpenCodeSessionState,
  getPolicyStatus,
  loadPolicy,
} from "../lib/opencode-policy.mjs";
import {
  appendAuditEntry,
  loadAuditEntries,
  loadAuditFile,
  verifyAuditEntries,
} from "../lib/audit.mjs";

const sessionStatePolicy = {
  maxPendingCallsPerSession: 8,
  maxSessions: 8,
  attributes: ["sensitive_data_read"],
  transitions: [
    {
      id: "sensitive-path-read",
      tool: "read",
      attribute: "sensitive_data_read",
      pathPatterns: [
        {
          source: "(^|/)(?:personal|private)(/|$)",
          flags: "i",
        },
      ],
    },
  ],
  rules: [
    {
      id: "deny-outbound-after-sensitive-read",
      tools: ["bash", "webfetch"],
      requires: ["sensitive_data_read"],
      effect: "deny",
      reason: "Outbound tools are blocked after a sensitive file read.",
    },
  ],
};

async function writePolicy(
  root,
  { sessionState = sessionStatePolicy, mode = "enforce", denyOnPolicyError } = {},
) {
  const policyPath = join(root, "policy.json");
  await writeFile(
    policyPath,
    JSON.stringify({
      schemaVersion: 1,
      mode,
      ...(denyOnPolicyError === undefined ? {} : { denyOnPolicyError }),
      toolPolicies: {
        allowedTools: ["read", "bash", "webfetch"],
        defaultEffect: "deny",
      },
      sessionState,
    }),
    "utf8",
  );
  return policyPath;
}

async function loadState(root, policyPath, auditPath = join(root, "audit.json")) {
  return loadPolicy({ policyPath, auditPath, homeDirectory: root });
}

function readInput(sessionId, callID = "read-call") {
  return {
    tool: "read",
    args: { filePath: "C:\\data\\personal\\profile.txt" },
    cwd: "C:\\data",
    sessionId,
    callID,
  };
}

function outboundInput(sessionId, callID = "outbound-call") {
  return {
    tool: "webfetch",
    args: { url: "https://example.com/upload" },
    sessionId,
    callID,
  };
}

test("staged reads block concurrent outbound tools and latch state monotonically", async (t) => {
  const root = await mkdtemp(join(tmpdir(), "agt-opencode-session-state-"));
  t.after(() => rm(root, { recursive: true, force: true }));
  const policyPath = await writePolicy(root);
  const state = await loadState(root, policyPath);

  const [readResult, outboundResult] = await Promise.all([
    evaluateOpenCodeTool(state, readInput("session-a")),
    evaluateOpenCodeTool(state, outboundInput("session-a")),
  ]);

  assert.equal(readResult.effect, "allow");
  assert.equal(outboundResult.effect, "deny");
  assert.match(outboundResult.reason, /sensitive file read/i);
  assert.deepEqual(getOpenCodeSessionState(state, "session-a"), {
    attributes: [],
    pendingAttributes: ["sensitive_data_read"],
    quarantined: false,
  });

  const separateSession = await evaluateOpenCodeTool(state, outboundInput("session-b"));
  assert.equal(separateSession.effect, "allow");

  await evaluateOpenCodeToolOutput(state, {
    tool: "read",
    output: "profile contents",
    sessionId: "session-a",
    callID: "read-call",
  });
  assert.deepEqual(getOpenCodeSessionState(state, "session-a"), {
    attributes: ["sensitive_data_read"],
    pendingAttributes: [],
    quarantined: false,
  });

  const laterOutbound = await evaluateOpenCodeTool(state, outboundInput("session-a", "later-send"));
  assert.equal(laterOutbound.effect, "deny");

  const entries = await loadAuditEntries(state.auditPath);
  assert.equal(verifyAuditEntries(entries), true);
  assert.ok(
    entries.some(
      (entry) =>
        entry.agentId === "opencode:session-a" &&
        entry.action === "session.state.pending:sensitive_data_read",
    ),
  );
  assert.ok(
    entries.some(
      (entry) =>
        entry.agentId === "opencode:session-a" &&
        entry.action === "session.state.set:sensitive_data_read",
    ),
  );

  const status = await getPolicyStatus(state);
  assert.equal(status.sessionState.enabled, true);
  assert.equal(status.sessionState.configured, true);
  assert.equal(status.sessionState.trackedSessions, 1);
  assert.equal(status.sessionState.maxPendingAttributesPerSession, 256);
});

test("the reference policy allows outbound access only before a sensitive read", async (t) => {
  const root = await mkdtemp(join(tmpdir(), "agt-opencode-session-example-"));
  t.after(() => rm(root, { recursive: true, force: true }));
  const policyPath = join(root, "policy.json");
  const example = await readFile(
    new URL("../config/session-state-policy.example.json", import.meta.url),
    "utf8",
  );
  await writeFile(policyPath, example, "utf8");
  const state = await loadState(root, policyPath);

  assert.equal((await evaluateOpenCodeTool(state, outboundInput("example-session"))).effect, "allow");
  assert.equal((await evaluateOpenCodeTool(state, readInput("example-session"))).effect, "allow");
  assert.equal(
    (await evaluateOpenCodeTool(state, outboundInput("example-session", "after-read"))).effect,
    "deny",
  );
});

test("transitions are scoped to matching paths and do not create empty session records", async (t) => {
  const root = await mkdtemp(join(tmpdir(), "agt-opencode-session-path-scope-"));
  t.after(() => rm(root, { recursive: true, force: true }));
  const policyPath = await writePolicy(root);
  const state = await loadState(root, policyPath);

  assert.equal(
    (await evaluateOpenCodeTool(state, {
      ...readInput("public-session"),
      args: { filePath: "C:\\data\\public\\readme.txt" },
      callID: "public-read-call",
    })).effect,
    "allow",
  );
  assert.equal((await evaluateOpenCodeTool(state, outboundInput("public-session"))).effect, "allow");
  assert.equal((await getPolicyStatus(state)).sessionState.trackedSessions, 0);
});

test("transition argument keys can target an OpenCode-specific path field", async (t) => {
  const root = await mkdtemp(join(tmpdir(), "agt-opencode-session-argument-keys-"));
  t.after(() => rm(root, { recursive: true, force: true }));
  const policyPath = await writePolicy(root, {
    sessionState: {
      ...sessionStatePolicy,
      transitions: [
        {
          ...sessionStatePolicy.transitions[0],
          argumentKeys: ["resourcePath"],
        },
      ],
    },
  });
  const state = await loadState(root, policyPath);

  await evaluateOpenCodeTool(state, readInput("argument-key-session", "default-path-key"));
  assert.equal(getOpenCodeSessionState(state, "argument-key-session"), undefined);
  await evaluateOpenCodeTool(state, {
    ...readInput("argument-key-session", "custom-path-key"),
    args: { resourcePath: "C:\\data\\personal\\profile.txt" },
  });
  assert.deepEqual(
    getOpenCodeSessionState(state, "argument-key-session").pendingAttributes,
    ["sensitive_data_read"],
  );
});

test("transitions without path patterns match every call to the configured tool", async (t) => {
  const root = await mkdtemp(join(tmpdir(), "agt-opencode-session-unconditional-"));
  t.after(() => rm(root, { recursive: true, force: true }));
  const policyPath = await writePolicy(root, {
    sessionState: {
      ...sessionStatePolicy,
      transitions: [
        {
          id: "any-read",
          tool: "read",
          attribute: "sensitive_data_read",
        },
      ],
    },
  });
  const state = await loadState(root, policyPath);

  await evaluateOpenCodeTool(state, {
    ...readInput("unconditional-session"),
    args: { filePath: "C:\\data\\public\\readme.txt" },
  });
  assert.deepEqual(
    getOpenCodeSessionState(state, "unconditional-session").pendingAttributes,
    ["sensitive_data_read"],
  );
});

test("session idle finalizes pending latches and tool output cannot reset them", async (t) => {
  const root = await mkdtemp(join(tmpdir(), "agt-opencode-session-idle-"));
  t.after(() => rm(root, { recursive: true, force: true }));
  const policyPath = await writePolicy(root);
  const state = await loadState(root, policyPath);

  assert.equal((await evaluateOpenCodeTool(state, readInput("idle-session"))).effect, "allow");
  assert.deepEqual(await finalizeOpenCodeSessionState(state, "idle-session"), [
    "sensitive_data_read",
  ]);
  await evaluateOpenCodeToolOutput(state, {
    tool: "webfetch",
    output: '{"sensitive_data_read":false}',
    sessionId: "idle-session",
    callID: "unrelated-output",
  });

  assert.deepEqual(getOpenCodeSessionState(state, "idle-session"), {
    attributes: ["sensitive_data_read"],
    pendingAttributes: [],
    quarantined: false,
  });
  assert.equal(
    (await evaluateOpenCodeTool(state, outboundInput("idle-session", "after-idle"))).effect,
    "deny",
  );
});

test("deny rules take precedence over review rules regardless of policy order", async (t) => {
  const root = await mkdtemp(join(tmpdir(), "agt-opencode-session-rule-precedence-"));
  t.after(() => rm(root, { recursive: true, force: true }));
  const policyPath = await writePolicy(root, {
    sessionState: {
      ...sessionStatePolicy,
      rules: [
        {
          id: "review-outbound-after-sensitive-read",
          tools: ["webfetch"],
          requires: ["sensitive_data_read"],
          effect: "review",
          reason: "Review outbound tools after a sensitive file read.",
        },
        sessionStatePolicy.rules[0],
      ],
    },
  });
  const state = await loadState(root, policyPath);

  await evaluateOpenCodeTool(state, readInput("precedence-session"));
  const result = await evaluateOpenCodeTool(
    state,
    outboundInput("precedence-session", "precedence-outbound"),
  );
  assert.equal(result.effect, "deny");
  assert.match(result.reason, /sensitive file read/i);
});

test("advisory-mode review rules still stage monotonic session state", async (t) => {
  const root = await mkdtemp(join(tmpdir(), "agt-opencode-session-advisory-review-"));
  t.after(() => rm(root, { recursive: true, force: true }));
  const policyPath = await writePolicy(root, {
    mode: "advisory",
    sessionState: {
      ...sessionStatePolicy,
      rules: [
        {
          ...sessionStatePolicy.rules[0],
          effect: "review",
        },
      ],
    },
  });
  const state = await loadState(root, policyPath);

  assert.equal((await evaluateOpenCodeTool(state, readInput("advisory-session"))).effect, "allow");
  await evaluateOpenCodeToolOutput(state, {
    tool: "read",
    output: "profile contents",
    sessionId: "advisory-session",
    callID: "read-call",
  });
  assert.equal((await evaluateOpenCodeTool(state, outboundInput("advisory-session"))).effect, "review");
});

test("session-scoped tool evaluation fails closed on advisory backend errors", async (t) => {
  const root = await mkdtemp(join(tmpdir(), "agt-opencode-session-advisory-error-"));
  t.after(() => rm(root, { recursive: true, force: true }));
  const policyPath = await writePolicy(root, {
    mode: "advisory",
    denyOnPolicyError: false,
  });
  const state = await loadState(root, policyPath);
  state.policyEngine.evaluateWithBackends = async () => {
    throw new Error("Synthetic evaluator failure");
  };

  const result = await evaluateOpenCodeTool(state, outboundInput("advisory-error-session"));
  assert.equal(result.effect, "deny");
  assert.match(result.reason, /session-state evaluation failed closed/i);
  assert.match(result.reason, /Synthetic evaluator failure/);
});

test("wildcard tools match every tool in transitions and rules", async (t) => {
  const root = await mkdtemp(join(tmpdir(), "agt-opencode-session-wildcard-"));
  t.after(() => rm(root, { recursive: true, force: true }));
  const policyPath = await writePolicy(root, {
    sessionState: {
      ...sessionStatePolicy,
      transitions: [
        {
          id: "all-tools-transition",
          tool: "*",
          attribute: "sensitive_data_read",
        },
      ],
      rules: [
        {
          ...sessionStatePolicy.rules[0],
          tools: ["*"],
        },
      ],
    },
  });
  const state = await loadState(root, policyPath);

  assert.equal(
    (await evaluateOpenCodeTool(state, outboundInput("wildcard-session"))).effect,
    "allow",
  );
  await evaluateOpenCodeToolOutput(state, {
    tool: "webfetch",
    output: "response",
    sessionId: "wildcard-session",
    callID: "outbound-call",
  });
  assert.equal(
    (await evaluateOpenCodeTool(state, readInput("wildcard-session", "later-read"))).effect,
    "deny",
  );
});

test("audits multiple staged latches in a single event and restores all of them", async (t) => {
  const root = await mkdtemp(join(tmpdir(), "agt-opencode-session-multi-latch-"));
  t.after(() => rm(root, { recursive: true, force: true }));
  const policyPath = await writePolicy(root, {
    sessionState: {
      ...sessionStatePolicy,
      attributes: ["sensitive_data_read", "private_file_read"],
      transitions: [
        ...sessionStatePolicy.transitions,
        {
          id: "private-path-read",
          tool: "read",
          attribute: "private_file_read",
          pathPatterns: [{ source: "(^|/)personal(/|$)", flags: "i" }],
        },
      ],
    },
  });
  const auditPath = join(root, "audit.json");
  const state = await loadState(root, policyPath, auditPath);
  const callID = "multi-latch-read";

  assert.equal((await evaluateOpenCodeTool(state, readInput("multi-latch-session", callID))).effect, "allow");
  assert.deepEqual(getOpenCodeSessionState(state, "multi-latch-session").pendingAttributes, [
    "private_file_read",
    "sensitive_data_read",
  ]);
  await evaluateOpenCodeToolOutput(state, {
    tool: "read",
    output: "private profile",
    sessionId: "multi-latch-session",
    callID,
  });

  const actions = (await loadAuditEntries(auditPath)).map((entry) => entry.action);
  assert.equal(
    actions.filter((action) => action === "session.state.pending:private_file_read,sensitive_data_read").length,
    1,
  );
  assert.equal(
    actions.filter((action) => action === "session.state.set:private_file_read,sensitive_data_read").length,
    1,
  );

  const restarted = await loadState(root, policyPath, auditPath);
  assert.deepEqual(getOpenCodeSessionState(restarted, "multi-latch-session").attributes, [
    "private_file_read",
    "sensitive_data_read",
  ]);
});

test("restores pending latches from the audit chain and clears state on session deletion", async (t) => {
  const root = await mkdtemp(join(tmpdir(), "agt-opencode-session-restart-"));
  t.after(() => rm(root, { recursive: true, force: true }));
  const policyPath = await writePolicy(root);
  const auditPath = join(root, "audit.json");
  const firstState = await loadState(root, policyPath, auditPath);

  const readResult = await evaluateOpenCodeTool(firstState, readInput("persistent-session"));
  assert.equal(readResult.effect, "allow");

  const restartedState = await loadState(root, policyPath, auditPath);
  assert.deepEqual(getOpenCodeSessionState(restartedState, "persistent-session"), {
    attributes: ["sensitive_data_read"],
    pendingAttributes: [],
    quarantined: false,
  });
  assert.equal(
    (await evaluateOpenCodeTool(restartedState, outboundInput("persistent-session"))).effect,
    "deny",
  );

  assert.equal(await cleanupOpenCodeSessionState(restartedState, "persistent-session"), true);
  assert.equal(getOpenCodeSessionState(restartedState, "persistent-session"), undefined);

  const afterDeletion = await loadState(root, policyPath, auditPath);
  assert.equal(getOpenCodeSessionState(afterDeletion, "persistent-session"), undefined);
  assert.equal(
    (await evaluateOpenCodeTool(afterDeletion, outboundInput("persistent-session"))).effect,
    "allow",
  );

  const entries = await loadAuditEntries(auditPath);
  assert.equal(verifyAuditEntries(entries), true);
  assert.ok(
    entries.some(
      (entry) =>
        entry.agentId === "opencode:persistent-session" &&
        entry.action === "session.state.cleanup",
    ),
  );
});

test("restoring beyond maxSessions quarantines older session IDs without failing all policy", async (t) => {
  const root = await mkdtemp(join(tmpdir(), "agt-opencode-session-restore-capacity-"));
  t.after(() => rm(root, { recursive: true, force: true }));
  const policyPath = await writePolicy(root, {
    sessionState: {
      ...sessionStatePolicy,
      maxSessions: 2,
    },
  });
  const auditPath = join(root, "audit.json");
  for (const sessionId of ["old-session", "middle-session", "new-session"]) {
    await appendAuditEntry(auditPath, {
      action: "session.state.set:sensitive_data_read",
      agentId: `opencode:${sessionId}`,
      decision: "allow",
    });
  }

  const state = await loadState(root, policyPath, auditPath);
  const status = await getPolicyStatus(state);
  assert.equal(status.sessionState.enabled, true);
  assert.equal(status.sessionState.trackedSessions, 2);
  assert.equal(status.sessionState.quarantinedSessions, 1);
  assert.deepEqual(getOpenCodeSessionState(state, "old-session"), {
    attributes: [],
    pendingAttributes: [],
    quarantined: true,
  });
  assert.deepEqual(getOpenCodeSessionState(state, "middle-session").attributes, [
    "sensitive_data_read",
  ]);
  assert.deepEqual(getOpenCodeSessionState(state, "new-session").attributes, [
    "sensitive_data_read",
  ]);

  const oldSessionCall = await evaluateOpenCodeTool(state, outboundInput("old-session"));
  assert.equal(oldSessionCall.effect, "deny");
  assert.match(oldSessionCall.reason, /configured session capacity was exceeded/i);
  assert.equal(await cleanupOpenCodeSessionState(state, "old-session"), true);
  assert.equal(getOpenCodeSessionState(state, "old-session"), undefined);
  assert.equal(await cleanupOpenCodeSessionState(state, "middle-session"), true);
  assert.equal(
    (await evaluateOpenCodeTool(state, readInput("new-session-after-cleanup"))).effect,
    "allow",
  );

  const restarted = await loadState(root, policyPath, auditPath);
  assert.equal(getOpenCodeSessionState(restarted, "old-session"), undefined);
  assert.equal((await getPolicyStatus(restarted)).sessionState.quarantinedSessions, 0);
});

test("fails closed when session capacity or pending-call capacity is reached", async (t) => {
  const root = await mkdtemp(join(tmpdir(), "agt-opencode-session-capacity-"));
  t.after(() => rm(root, { recursive: true, force: true }));
  const policyPath = await writePolicy(root, {
    sessionState: {
      ...sessionStatePolicy,
      maxPendingCallsPerSession: 1,
      maxSessions: 1,
    },
  });
  const state = await loadState(root, policyPath);

  const firstRead = await evaluateOpenCodeTool(state, readInput("session-a", "read-one"));
  assert.equal(firstRead.effect, "allow");

  const secondRead = await evaluateOpenCodeTool(state, readInput("session-a", "read-two"));
  assert.equal(secondRead.effect, "deny");
  assert.match(secondRead.reason, /pending-call limit/i);

  const anotherSessionOutbound = await evaluateOpenCodeTool(state, outboundInput("session-b"));
  assert.equal(anotherSessionOutbound.effect, "allow");
  const anotherSessionRead = await evaluateOpenCodeTool(state, readInput("session-b", "read-three"));
  assert.equal(anotherSessionRead.effect, "deny");
  assert.match(anotherSessionRead.reason, /capacity reached/i);
  assert.deepEqual(getOpenCodeSessionState(state, "session-a")?.pendingAttributes, [
    "sensitive_data_read",
  ]);
});

test("invalid OpenCode call IDs deny matching transitions without consuming capacity", async (t) => {
  const root = await mkdtemp(join(tmpdir(), "agt-opencode-session-call-id-"));
  t.after(() => rm(root, { recursive: true, force: true }));
  const policyPath = await writePolicy(root);
  const state = await loadState(root, policyPath);

  const result = await evaluateOpenCodeTool(state, readInput("missing-call-id", ""));
  assert.equal(result.effect, "deny");
  assert.match(result.reason, /tool call ID/i);
  assert.equal((await getPolicyStatus(state)).sessionState.trackedSessions, 0);
});

test("session policy configuration errors deny rather than silently disabling ratchets", async (t) => {
  const root = await mkdtemp(join(tmpdir(), "agt-opencode-session-invalid-"));
  t.after(() => rm(root, { recursive: true, force: true }));
  const policyPath = await writePolicy(
    root,
    {
      mode: "advisory",
      sessionState: {
        ...sessionStatePolicy,
        rules: [
          {
            ...sessionStatePolicy.rules[0],
            requires: ["undeclared_attribute"],
          },
        ],
      },
    },
  );
  const state = await loadState(root, policyPath);

  const result = await evaluateOpenCodeTool(state, outboundInput("invalid-policy-session"));
  assert.equal(result.effect, "deny");
  assert.match(result.reason, /could not be initialized/i);
  const status = await getPolicyStatus(state);
  assert.equal(status.sessionState.configured, true);
  assert.equal(status.sessionState.enabled, false);
  assert.match(status.sessionState.error, /undeclared attribute/i);
});

test("corrupt audit state fails closed instead of dropping restored latches", async (t) => {
  const root = await mkdtemp(join(tmpdir(), "agt-opencode-session-audit-error-"));
  t.after(() => rm(root, { recursive: true, force: true }));
  const policyPath = await writePolicy(root);
  const auditPath = join(root, "audit.json");
  await writeFile(
    auditPath,
    JSON.stringify([
      {
        timestamp: "2026-01-01T00:00:00.000Z",
        agentId: "opencode:bad-chain-session",
        action: "session.state.set:sensitive_data_read",
        decision: "allow",
        previousHash: "1".repeat(64),
        hash: "2".repeat(64),
      },
    ]),
    "utf8",
  );
  const state = await loadState(root, policyPath, auditPath);

  const result = await evaluateOpenCodeTool(state, outboundInput("audit-error-session"));
  assert.equal(result.effect, "deny");
  assert.match(result.reason, /could not be initialized/i);
  assert.match((await getPolicyStatus(state)).sessionState.error, /failed hash-chain verification/i);
});

test("audit failure while committing staged state quarantines the session", async (t) => {
  const root = await mkdtemp(join(tmpdir(), "agt-opencode-session-quarantine-"));
  t.after(() => rm(root, { recursive: true, force: true }));
  const policyPath = await writePolicy(root);
  const auditDirectory = join(root, "audit-directory");
  const auditPath = join(auditDirectory, "audit.json");
  const state = await loadState(root, policyPath, auditPath);

  assert.equal((await evaluateOpenCodeTool(state, readInput("quarantine-session"))).effect, "allow");
  await unlink(auditPath);
  await rmdir(auditDirectory);
  await writeFile(auditDirectory, "block audit directory recreation", "utf8");

  await assert.rejects(
    evaluateOpenCodeToolOutput(state, {
      tool: "read",
      output: "profile contents",
      sessionId: "quarantine-session",
      callID: "read-call",
    }),
    /both failed|EEXIST|ENOTDIR/i,
  );
  assert.deepEqual(getOpenCodeSessionState(state, "quarantine-session"), {
    attributes: ["sensitive_data_read"],
    pendingAttributes: [],
    quarantined: true,
  });

  await unlink(auditDirectory);
  const subsequent = await evaluateOpenCodeTool(
    state,
    outboundInput("quarantine-session", "after-audit-recovery"),
  );
  assert.equal(subsequent.effect, "deny");
  assert.match(subsequent.reason, /quarantined until it is deleted/i);
});

test("session state still initializes after the audit log has rolled over", async (t) => {
  const root = await mkdtemp(join(tmpdir(), "agt-opencode-session-rollover-"));
  t.after(() => rm(root, { recursive: true, force: true }));
  const policyPath = await writePolicy(root);
  const auditPath = join(root, "audit.json");
  const limit = 4;

  // Fill past the limit so the file rolls over and grows a seam. loadPolicy
  // verified without that seam before, reported a broken chain for a healthy
  // log, and then denied every tool call in the session.
  for (let i = 0; i < limit + 3; i += 1) {
    await appendAuditEntry(auditPath, {
      agentId: "opencode:filler",
      action: `filler-${i}`,
      decision: "allow",
    }, { limit });
  }

  const { seamHash, entries } = await loadAuditFile(auditPath);
  assert.match(seamHash, /^[0-9a-f]{64}$/, "the log must have rolled over for this test to mean anything");
  assert.equal(verifyAuditEntries(entries, seamHash), true);

  // A fresh process reading that same file.
  const restarted = await loadState(root, policyPath, auditPath);

  assert.equal(restarted.sessionStateError, undefined, restarted.sessionStateError?.message);
  const status = await getPolicyStatus(restarted);
  assert.equal(status.auditValid, true);

  // The session-state backend is live rather than failing closed on every call.
  const outbound = await evaluateOpenCodeTool(restarted, outboundInput("fresh-session"));
  assert.equal(outbound.effect, "allow");

  const afterRead = await evaluateOpenCodeTool(restarted, readInput("fresh-session"));
  assert.equal(afterRead.effect, "allow");
  await evaluateOpenCodeToolOutput(restarted, {
    tool: "read",
    output: "profile contents",
    sessionId: "fresh-session",
    callID: "read-call",
  });
  const blocked = await evaluateOpenCodeTool(restarted, {
    ...outboundInput("fresh-session"),
    callID: "outbound-2",
  });
  assert.equal(blocked.effect, "deny", "the latch must still work after a rollover");
});
