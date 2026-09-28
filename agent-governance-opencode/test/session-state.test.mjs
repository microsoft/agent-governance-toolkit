// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

import assert from "node:assert/strict";
import { mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
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
import { loadAuditEntries, verifyAuditEntries } from "../lib/audit.mjs";

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

async function writePolicy(root, { sessionState = sessionStatePolicy, mode = "enforce" } = {}) {
  const policyPath = join(root, "policy.json");
  await writeFile(
    policyPath,
    JSON.stringify({
      schemaVersion: 1,
      mode,
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
  assert.match((await getPolicyStatus(state)).sessionState.error, /undeclared attribute/i);
});

test("corrupt audit state fails closed instead of dropping restored latches", async (t) => {
  const root = await mkdtemp(join(tmpdir(), "agt-opencode-session-audit-error-"));
  t.after(() => rm(root, { recursive: true, force: true }));
  const policyPath = await writePolicy(root);
  const auditPath = join(root, "audit.json");
  await writeFile(auditPath, "{invalid audit\n", "utf8");
  const state = await loadState(root, policyPath, auditPath);

  const result = await evaluateOpenCodeTool(state, outboundInput("audit-error-session"));
  assert.equal(result.effect, "deny");
  assert.match(result.reason, /could not be initialized/i);
  assert.match((await getPolicyStatus(state)).sessionState.error, /unreadable or corrupt/i);
});
