// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

import assert from "node:assert/strict";
import { mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";

import {
  appendAuditEntry,
  getAuditStatus,
  loadAuditFile,
  verifyAuditEntries,
} from "../lib/audit.mjs";

const GENESIS = "0".repeat(64);

async function createTempAudit() {
  const directory = await mkdtemp(join(tmpdir(), "agt-claude-audit-rollover-"));
  return { directory, path: join(directory, "audit.json") };
}

async function appendEntries(path, count) {
  for (let index = 0; index < count; index += 1) {
    await appendAuditEntry(path, {
      agentId: "agent-a",
      action: `tool.test-${index}`,
      decision: "allow",
    });
  }
}

test("audit rollover keeps the surviving chain verifiable", async () => {
  const { directory, path } = await createTempAudit();
  try {
    const limit = 3;
    for (let index = 0; index < limit + 2; index += 1) {
      await appendAuditEntry(
        path,
        { agentId: "agent-a", action: `tool.test-${index}`, decision: "allow" },
        { limit },
      );
    }

    const { seamHash, entries } = await loadAuditFile(path);
    assert.equal(entries.length, limit);
    assert.deepEqual(
      entries.map((entry) => entry.action),
      ["tool.test-2", "tool.test-3", "tool.test-4"],
    );
    assert.ok(seamHash);
    assert.equal(entries[0].previousHash, seamHash);
    assert.equal(verifyAuditEntries(entries, seamHash), true);
    assert.equal((await getAuditStatus(path)).valid, true);

    await appendAuditEntry(
      path,
      { agentId: "agent-a", action: "tool.after-rollover", decision: "allow" },
      { limit },
    );
    assert.equal((await getAuditStatus(path)).valid, true);

    const persisted = JSON.parse(await readFile(path, "utf8"));
    assert.equal(Array.isArray(persisted), false);
    assert.equal(persisted.seamHash, (await loadAuditFile(path)).seamHash);
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
});

test("legacy truncated arrays recover without weakening in-place tamper detection", async () => {
  const { directory, path } = await createTempAudit();
  try {
    await appendEntries(path, 4);
    const original = await loadAuditFile(path);
    const truncated = original.entries.slice(1);
    await writeFile(path, `${JSON.stringify(truncated, null, 2)}\n`, "utf8");

    assert.notEqual(truncated[0].previousHash, GENESIS);
    assert.equal((await getAuditStatus(path)).valid, true);
    await appendAuditEntry(path, {
      agentId: "agent-a",
      action: "tool.after-recovery",
      decision: "allow",
    });
    assert.equal((await getAuditStatus(path)).valid, true);

    const afterRecovery = await loadAuditFile(path);
    afterRecovery.entries[1].decision = "deny";
    await writeFile(path, `${JSON.stringify(afterRecovery.entries, null, 2)}\n`, "utf8");
    assert.equal((await getAuditStatus(path)).valid, false);
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
});

test("unrolled audit logs retain the legacy bare-array format", async () => {
  const { directory, path } = await createTempAudit();
  try {
    await appendEntries(path, 2);
    const persisted = JSON.parse(await readFile(path, "utf8"));
    assert.ok(Array.isArray(persisted));
    assert.equal(persisted[0].previousHash, GENESIS);
    assert.equal((await getAuditStatus(path)).valid, true);
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
});
