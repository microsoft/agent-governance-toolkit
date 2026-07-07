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
  loadAuditEntries,
  loadAuditFile,
  MAX_ENTRIES,
  verifyAuditEntries,
} from "../lib/audit.mjs";

const GENESIS = "0".repeat(64);

async function tmp() {
  const dir = await mkdtemp(join(tmpdir(), "agt-audit-rollover-"));
  return { dir, path: join(dir, "audit.json") };
}

async function chain(path, n) {
  for (let i = 0; i < n; i += 1) {
    await appendAuditEntry(path, { agentId: "a", action: `tool.t${i}`, decision: "allow" });
  }
  return loadAuditEntries(path);
}

test("MAX_ENTRIES default is exported and positive", () => {
  assert.equal(Number.isInteger(MAX_ENTRIES), true);
  assert.ok(MAX_ENTRIES > 0);
});

test("append itself evicts and computes the seam once entries exceed the limit", async () => {
  const { dir, path } = await tmp();
  try {
    const limit = 3;
    // Drive the real appendAuditEntry eviction path (combined.length > limit),
    // not a hand-written rolled-over file. limit + 2 appends force the
    // eviction/seam-computation branch to run more than once.
    for (let i = 0; i < limit + 2; i += 1) {
      await appendAuditEntry(
        path,
        { agentId: "a", action: `tool.t${i}`, decision: "allow" },
        { limit },
      );
    }

    const { seamHash, entries } = await loadAuditFile(path);
    // Capped at the limit, oldest entries dropped, newest retained in order.
    assert.equal(entries.length, limit);
    assert.deepEqual(
      entries.map((e) => e.action),
      ["tool.t2", "tool.t3", "tool.t4"],
    );
    // A seam was computed and the surviving head links to it (not GENESIS).
    assert.notEqual(seamHash, null);
    assert.notEqual(entries[0].previousHash, GENESIS);
    assert.equal(entries[0].previousHash, seamHash);

    // Persisted format switched to { seamHash, entries } once rolled over.
    const raw = JSON.parse(await readFile(path, "utf8"));
    assert.equal(Array.isArray(raw), false);
    assert.equal(raw.seamHash, seamHash);
    assert.ok(Array.isArray(raw.entries));

    // Chain verifies and further appends are still accepted (no brick).
    assert.equal(verifyAuditEntries(entries, seamHash), true);
    assert.equal((await getAuditStatus(path)).valid, true);
    await appendAuditEntry(
      path,
      { agentId: "a", action: "tool.more", decision: "allow" },
      { limit },
    );
    assert.equal((await getAuditStatus(path)).valid, true);
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});

test("rolled-over log (seam-anchored head) still verifies and accepts appends", async () => {
  const { dir, path } = await tmp();
  try {
    const entries = await chain(path, 4);
    // Simulate what append does once the log exceeds MAX_ENTRIES: evict the
    // genesis-anchored head and retain its hash as the seam.
    const evicted = entries[0];
    const survivors = entries.slice(1);
    await writeFile(
      path,
      JSON.stringify({ seamHash: evicted.hash, entries: survivors }, null, 2) + "\n",
      "utf8",
    );

    const loaded = await loadAuditFile(path);
    assert.equal(loaded.seamHash, evicted.hash);
    assert.notEqual(survivors[0].previousHash, GENESIS);
    assert.equal(verifyAuditEntries(loaded.entries, loaded.seamHash), true);
    assert.equal((await getAuditStatus(path)).valid, true);

    // The previous implementation threw "failed hash-chain verification" here.
    const appended = await appendAuditEntry(path, {
      agentId: "a",
      action: "tool.next",
      decision: "allow",
    });
    assert.equal(appended.previousHash, survivors[survivors.length - 1].hash);
    assert.equal((await getAuditStatus(path)).valid, true);
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});

test("legacy truncated bare-array log (non-GENESIS head) is recovered, not bricked", async () => {
  const { dir, path } = await tmp();
  try {
    const entries = await chain(path, 4);
    // A prior version wrote a bare array truncated to a non-GENESIS head, with
    // no seam persisted.
    const truncated = entries.slice(1);
    await writeFile(path, JSON.stringify(truncated, null, 2) + "\n", "utf8");

    assert.notEqual(truncated[0].previousHash, GENESIS);
    assert.equal((await getAuditStatus(path)).valid, true);
    await appendAuditEntry(path, {
      agentId: "a",
      action: "tool.after-recovery",
      decision: "allow",
    });
    assert.equal((await getAuditStatus(path)).valid, true);
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});

test("fresh un-rolled log stays GENESIS-anchored in the legacy bare-array format", async () => {
  const { dir, path } = await tmp();
  try {
    await chain(path, 3);
    const raw = JSON.parse(await readFile(path, "utf8"));
    assert.ok(Array.isArray(raw), "un-rolled log stays a bare array");
    assert.equal(raw[0].previousHash, GENESIS);
    assert.equal((await getAuditStatus(path)).valid, true);
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});

test("tampered entry content is still detected after the fix", async () => {
  const { dir, path } = await tmp();
  try {
    const entries = await chain(path, 3);
    entries[1].decision = "deny"; // tamper content without recomputing hash
    await writeFile(path, JSON.stringify(entries, null, 2) + "\n", "utf8");
    assert.equal((await getAuditStatus(path)).valid, false);
    await assert.rejects(
      () =>
        appendAuditEntry(path, { agentId: "a", action: "tool.x", decision: "allow" }),
      /failed hash-chain verification/,
    );
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});
