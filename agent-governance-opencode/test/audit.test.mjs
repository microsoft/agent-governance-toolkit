// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

import assert from "node:assert/strict";
import { createHash, createHmac, createSecretKey } from "node:crypto";
import { mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";

import {
  AUDIT_ARGS_DIGEST_MAX_BYTES,
  appendAuditEntry,
  canonicalJson,
  computeArgsDigest,
  loadAuditEntries,
  verifyAuditEntries,
} from "../lib/audit.mjs";

const GENESIS_HASH = "0".repeat(64);

async function auditFile(t) {
  const root = await mkdtemp(join(tmpdir(), "agt-opencode-audit-"));
  t.after(() => rm(root, { force: true, recursive: true }));
  return join(root, "audit.json");
}

/**
 * Builds a version 1 entry the way releases before entry versioning did,
 * hashing it here rather than through the module so the fixture stays
 * independent of the code under test.
 */
function makeV1Entry({ action = "tool.bash", agentId = "opencode:s1", decision = "allow", previousHash = GENESIS_HASH, timestamp = "2026-01-01T00:00:00.000Z" } = {}) {
  const hash = createHash("sha256")
    .update(JSON.stringify({ timestamp, agentId, action, decision, previousHash }))
    .digest("hex");
  return { timestamp, agentId, action, decision, previousHash, hash };
}

async function writeEntries(path, entries) {
  await writeFile(path, `${JSON.stringify(entries, null, 2)}\n`, "utf8");
}

test("a v1 log written by an earlier release still verifies", async (t) => {
  const path = await auditFile(t);
  const first = makeV1Entry();
  const second = makeV1Entry({ action: "tool.edit", decision: "deny", previousHash: first.hash });

  await writeEntries(path, [first, second]);

  assert.equal(verifyAuditEntries(await loadAuditEntries(path)), true);
});

test("the v1 hash is unchanged byte for byte", () => {
  const entry = makeV1Entry();
  // Pinned so a future refactor of the hashing path cannot quietly alter v1.
  assert.equal(
    entry.hash,
    createHash("sha256")
      .update(
        '{"timestamp":"2026-01-01T00:00:00.000Z","agentId":"opencode:s1","action":"tool.bash","decision":"allow","previousHash":"' +
          GENESIS_HASH +
          '"}',
      )
      .digest("hex"),
  );
});

test("the v2 preimage is pinned", () => {
  // A fixed entry and the hash an external verifier must reproduce. Without
  // this, dropping a field from the preimage still passes every structural
  // test, because the writer and the verifier drop it together.
  const entry = {
    v: 2,
    timestamp: "2026-01-01T00:00:00.000Z",
    agentId: "opencode:pinned",
    action: "tool.bash",
    decision: "deny",
    previousHash: GENESIS_HASH,
    policyVersion: "sha256:" + "0".repeat(64),
    reason: "blocked by rule",
    argsDigest: "a".repeat(64),
    argsDigestAlg: "sha256",
    principal: { sub: "user-1", iss: "https://idp.example" },
  };

  const preimage =
    '{"action":"tool.bash","agentId":"opencode:pinned","argsDigest":"' + "a".repeat(64) +
    '","argsDigestAlg":"sha256","decision":"deny","policyVersion":"sha256:' + "0".repeat(64) +
    '","previousHash":"' + GENESIS_HASH +
    '","principal":{"iss":"https://idp.example","sub":"user-1"},"reason":"blocked by rule",' +
    '"timestamp":"2026-01-01T00:00:00.000Z","v":2}';

  assert.equal(canonicalJson(entry), preimage, "canonical preimage drifted");

  const hash = createHash("sha256").update(preimage, "utf8").digest("hex");
  assert.equal(
    hash,
    "525187f667de119cb55772e2add4cadd937b37de577b4d1873ffa612a701680b",
    "pinned v2 hash drifted",
  );
  assert.equal(verifyAuditEntries([{ ...entry, hash }]), true);
});

test("appending to a v1 log writes a v2 entry linked to the v1 tail", async (t) => {
  const path = await auditFile(t);
  const legacy = makeV1Entry();
  await writeEntries(path, [legacy]);

  const appended = await appendAuditEntry(path, {
    agentId: "opencode:s2",
    action: "tool.read",
    decision: "allow",
  });

  assert.equal(appended.v, 2);
  assert.equal(appended.previousHash, legacy.hash);

  const entries = await loadAuditEntries(path);
  assert.equal(entries.length, 2);
  assert.equal(verifyAuditEntries(entries), true, "a mixed v1/v2 chain must verify");
});

test("empty and v2-only logs verify", async (t) => {
  const path = await auditFile(t);
  assert.equal(verifyAuditEntries([]), true);

  await appendAuditEntry(path, { agentId: "opencode:s1", action: "a", decision: "allow" });
  await appendAuditEntry(path, { agentId: "opencode:s1", action: "b", decision: "deny" });

  assert.equal(verifyAuditEntries(await loadAuditEntries(path)), true);
});

test("verifyAuditEntries rejects a non-array", () => {
  assert.equal(verifyAuditEntries(null), false);
  assert.equal(verifyAuditEntries({}), false);
});

test("downgrade: stripping v from a v2 entry fails verification", async (t) => {
  const path = await auditFile(t);
  await appendAuditEntry(path, { agentId: "opencode:s1", action: "a", decision: "allow" });

  const entries = await loadAuditEntries(path);
  const { v: _dropped, ...withoutVersion } = entries[0];

  assert.equal(verifyAuditEntries([withoutVersion]), false);
});

test("downgrade: a re-hashed v1 tail after a v2 entry fails verification", async (t) => {
  const path = await auditFile(t);
  await appendAuditEntry(path, { agentId: "opencode:s1", action: "a", decision: "allow" });
  const [first] = await loadAuditEntries(path);

  // A well-formed v1 entry, correctly hashed, appended after a v2 entry. Only
  // the versions-only-go-up rule catches this.
  const forged = makeV1Entry({ previousHash: first.hash, action: "tool.exfiltrate" });

  assert.equal(verifyAuditEntries([first, forged]), false);
});

test("injecting a v key onto a v1 entry fails verification", () => {
  for (const injected of [2, 1, null, "2"]) {
    const entry = { ...makeV1Entry(), v: injected };
    assert.equal(verifyAuditEntries([entry]), false, `v: ${JSON.stringify(injected)}`);
  }
});

test("an enrichment field forged onto a v1 entry fails verification", () => {
  const entry = { ...makeV1Entry(), reason: "looks official" };
  assert.equal(verifyAuditEntries([entry]), false);
});

test("tampering with a v2 entry fails verification", async (t) => {
  const path = await auditFile(t);
  await appendAuditEntry(path, {
    agentId: "opencode:s1",
    action: "tool.bash",
    decision: "deny",
    reason: "blocked by rule",
    policyVersion: "sha256:abc",
    argsDigest: "a".repeat(64),
    argsDigestAlg: "sha256",
    principal: { sub: "user-1", iss: "https://idp.example" },
  });
  const [entry] = await loadAuditEntries(path);

  assert.equal(verifyAuditEntries([entry]), true, "baseline must verify");

  const mutations = {
    "unknown key": { ...entry, note: "hello" },
    "changed reason": { ...entry, reason: "allowed by rule" },
    "changed principal": { ...entry, principal: { ...entry.principal, sub: "user-2" } },
    "removed digest": (() => {
      const { argsDigest: _gone, ...rest } = entry;
      return rest;
    })(),
    "removed alg": (() => {
      const { argsDigestAlg: _gone, ...rest } = entry;
      return rest;
    })(),
    "unknown alg": { ...entry, argsDigestAlg: "md5" },
    "argsTruncated false": { ...entry, argsTruncated: false },
    "principal extra key": { ...entry, principal: { sub: "user-1", role: "admin" } },
  };

  for (const [label, mutated] of Object.entries(mutations)) {
    assert.equal(verifyAuditEntries([mutated]), false, label);
  }
});

test("appendAuditEntry refuses to write a malformed entry", async (t) => {
  const path = await auditFile(t);
  await assert.rejects(
    () => appendAuditEntry(path, { agentId: "a", action: "b", decision: "allow", principal: { iss: "no-sub" } }),
    /malformed audit entry/,
  );
});

test("canonicalJson sorts integer-like keys lexicographically", () => {
  // Rebuilding an object would reorder these: JS puts integer-like keys first.
  assert.equal(canonicalJson({ 10: 1, 2: 1, a: 1 }), '{"10":1,"2":1,"a":1}');
});

test("canonicalJson is independent of insertion order", () => {
  const a = { z: 1, a: { y: 2, b: 3 } };
  const b = { a: { b: 3, y: 2 }, z: 1 };
  assert.equal(canonicalJson(a), canonicalJson(b));
});

test("canonicalJson handles unicode and number edge cases", () => {
  assert.equal(canonicalJson("\ud800"), '"\\ud800"', "a lone surrogate must be escaped");
  assert.equal(canonicalJson(-0), "0");
  assert.equal(canonicalJson([1, "a", null, true]), '[1,"a",null,true]');
});

test("canonicalJson strict mode refuses what JSON cannot represent", () => {
  for (const value of [Number.NaN, Number.POSITIVE_INFINITY, undefined, 1n, () => {}]) {
    assert.throws(() => canonicalJson(value), TypeError, String(value));
  }

  const cyclic = { name: "root" };
  cyclic.self = cyclic;
  assert.throws(() => canonicalJson(cyclic), /circular/);
  assert.throws(() => canonicalJson({ a: { b: { c: 1 } } }, { maxDepth: 1 }), /depth/);
});

test("canonicalJson lenient mode follows JSON semantics", () => {
  assert.equal(canonicalJson({ a: undefined, b: 1 }, { lenient: true }), '{"b":1}');
  assert.equal(canonicalJson([undefined], { lenient: true }), "[null]");
  assert.equal(canonicalJson(Number.NaN, { lenient: true }), "null");
});

test("unserializable arguments are flagged, not silently constant", () => {
  const cyclic = {};
  cyclic.self = cyclic;

  const flagged = computeArgsDigest(cyclic);
  assert.equal(flagged.argsUnserializable, true);

  // Every unserializable value digests to the same constant, so without the
  // flag the entry would imply the digest identifies these arguments.
  assert.equal(computeArgsDigest({ big: 1n }).argsDigest, flagged.argsDigest);
  assert.equal(Object.hasOwn(computeArgsDigest({ ok: 1 }), "argsUnserializable"), false);
});

test("computeArgsDigest never throws", () => {
  const cyclic = {};
  cyclic.self = cyclic;
  const throwing = {
    get boom() {
      throw new Error("nope");
    },
  };

  for (const args of [cyclic, { big: 1n }, throwing]) {
    const result = computeArgsDigest(args);
    assert.match(result.argsDigest, /^[0-9a-f]{64}$/);
    assert.equal(result.argsDigestAlg, "sha256");
  }
});

test("computeArgsDigest switches to HMAC when a key is configured", () => {
  const args = { command: "ls -la" };
  const key = createSecretKey(Buffer.alloc(32, 7));

  const plain = computeArgsDigest(args);
  const keyed = computeArgsDigest(args, { hmacKey: key });

  assert.equal(plain.argsDigestAlg, "sha256");
  assert.equal(keyed.argsDigestAlg, "hmac-sha256");
  assert.notEqual(plain.argsDigest, keyed.argsDigest);
  assert.equal(
    keyed.argsDigest,
    createHmac("sha256", key).update(canonicalJson(args, { lenient: true }), "utf8").digest("hex"),
  );
});

test("an HMAC digest still verifies when no key is configured", async (t) => {
  const path = await auditFile(t);
  const key = createSecretKey(Buffer.alloc(32, 9));
  const digest = computeArgsDigest({ command: "rm -rf /" }, { hmacKey: key });

  await appendAuditEntry(path, { agentId: "a", action: "tool.bash", decision: "deny", ...digest });

  // Verification reads the stored digest; it never recomputes it, so rotating
  // or losing the key cannot invalidate history.
  assert.equal(verifyAuditEntries(await loadAuditEntries(path)), true);
});

test("computeArgsDigest truncates oversized arguments and says so", () => {
  const small = computeArgsDigest({ text: "x".repeat(16) });
  assert.equal(Object.hasOwn(small, "argsTruncated"), false);

  const huge = computeArgsDigest({ text: "x".repeat(AUDIT_ARGS_DIGEST_MAX_BYTES + 1024) });
  assert.equal(huge.argsTruncated, true);
  assert.match(huge.argsDigest, /^[0-9a-f]{64}$/);
});

test("raw arguments never reach the audit file", async (t) => {
  const path = await auditFile(t);
  const secret = "correct-horse-battery-staple";

  await appendAuditEntry(path, {
    agentId: "a",
    action: "tool.bash",
    decision: "allow",
    ...computeArgsDigest({ command: `echo ${secret}` }),
  });

  const contents = await readFile(path, "utf8");
  assert.equal(contents.includes(secret), false);
});
