// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

import assert from "node:assert/strict";
import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";

import AgtGovernance from "../src/index.mjs";

function makeClient(logs = []) {
  return {
    app: {
      log: async ({ body }) => {
        logs.push(body);
      },
    },
  };
}

test("duplicate registration for the same client and workspace is suppressed", async () => {
  const root = await mkdtemp(join(tmpdir(), "agt-opencode-duplicate-"));
  const logs = [];
  const client = makeClient(logs);

  try {
    const first = await AgtGovernance({ directory: root, worktree: root, client });
    const second = await AgtGovernance({ directory: root, worktree: join(root, "."), client });

    assert.equal(typeof first["tool.execute.before"], "function");
    assert.deepEqual(second, {});
    assert.equal(
      [first, second].filter((plugin) => typeof plugin["tool.execute.before"] === "function").length,
      1,
    );
    assert.ok(
      logs.some(
        (entry) =>
          entry?.level === "warn" &&
          /Duplicate OpenCode governance registration ignored/.test(entry?.message ?? ""),
      ),
      "duplicate registration should emit an actionable warning",
    );
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

test("duplicate registration falls back to console.warn without app logger", async () => {
  const root = await mkdtemp(join(tmpdir(), "agt-opencode-console-warning-"));
  const client = {};
  const warnings = [];
  const originalWarn = console.warn;
  console.warn = (...args) => warnings.push(args.join(" "));

  try {
    await AgtGovernance({ directory: root, worktree: root, client });
    const duplicate = await AgtGovernance({ directory: root, worktree: root, client });

    assert.deepEqual(duplicate, {});
    assert.ok(
      warnings.some((warning) => /Duplicate OpenCode governance registration ignored/.test(warning)),
      "duplicate registration should remain observable without client.app.log",
    );
  } finally {
    console.warn = originalWarn;
    await rm(root, { recursive: true, force: true });
  }
});

test("different workspaces on the same OpenCode client are not suppressed", async () => {
  const rootA = await mkdtemp(join(tmpdir(), "agt-opencode-workspace-a-"));
  const rootB = await mkdtemp(join(tmpdir(), "agt-opencode-workspace-b-"));
  const client = makeClient();

  try {
    const pluginA = await AgtGovernance({ directory: rootA, worktree: rootA, client });
    const pluginB = await AgtGovernance({ directory: rootB, worktree: rootB, client });

    assert.equal(typeof pluginA["tool.execute.before"], "function");
    assert.equal(typeof pluginB["tool.execute.before"], "function");
  } finally {
    await rm(rootA, { recursive: true, force: true });
    await rm(rootB, { recursive: true, force: true });
  }
});

test("independent OpenCode clients in the same workspace are not suppressed", async () => {
  const root = await mkdtemp(join(tmpdir(), "agt-opencode-independent-"));

  try {
    const pluginA = await AgtGovernance({ directory: root, worktree: root, client: makeClient() });
    const pluginB = await AgtGovernance({ directory: root, worktree: root, client: makeClient() });

    assert.equal(typeof pluginA["tool.execute.before"], "function");
    assert.equal(typeof pluginB["tool.execute.before"], "function");
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});
