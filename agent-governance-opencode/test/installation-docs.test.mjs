// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";

import AgtGovernance from "../src/index.mjs";

for (const path of ["../README.md", "../../docs/packages/opencode-governance.md"]) {
  test(`${path} documents a discoverable shim using the package export`, async () => {
    const doc = await readFile(new URL(path, import.meta.url), "utf8");
    const shim = doc.match(/\.opencode\/plugins\/agt\.(\w+)/);
    assert.ok(shim, "document the workspace shim path");
    assert.ok(["js", "ts"].includes(shim[1]), "OpenCode discovers JS/TS shims");
    assert.doesNotMatch(doc, /\*\.\{[^}]*mjs[^}]*\}/);

    // The 1.x shim re-exports the package root, the 2.x shim its `./server` entry.
    const reexports = [...doc.matchAll(/export \{ default \} from "([^"]+)";/g)].map((m) => m[1]);
    assert.deepEqual(reexports, [
      "@microsoft/agent-governance-opencode",
      "@microsoft/agent-governance-opencode/server",
    ]);
    assert.equal((await import(reexports[0])).default, AgtGovernance);
    assert.equal((await import(reexports[1])).default.server, AgtGovernance);
    assert.match(doc, /opencode debug config/);
    assert.doesNotMatch(doc, /`session\.start`|`tool\.execute\.error`/);
  });
}
