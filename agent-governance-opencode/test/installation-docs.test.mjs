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

    const reexport = doc.match(/export \{ default \} from "([^"]+)";/);
    assert.ok(reexport, "document the workspace shim's import");
    assert.equal(reexport[1], "@microsoft/agent-governance-opencode");
    assert.equal((await import(reexport[1])).default, AgtGovernance);
    assert.match(doc, /opencode debug config/);
    assert.doesNotMatch(doc, /`session\.start`|`tool\.execute\.error`/);
  });
}
