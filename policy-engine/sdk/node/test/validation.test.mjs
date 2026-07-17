// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

import test from "node:test";
import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";

import { validateArtifacts } from "../dist/index.js";

const fixtureUrl = new URL("../../../tests/parity/artifact-validation-cases.json", import.meta.url);
const corpus = JSON.parse(await readFile(fixtureUrl, "utf8"));

for (const fixture of corpus.cases) {
  test(`artifact validation parity ${fixture.name}`, async () => {
    const result = await validateArtifacts(fixture.manifest, fixture.rego);
    assert.equal(result.valid, fixture.valid);
    assert.deepEqual(
      result.diagnostics.map((diagnostic) => diagnostic.code),
      fixture.codes,
    );
  });
}
