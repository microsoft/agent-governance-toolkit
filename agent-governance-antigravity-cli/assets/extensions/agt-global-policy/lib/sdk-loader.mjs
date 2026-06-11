// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

import { existsSync, realpathSync } from "node:fs";
import { join, resolve } from "node:path";
import { pathToFileURL } from "node:url";

const VENDORED_SDK_RELATIVE_PATH =
  "./vendor/agent-governance-sdk/node_modules/@microsoft/agent-governance-sdk/dist/index.js";

export async function loadAgentGovernanceSdk({
  env = process.env,
  extensionRoot = import.meta.dirname,
} = {}) {
  const extensionRootPath = realpathSync(resolve(extensionRoot));
  const vendoredSdkPath = resolve(extensionRootPath, VENDORED_SDK_RELATIVE_PATH);
  const candidates = [
    {
      path: vendoredSdkPath,
      source: "vendored",
    },
  ];

  const attempted = [];
  for (const candidate of candidates) {
    attempted.push(candidate.path);
    if (!existsSync(candidate.path)) {
      continue;
    }

    const canonicalCandidatePath = realpathSync(candidate.path);
    const loaded = await import(pathToFileURL(canonicalCandidatePath).href);
    return {
      path: canonicalCandidatePath,
      sdk: loaded.default ?? loaded,
      source: candidate.source,
    };
  }

  throw new Error(
    [
      "Unable to locate the vendored Agent Governance TypeScript SDK.",
      `Checked paths: ${attempted.join("; ")}`,
    ].join(" "),
  );
}
