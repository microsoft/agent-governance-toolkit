// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

import { existsSync } from "node:fs";
import { resolve } from "node:path";
import { pathToFileURL } from "node:url";

export const SDK_ENTRY_ENV = "AGT_COPILOT_SDK_ENTRY";

const VENDORED_SDK_RELATIVE_PATH =
  "./vendor/agent-governance-sdk/node_modules/@microsoft/agent-governance-sdk/dist/index.js";
const REPO_SDK_RELATIVE_PATH = "../../../../../agent-governance-typescript/dist/index.js";

export async function loadAgentGovernanceSdk({
  env = process.env,
  extensionRoot = import.meta.dirname,
} = {}) {
  const candidates = [];

  if (env[SDK_ENTRY_ENV]) {
    candidates.push({
      path: resolve(String(env[SDK_ENTRY_ENV])),
      source: "env",
    });
  }

  candidates.push(
    {
      path: resolve(extensionRoot, VENDORED_SDK_RELATIVE_PATH),
      source: "vendored",
    },
    {
      path: resolve(extensionRoot, REPO_SDK_RELATIVE_PATH),
      source: "repo-build",
    },
  );

  const attempted = [];
  for (const candidate of candidates) {
    attempted.push(candidate.path);
    if (!existsSync(candidate.path)) {
      continue;
    }

    const loaded = await import(pathToFileURL(candidate.path).href);
    return {
      path: candidate.path,
      sdk: loaded.default ?? loaded,
      source: candidate.source,
    };
  }

  throw new Error(
    [
       "Unable to locate the Agent Governance TypeScript SDK.",
       `Checked ${SDK_ENTRY_ENV}, the vendored npm package, and a repo-local build.`,
       `Paths: ${attempted.join("; ")}`,
     ].join(" "),
   );
}
