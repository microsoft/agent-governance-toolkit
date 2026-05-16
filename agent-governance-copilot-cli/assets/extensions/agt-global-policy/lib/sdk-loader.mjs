// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

import { existsSync, realpathSync } from "node:fs";
import { join, resolve } from "node:path";
import { pathToFileURL } from "node:url";

export const SDK_ENTRY_ENV = "AGT_COPILOT_SDK_ENTRY";
export const UNSAFE_SDK_OVERRIDE_ENV = "AGT_COPILOT_ALLOW_UNSAFE_SDK_OVERRIDE";

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

  if (env[SDK_ENTRY_ENV]) {
    const overridePath = resolve(String(env[SDK_ENTRY_ENV]));
    if (env[UNSAFE_SDK_OVERRIDE_ENV] === "true") {
      candidates.unshift({
        path: overridePath,
        source: "env-unsafe",
      });
    } else if (existsSync(overridePath)) {
      const canonicalOverridePath = realpathSync(overridePath);
      if (isPathContained(canonicalOverridePath, join(extensionRootPath, "vendor"))) {
        candidates.unshift({
          path: canonicalOverridePath,
          source: "env",
        });
      }
    }
  }

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
       "Unable to locate the Agent Governance TypeScript SDK.",
        `Checked the vendored npm package and ${SDK_ENTRY_ENV}${env[UNSAFE_SDK_OVERRIDE_ENV] === "true" ? " (unsafe override enabled)" : ""}.`,
        `Paths: ${attempted.join("; ")}`,
      ].join(" "),
    );
}

function isPathContained(candidatePath, expectedRoot) {
  const normalizedCandidate = `${candidatePath.replace(/\\/g, "/").toLowerCase()}/`;
  const normalizedRoot = `${realpathSync(resolve(expectedRoot)).replace(/\\/g, "/").toLowerCase()}/`;
  return normalizedCandidate.startsWith(normalizedRoot);
}
