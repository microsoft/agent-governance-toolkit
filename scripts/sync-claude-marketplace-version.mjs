#!/usr/bin/env node
// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const repoRoot = process.env.AGT_TEST_REPO_ROOT
  || path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const check = process.argv.includes("--check");

const packageJsonPath = path.join(repoRoot, "agent-governance-claude-code", "package.json");
const pluginJsonPath = path.join(
  repoRoot,
  "agent-governance-claude-code",
  ".claude-plugin",
  "plugin.json",
);
const marketplaceJsonPath = path.join(repoRoot, ".claude-plugin", "marketplace.json");

function readJson(filePath) {
  return JSON.parse(fs.readFileSync(filePath, "utf8"));
}

function writeJson(filePath, data) {
  fs.writeFileSync(filePath, `${JSON.stringify(data, null, 2)}\n`);
}

function setIfDifferent(data, key, value, drift) {
  if (data[key] === value) {
    return false;
  }
  drift.push(`${key}: ${JSON.stringify(data[key])} -> ${JSON.stringify(value)}`);
  data[key] = value;
  return true;
}

const packageJson = readJson(packageJsonPath);
const pluginJson = readJson(pluginJsonPath);
const marketplaceJson = readJson(marketplaceJsonPath);
const expectedVersion = packageJson.version;

if (!expectedVersion) {
  throw new Error(`${path.relative(repoRoot, packageJsonPath)} is missing version`);
}

const pluginDrift = [];
setIfDifferent(pluginJson, "version", expectedVersion, pluginDrift);

const marketplaceDrift = [];
setIfDifferent(marketplaceJson, "version", expectedVersion, marketplaceDrift);

const pluginEntry = marketplaceJson.plugins?.find((plugin) => plugin.name === pluginJson.name);
if (!pluginEntry) {
  throw new Error(
    `${path.relative(repoRoot, marketplaceJsonPath)} is missing plugin entry ${pluginJson.name}`,
  );
}
setIfDifferent(pluginEntry, "version", expectedVersion, marketplaceDrift);

if (check) {
  if (pluginDrift.length || marketplaceDrift.length) {
    if (pluginDrift.length) {
      console.error(`${path.relative(repoRoot, pluginJsonPath)} is out of sync:`);
      for (const item of pluginDrift) {
        console.error(`  ${item}`);
      }
    }
    if (marketplaceDrift.length) {
      console.error(`${path.relative(repoRoot, marketplaceJsonPath)} is out of sync:`);
      for (const item of marketplaceDrift) {
        console.error(`  ${item}`);
      }
    }
    console.error(
      `Run \`node scripts/sync-claude-marketplace-version.mjs\` to sync from ${path.relative(
        repoRoot,
        packageJsonPath,
      )}.`,
    );
    process.exit(1);
  }
  console.log(`OK: Claude Code marketplace version is ${expectedVersion}`);
  process.exit(0);
}

if (pluginDrift.length) {
  writeJson(pluginJsonPath, pluginJson);
  console.log(`UPDATED ${path.relative(repoRoot, pluginJsonPath)}`);
}

if (marketplaceDrift.length) {
  writeJson(marketplaceJsonPath, marketplaceJson);
  console.log(`UPDATED ${path.relative(repoRoot, marketplaceJsonPath)}`);
}

if (!pluginDrift.length && !marketplaceDrift.length) {
  console.log(`OK: Claude Code marketplace version is ${expectedVersion}`);
}
