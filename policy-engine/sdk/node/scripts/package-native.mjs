#!/usr/bin/env node
// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

import { copyFileSync, mkdirSync } from "node:fs";
import { basename, dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { spawnSync } from "node:child_process";

const args = new Map();
for (let index = 2; index < process.argv.length; index += 2) {
  const key = process.argv[index];
  const value = process.argv[index + 1];
  if (!key?.startsWith("--") || value === undefined) {
    process.stderr.write("usage: package-native.mjs --package <name> --binary <path> --pack-destination <dir>\n");
    process.exit(2);
  }
  args.set(key.slice(2), value);
}

const packageName = args.get("package");
const binaryPath = args.get("binary");
const packDestination = args.get("pack-destination");
if (!packageName || !binaryPath || !packDestination) {
  process.stderr.write("usage: package-native.mjs --package <name> --binary <path> --pack-destination <dir>\n");
  process.exit(2);
}

const here = dirname(fileURLToPath(import.meta.url));
const packageDir = join(here, "..", "npm", packageName);
const packageBinary = join(packageDir, basename(binaryPath));
mkdirSync(packDestination, { recursive: true });
copyFileSync(binaryPath, packageBinary);

const result = spawnSync("npm", ["pack", "--pack-destination", packDestination], {
  cwd: packageDir,
  stdio: "inherit",
  shell: process.platform === "win32",
});
process.exit(result.status ?? 1);
