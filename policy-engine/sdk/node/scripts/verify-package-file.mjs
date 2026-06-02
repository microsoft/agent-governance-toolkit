#!/usr/bin/env node
// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

import { accessSync, constants, statSync } from "node:fs";
import { join } from "node:path";

const relativePath = process.argv[2];
if (relativePath === undefined || relativePath === "") {
  process.stderr.write("usage: verify-package-file.mjs <relative-file>\n");
  process.exit(2);
}

const path = join(process.cwd(), relativePath);
try {
  accessSync(path, constants.R_OK);
  const stat = statSync(path);
  if (!stat.isFile() || stat.size === 0) {
    throw new Error(`${relativePath} is not a non-empty file`);
  }
} catch (error) {
  process.stderr.write(`package file verification failed: ${error instanceof Error ? error.message : String(error)}\n`);
  process.exit(1);
}
