#!/usr/bin/env node
// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

import { runCli } from "../lib/cli.mjs";

const exitCode = await runCli(process.argv.slice(2));
if (typeof exitCode === "number" && exitCode !== 0) {
  process.exit(exitCode);
}
