// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

import assert from "node:assert/strict";
import { existsSync } from "node:fs";
import { spawnSync } from "node:child_process";
import test from "node:test";
import { matchesRecursiveDeleteCommand } from "../lib/recursive-delete.mjs";

test("reviewer fixtures agree with Bash argument boundaries using a mock rm", { skip: !existsSync("/bin/bash") }, () => {
  // Only these fixed reviewer fixtures execute. The shell functions replace
  // rm and pwd; no real deletion or arbitrary generated command is executed.
  const fixtures = [
    ['rm -r "$(pwd)/src" -f', ["-r", "/fixture/src", "-f"]],
    ["rm -r x$(pwd) -f", ["-r", "x/fixture", "-f"]],
    ['rm "$(pwd)/src" -rf', ["/fixture/src", "-rf"]],
    ['rm -r "`pwd`/src" -f', ["-r", "/fixture/src", "-f"]],
    ["rm -r x`pwd` -f", ["-r", "x/fixture", "-f"]],
    ['rm "`pwd`/src" -rf', ["/fixture/src", "-rf"]],
    ["echo $(pwd) rm -rf src", []],
    ["echo `pwd` rm -rf src", []],
  ];
  for (const [command, expectedArgs] of fixtures) {
    // cspell:ignore noprofile norc
    const result = spawnSync("/bin/bash", ["--noprofile", "--norc", "-c",
      'rm() { printf "%s\\0" "$@" >&2; }; pwd() { printf /fixture; }; ' + command,
    ], { encoding: "utf8", timeout: 5000, env: { PATH: "/usr/bin:/bin", LC_ALL: "C" } });
    assert.equal(result.status, 0, result.stderr);
    const args = result.stderr ? result.stderr.split("\0").slice(0, -1) : [];
    assert.deepEqual(args, expectedArgs, command);
    assert.equal(matchesRecursiveDeleteCommand(command), expectedArgs.length > 0, command);
  }
});
