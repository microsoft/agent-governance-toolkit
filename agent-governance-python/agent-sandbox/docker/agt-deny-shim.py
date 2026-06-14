#!/usr/bin/env python3
# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""Logging denial shim for the hardened sandbox image (issue #2662, option 2).

The minimal-PATH image already makes denied network/infra CLIs unreachable, but
a blocked attempt is *silent* ("command not found" / EACCES). For compliance,
detecting the attempt matters as much as preventing it. This shim is installed
in place of those CLIs (and exposed under their names in the pinned PATH dir),
so any attempt to run one lands here: the attempt is recorded as a structured
``command_denied`` record on stderr — captured in ``SandboxResult.stderr`` — and
the shim exits non-zero, so the real command never runs.

It is written in Python on purpose: the hardened image strips the execute bit
off every shell, so a shell shim could not run, whereas ``python3`` is an
allowed interpreter. It depends only on the standard library.
"""

import json
import os
import sys
import time

# Conventional "permission denied" exit status. Distinct from 127 ("command
# not found") so logs/tests can tell an explicit denial from an absent binary.
DENY_EXIT_CODE = 126


def main(argv: list[str]) -> int:
    invoked = os.path.basename(argv[0]) if argv and argv[0] else "unknown"
    record = {
        "event": "command_denied",
        "binary": invoked,
        "argv": argv[1:],
        "ts": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "issue": 2662,
    }
    line = json.dumps(record, separators=(",", ":"), sort_keys=True)
    # Structured record first (machine-parseable), then a human-readable line.
    sys.stderr.write(line + "\n")
    sys.stderr.write(
        f"agt-sandbox: command denied: {invoked} "
        "(blocked by sandbox command denylist)\n"
    )

    # Best-effort append to an audit log when a writable path is configured.
    # The hardened image runs read-only as nobody, so this is normally a no-op;
    # it lets an embedder point at a writable mount when one exists.
    log_path = os.environ.get("AGT_DENIED_LOG")
    if log_path:
        try:
            with open(log_path, "a", encoding="utf-8") as handle:
                handle.write(line + "\n")
        except OSError:
            pass

    return DENY_EXIT_CODE


if __name__ == "__main__":
    sys.exit(main(sys.argv))
