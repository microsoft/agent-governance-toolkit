#!/usr/local/bin/python3
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
allowed interpreter. The shebang is the absolute interpreter path
(``/usr/local/bin/python3`` in the ``python:3.11-slim`` base) rather than
``/usr/bin/env python3`` so it does not depend on ``env`` or on PATH resolution.
It depends only on the standard library.
"""

import json
import os
import sys
import time

# Conventional "permission denied" exit status. Distinct from 127 ("command
# not found") so logs/tests can tell an explicit denial from an absent binary.
# Note (issue #2662 review): routing through this shim means an absolute-path
# call to a denied binary now exits 126 rather than raising EACCES; the denial
# signal is the non-zero exit plus the stderr record, not a PermissionError.
DENY_EXIT_CODE = 126


def main(argv: list[str]) -> int:
    invoked = os.path.basename(argv[0]) if argv and argv[0] else "unknown"
    record = {
        "event": "command_denied",
        "binary": invoked,
        "argv": argv[1:],
        "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "issue": 2662,
    }
    line = json.dumps(record, separators=(",", ":"), sort_keys=True)
    # Emit the structured record and the human-readable line in a single write
    # so concurrent shim processes cannot interleave a partial record on the
    # shared stderr stream.
    sys.stderr.write(
        line
        + "\n"
        + f"agt-sandbox: command denied: {invoked} "
        "(blocked by sandbox command denylist)\n"
    )

    # Best-effort append to an audit log when a writable path is configured.
    # The hardened image runs read-only as nobody, so this is normally a no-op;
    # it lets an embedder point at a writable mount when one exists.
    #
    # O_NOFOLLOW refuses to open a symlink at the final path component, so a
    # planted AGT_DENIED_LOG symlink cannot redirect the append to an arbitrary
    # file. A write failure is surfaced on stderr rather than swallowed.
    log_path = os.environ.get("AGT_DENIED_LOG")
    if log_path:
        try:
            fd = os.open(
                log_path,
                os.O_WRONLY | os.O_CREAT | os.O_APPEND | os.O_NOFOLLOW,
                0o600,
            )
            try:
                os.write(fd, (line + "\n").encode("utf-8"))
            finally:
                os.close(fd)
        except OSError as exc:
            sys.stderr.write(
                f"agt-sandbox: warning: could not write AGT_DENIED_LOG: {exc}\n"
            )

    return DENY_EXIT_CODE


if __name__ == "__main__":
    sys.exit(main(sys.argv))
