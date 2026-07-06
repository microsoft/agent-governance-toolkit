# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""Sandbox PATH constants for Ring-3 execution environments.

These constants define the minimal PATH used by the hardened sandbox
container image (``docker/Dockerfile.sandbox``).  They are the single
source of truth shared between the Dockerfile build, the smoke tests,
and the ``RingEnforcer`` documentation.

The ``MINIMAL_SANDBOX_PATH`` contains only the curated directory
``/usr/local/sandbox/bin``.  Only binaries explicitly symlinked there
during the image build are reachable by sandboxed code.
"""

from __future__ import annotations

# ---------------------------------------------------------------------------
# PATH
# ---------------------------------------------------------------------------

MINIMAL_SANDBOX_PATH: str = "/usr/local/sandbox/bin"
"""Colon-separated PATH string used inside the sandbox container.

Contains exactly one directory: the curated ``/usr/local/sandbox/bin``
populated by ``docker/Dockerfile.sandbox``.  No system bin directories
(``/usr/bin``, ``/bin``) are included.
"""

# ---------------------------------------------------------------------------
# Allowed binaries
# ---------------------------------------------------------------------------

ALLOWED_BINARIES: tuple[str, ...] = (
    "python3",  # required interpreter for sandbox workloads
    "python",  # python3 alias for compatibility
)
"""Binaries intentionally present in ``MINIMAL_SANDBOX_PATH``.

Each entry must have a corresponding ``ln -s`` in the Dockerfile so that
``shutil.which(name, path=MINIMAL_SANDBOX_PATH)`` returns a non-None
result inside the built image.

To extend this list, see ``docs/sandbox-image.md``.
"""

# ---------------------------------------------------------------------------
# Denied commands
# ---------------------------------------------------------------------------

DENIED_COMMANDS: tuple[str, ...] = (
    # Network fetch tools — primary exfiltration / C2 vectors
    "curl",
    "wget",
    "ftp",
    "telnet",
    # Raw socket / proxy tools
    "nc",
    "ncat",
    "netcat",
    "socat",
    "nmap",
    "tcpdump",
    # Alternative interpreters — allow arbitrary code execution
    "perl",
    "ruby",
    "python2",
    # Compiler toolchain — can produce new executables at runtime
    "gcc",
    "g++",
    "make",
    "cc",
    # Shells — allow subshell spawning that bypasses ring enforcement
    "bash",
    "sh",
    "dash",
    "zsh",
    "ksh",
    "fish",
)
"""Commands that MUST NOT be resolvable from ``MINIMAL_SANDBOX_PATH``.

The smoke test (``tests/unit/test_sandbox_path.py``) asserts that
``shutil.which(cmd, path=MINIMAL_SANDBOX_PATH)`` returns ``None`` for
every entry.

These represent the primary denylist-bypass vectors: a sandboxed agent
that can invoke these commands can exfiltrate data, compile new
executables, or spawn unrestricted subshells.

In the built image these binaries are additionally removed from their
original filesystem locations (see ``docker/Dockerfile.sandbox``), so
they cannot be reached by absolute path either — PATH pinning and
filesystem removal are defence-in-depth layers, not alternatives.
"""
