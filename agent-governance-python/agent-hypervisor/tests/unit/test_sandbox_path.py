# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""Smoke tests for the minimal-PATH sandbox image (docker/Dockerfile.sandbox).

These tests validate that the constants defined in ``hypervisor.sandbox``
are internally consistent and that a simulated minimal sandbox PATH
exposes only the intentionally allowed binaries.

The simulation works by creating a temporary directory, populating it
with stub executables for each entry in ``ALLOWED_BINARIES``, and then
calling ``shutil.which`` with that directory as the sole PATH.  This
approach is portable (no Docker daemon required) and deterministic
(independent of the host filesystem).

To run a full end-to-end smoke test against the built container image::

    docker build -f docker/Dockerfile.sandbox -t hypervisor-sandbox .
    docker run --rm hypervisor-sandbox sh -c '
        for cmd in curl wget nc bash perl ruby gcc; do
            command -v "$cmd" && exit 1 || true
        done
        echo "All denied binaries absent — OK"
    '

Wired into the Ring-3 sandbox provider tests via the shared
``hypervisor.sandbox`` module imported in ``test_ring_enforcement.py``.
"""

from __future__ import annotations

import os
import shutil
import stat
from pathlib import Path

import pytest

from hypervisor.sandbox import (
    ALLOWED_BINARIES,
    DENIED_COMMANDS,
    MINIMAL_SANDBOX_PATH,
)

# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture()
def simulated_sandbox_bin(tmp_path: Path) -> str:
    """Return a PATH string pointing at a directory pre-populated with
    stub executables for every entry in ``ALLOWED_BINARIES``.

    Each stub is a minimal shell script that is marked executable.  On
    Windows the stub is created with a ``.cmd`` extension so that
    ``shutil.which`` can locate it via PATHEXT; on Linux/macOS the
    script has no extension.  The directory contains *only* those stubs —
    no denied commands are present.

    Note: the sandbox image is Linux-only; Windows support here is for
    running these unit tests in mixed-platform CI environments.
    """
    sandbox_bin = tmp_path / "sandbox_bin"
    sandbox_bin.mkdir()
    for name in ALLOWED_BINARIES:
        if os.name == "nt":
            # Windows: shutil.which resolves names via PATHEXT
            stub = sandbox_bin / f"{name}.cmd"
            stub.write_text("@echo off\n", encoding="utf-8")
        else:
            stub = sandbox_bin / name
            stub.write_text("#!/bin/sh\nexec true\n", encoding="utf-8")
            stub.chmod(stub.stat().st_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)
    return str(sandbox_bin)


# ---------------------------------------------------------------------------
# Constants consistency tests
# ---------------------------------------------------------------------------


def test_minimal_sandbox_path_is_single_directory() -> None:
    """MINIMAL_SANDBOX_PATH must be exactly one directory (no colons)."""
    dirs = [d for d in MINIMAL_SANDBOX_PATH.split(":") if d]
    assert len(dirs) == 1, (
        f"MINIMAL_SANDBOX_PATH must contain exactly one directory; got: {dirs}"
    )


def test_minimal_sandbox_path_is_curated_directory() -> None:
    """MINIMAL_SANDBOX_PATH must use the curated sandbox bin directory,
    not a standard system directory that ships many uncontrolled binaries.
    """
    forbidden_prefixes = ("/usr/bin", "/bin", "/sbin", "/usr/sbin", "/usr/local/bin")
    assert not MINIMAL_SANDBOX_PATH.startswith(forbidden_prefixes), (
        f"MINIMAL_SANDBOX_PATH ({MINIMAL_SANDBOX_PATH!r}) must not use a "
        "standard system bin directory — use a curated directory instead."
    )


def test_allowed_binaries_is_non_empty() -> None:
    assert len(ALLOWED_BINARIES) >= 1, "ALLOWED_BINARIES must list at least one binary"


def test_denied_commands_is_non_empty() -> None:
    assert len(DENIED_COMMANDS) >= 1, "DENIED_COMMANDS must list at least one command"


def test_no_overlap_between_allowed_and_denied() -> None:
    """No binary should appear in both the allow-list and deny-list."""
    overlap = set(ALLOWED_BINARIES) & set(DENIED_COMMANDS)
    assert not overlap, (
        f"These names appear in both ALLOWED_BINARIES and DENIED_COMMANDS: {overlap}"
    )


def test_core_network_tools_are_denied() -> None:
    """Canonical network exfiltration tools must be on the denylist."""
    required_denied = {"curl", "wget", "nc", "ncat"}
    missing = required_denied - set(DENIED_COMMANDS)
    assert not missing, f"Missing from DENIED_COMMANDS: {missing}"


def test_shells_are_denied() -> None:
    """Shell interpreters must be on the denylist."""
    required_denied = {"bash", "sh"}
    missing = required_denied - set(DENIED_COMMANDS)
    assert not missing, f"Missing from DENIED_COMMANDS: {missing}"


def test_python3_is_allowed() -> None:
    """python3 must be in the allowed list (it is the runtime interpreter)."""
    assert "python3" in ALLOWED_BINARIES


# ---------------------------------------------------------------------------
# Simulated minimal PATH smoke tests
# ---------------------------------------------------------------------------


def test_allowed_binaries_resolvable_from_sandbox_path(
    simulated_sandbox_bin: str,
) -> None:
    """Every entry in ALLOWED_BINARIES must be findable on the simulated PATH."""
    for name in ALLOWED_BINARIES:
        result = shutil.which(name, path=simulated_sandbox_bin)
        assert result is not None, (
            f"{name!r} is in ALLOWED_BINARIES but not found on the simulated sandbox PATH. "
            "Update the fixture or the Dockerfile symlinks."
        )


def test_denied_commands_not_resolvable_from_sandbox_path(
    simulated_sandbox_bin: str,
) -> None:
    """No entry in DENIED_COMMANDS must be findable on the simulated sandbox PATH.

    This is the core smoke test: the simulated PATH directory contains *only*
    the ALLOWED_BINARIES stubs, so any denied command must return None.
    """
    for cmd in DENIED_COMMANDS:
        result = shutil.which(cmd, path=simulated_sandbox_bin)
        assert result is None, (
            f"{cmd!r} is in DENIED_COMMANDS but was found on the simulated sandbox PATH "
            f"at {result!r}. Remove it from ALLOWED_BINARIES or re-check the fixture."
        )


def test_extra_binary_outside_allowed_is_not_resolvable(tmp_path: Path) -> None:
    """Binaries placed outside the curated directory are not on PATH."""
    other_dir = tmp_path / "other"
    other_dir.mkdir()
    if os.name == "nt":
        exe = other_dir / "curl.cmd"
        exe.write_text("@echo off\n", encoding="utf-8")
    else:
        exe = other_dir / "curl"
        exe.write_text("#!/bin/sh\nexec true\n", encoding="utf-8")
        exe.chmod(exe.stat().st_mode | stat.S_IXUSR)

    # Curated dir has no curl; other_dir has curl but is not on PATH
    curated = tmp_path / "curated"
    curated.mkdir()
    result = shutil.which("curl", path=str(curated))
    assert result is None


# ---------------------------------------------------------------------------
# Dockerfile enforcement test
# ---------------------------------------------------------------------------


def test_dockerfile_removes_denied_binaries_at_filesystem_level() -> None:
    """The Dockerfile must physically remove (``rm -f``) representative denied
    binaries — network fetch tools and shells — rather than only dropping them
    from PATH.

    A binary that is merely PATH-pinned could still be invoked by absolute
    path, so filesystem removal is required to keep the built image consistent
    with ``DENIED_COMMANDS``.
    """
    dockerfile = Path(__file__).resolve().parents[2] / "docker" / "Dockerfile.sandbox"
    text = dockerfile.read_text(encoding="utf-8")

    assert "rm -f" in text, "Dockerfile must remove denied binaries with rm -f"
    for path in ("/usr/bin/curl", "/usr/bin/wget", "/bin/bash", "/bin/sh"):
        assert path in text, (
            f"{path!r} must be removed from the filesystem in Dockerfile.sandbox "
            "so the image matches DENIED_COMMANDS"
        )


def test_dockerfile_strips_setuid_bits() -> None:
    """The Dockerfile must clear setuid/setgid bits to block privilege
    escalation through binaries such as su, mount, or ping.
    """
    dockerfile = Path(__file__).resolve().parents[2] / "docker" / "Dockerfile.sandbox"
    text = dockerfile.read_text(encoding="utf-8")
    assert "chmod a-s" in text, (
        "Dockerfile must strip setuid/setgid bits with 'chmod a-s'"
    )
