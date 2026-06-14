# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""Tests for the hardened-image logging denial shim (issue #2662, option 2).

These exercise the shim directly and assert the Dockerfile wires it in. They do
not require a Docker daemon: the shim is plain-stdlib Python invoked through a
symlink so ``argv[0]`` carries the denied command name, exactly as it would in
the image.
"""

from __future__ import annotations

import json
import pathlib
import subprocess
import sys

import pytest

_DOCKER_DIR = pathlib.Path(__file__).resolve().parent.parent / "docker"
SHIM = _DOCKER_DIR / "agt-deny-shim.py"
DOCKERFILE = _DOCKER_DIR / "Dockerfile.sandbox"
DENY_EXIT_CODE = 126


def _invoke_as(tmp_path, name: str, *args: str, env: dict | None = None):
    """Run the shim through a symlink named *name*, returning the result."""
    link = tmp_path / name
    link.symlink_to(SHIM)
    return subprocess.run(
        [sys.executable, str(link), *args],
        capture_output=True,
        text=True,
        env=env,
    )


class TestDenyShim:
    def test_denies_with_nonzero_exit(self, tmp_path):
        result = _invoke_as(tmp_path, "az", "account", "list")
        assert result.returncode == DENY_EXIT_CODE
        # The real command must never run, so there is nothing on stdout.
        assert result.stdout == ""

    def test_emits_structured_record(self, tmp_path):
        result = _invoke_as(tmp_path, "kubectl", "get", "pods")
        # First stderr line is the machine-parseable record.
        first = result.stderr.splitlines()[0]
        record = json.loads(first)
        assert record["event"] == "command_denied"
        assert record["binary"] == "kubectl"
        assert record["argv"] == ["get", "pods"]
        assert record["issue"] == 2662
        # Audit records key on "timestamp" across AGT (compliance/flight_recorder/…).
        assert record["timestamp"].endswith("Z")

    def test_emits_human_readable_line(self, tmp_path):
        result = _invoke_as(tmp_path, "terraform", "apply")
        assert "command denied: terraform" in result.stderr

    def test_records_binary_name_from_argv0(self, tmp_path):
        # The same shim file reports whichever name it was invoked under.
        assert json.loads(_invoke_as(tmp_path, "curl").stderr.splitlines()[0])["binary"] == "curl"
        assert json.loads(_invoke_as(tmp_path, "wget").stderr.splitlines()[0])["binary"] == "wget"

    def test_appends_to_audit_log_when_configured(self, tmp_path):
        log = tmp_path / "denied.log"
        result = _invoke_as(
            tmp_path, "az", "login", env={"AGT_DENIED_LOG": str(log)}
        )
        assert result.returncode == DENY_EXIT_CODE
        record = json.loads(log.read_text(encoding="utf-8").splitlines()[0])
        assert record["binary"] == "az"
        assert record["argv"] == ["login"]

    def test_unwritable_audit_log_warns_but_does_not_crash(self, tmp_path):
        # A bad log path must not turn a denial into a hard error, but the
        # failure to record should be surfaced rather than swallowed.
        result = _invoke_as(
            tmp_path, "az", env={"AGT_DENIED_LOG": "/nonexistent-dir/x.log"}
        )
        assert result.returncode == DENY_EXIT_CODE
        assert "could not write AGT_DENIED_LOG" in result.stderr

    def test_audit_log_does_not_follow_symlink(self, tmp_path):
        # A planted AGT_DENIED_LOG symlink must not redirect the append
        # (O_NOFOLLOW). The symlink target stays untouched and the failure
        # is surfaced on stderr.
        target = tmp_path / "secret.txt"
        target.write_text("original", encoding="utf-8")
        link = tmp_path / "evil.log"
        link.symlink_to(target)

        result = _invoke_as(tmp_path, "az", env={"AGT_DENIED_LOG": str(link)})

        assert result.returncode == DENY_EXIT_CODE
        assert target.read_text(encoding="utf-8") == "original"
        assert "could not write AGT_DENIED_LOG" in result.stderr

    def test_main_with_empty_argv_reports_unknown(self):
        # main([]) is reachable as a direct call; the argv[0] guard must hold.
        import contextlib
        import importlib.util
        import io

        spec = importlib.util.spec_from_file_location("agt_deny_shim", SHIM)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)

        stderr = io.StringIO()
        with contextlib.redirect_stderr(stderr):
            rc = module.main([])
        assert rc == DENY_EXIT_CODE
        assert json.loads(stderr.getvalue().splitlines()[0])["binary"] == "unknown"


class TestDockerfileWiresShim:
    """Validate the Dockerfile wiring as text (no Docker daemon needed)."""

    @staticmethod
    def _read() -> str:
        return DOCKERFILE.read_text(encoding="utf-8")

    def test_shim_file_exists(self):
        assert SHIM.is_file()

    def test_dockerfile_copies_shim(self):
        assert "COPY agt-deny-shim.py" in self._read()

    def test_dockerfile_routes_denied_clis_to_shim(self):
        content = self._read()
        # The shim must be symlinked into both the real dirs and the pinned
        # PATH dir so by-name and absolute-path calls are both logged.
        assert "agt-deny-shim.py" in content
        assert "/usr/local/sandbox-bin/$bin" in content
        # The network/infra CLIs the issue calls out must be in the routed set.
        import re

        match = re.search(r'ARG\s+DENIED_LOGGED_BIN_NAMES\s*=\s*"([^"]+)"', content)
        assert match, "Dockerfile must declare DENIED_LOGGED_BIN_NAMES"
        routed = set(match.group(1).split())
        assert {"az", "kubectl", "terraform", "curl"} <= routed

    def test_shells_are_not_routed_to_python_shim(self):
        # Shells stay execute-bit-stripped (stage 2); routing them to a Python
        # shim would be pointless and risks an interpreter loop.
        import re

        content = self._read()
        match = re.search(r'ARG\s+DENIED_LOGGED_BIN_NAMES\s*=\s*"([^"]+)"', content)
        routed = set(match.group(1).split())
        assert not ({"sh", "bash", "dash", "busybox"} & routed)


if __name__ == "__main__":
    sys.exit(pytest.main([__file__, "-q"]))
