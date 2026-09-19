# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""Tests for the Scope Guard integration module."""

from __future__ import annotations

import subprocess
from unittest.mock import MagicMock, patch

import pytest

from agent_os.integrations.scope_guard import (
    ScopeConfig,
    ScopeGuard,
    _escalate,
    _get_diff_stats,
)

# ── ScopeConfig defaults ──────────────────────────────────────


class TestScopeConfig:
    def test_defaults(self):
        cfg = ScopeConfig()
        assert cfg.max_files == 10
        assert cfg.max_lines == 500
        assert cfg.mode == "on"
        assert cfg.drift_detection is True

    def test_custom_values(self):
        cfg = ScopeConfig(max_files=5, max_lines=200, mode="off", drift_detection=False)
        assert cfg.max_files == 5
        assert cfg.max_lines == 200
        assert cfg.mode == "off"
        assert cfg.drift_detection is False


# ── _escalate helper ──────────────────────────────────────────


class TestEscalate:
    def test_pass_to_soft_fail(self):
        assert _escalate("PASS", "SOFT_FAIL") == "SOFT_FAIL"

    def test_soft_fail_to_hard_fail(self):
        assert _escalate("SOFT_FAIL", "HARD_FAIL") == "HARD_FAIL"

    def test_hard_fail_stays(self):
        assert _escalate("HARD_FAIL", "SOFT_FAIL") == "HARD_FAIL"

    def test_same_level(self):
        assert _escalate("SOFT_FAIL", "SOFT_FAIL") == "SOFT_FAIL"

    def test_pass_stays_on_pass(self):
        assert _escalate("PASS", "PASS") == "PASS"


# ── ScopeGuard.evaluate — decision paths ─────────────────────


class TestScopeGuardEvaluate:
    def setup_method(self):
        self.guard = ScopeGuard()

    def test_mode_off_always_passes(self):
        cfg = ScopeConfig(max_files=1, max_lines=1, mode="off")
        result = self.guard.evaluate(
            "agent-1", cfg,
            changed_files=["a.py", "b.py", "c.py"],
            insertions=999, deletions=999,
        )
        assert result.decision == "PASS"
        assert "disabled" in result.reason.lower()

    def test_within_limits_passes(self):
        cfg = ScopeConfig(max_files=10, max_lines=500)
        result = self.guard.evaluate(
            "agent-1", cfg,
            changed_files=["a.py"],
            insertions=50, deletions=10,
        )
        assert result.decision == "PASS"
        assert result.files_changed == 1
        assert result.lines_changed == 60

    def test_files_exceed_soft_fail(self):
        cfg = ScopeConfig(max_files=2, max_lines=1000)
        result = self.guard.evaluate(
            "agent-1", cfg,
            changed_files=["a.py", "b.py", "c.py"],
            insertions=10, deletions=10,
        )
        assert result.decision == "SOFT_FAIL"
        assert result.excess_files == ["c.py"]

    def test_files_exceed_hard_fail(self):
        cfg = ScopeConfig(max_files=2, max_lines=1000)
        files = [f"f{i}.py" for i in range(5)]
        result = self.guard.evaluate(
            "agent-1", cfg,
            changed_files=files,
            insertions=10, deletions=10,
        )
        assert result.decision == "HARD_FAIL"
        assert "2× limit" in result.reason

    def test_lines_exceed_soft_fail(self):
        cfg = ScopeConfig(max_files=100, max_lines=100)
        result = self.guard.evaluate(
            "agent-1", cfg,
            changed_files=["a.py"],
            insertions=100, deletions=50,
        )
        assert result.decision == "SOFT_FAIL"
        assert result.lines_changed == 150

    def test_lines_exceed_hard_fail(self):
        cfg = ScopeConfig(max_files=100, max_lines=100)
        result = self.guard.evaluate(
            "agent-1", cfg,
            changed_files=["a.py"],
            insertions=150, deletions=60,
        )
        assert result.decision == "HARD_FAIL"
        assert result.lines_changed == 210

    def test_drift_warning_triggers_soft_fail(self):
        cfg = ScopeConfig(max_files=10, max_lines=500, drift_detection=True)
        drift = [{"severity": "warning", "type": "scope_creep"}]
        result = self.guard.evaluate(
            "agent-1", cfg,
            changed_files=["a.py"],
            insertions=10, deletions=0,
            drift_indicators=drift,
        )
        assert result.decision == "SOFT_FAIL"
        assert "drift" in result.reason.lower()

    def test_drift_info_does_not_trigger(self):
        cfg = ScopeConfig(max_files=10, max_lines=500, drift_detection=True)
        drift = [{"severity": "info", "type": "minor"}]
        result = self.guard.evaluate(
            "agent-1", cfg,
            changed_files=["a.py"],
            insertions=10, deletions=0,
            drift_indicators=drift,
        )
        assert result.decision == "PASS"

    def test_drift_detection_disabled_ignores_warnings(self):
        cfg = ScopeConfig(max_files=10, max_lines=500, drift_detection=False)
        drift = [{"severity": "warning", "type": "scope_creep"}]
        result = self.guard.evaluate(
            "agent-1", cfg,
            changed_files=["a.py"],
            insertions=10, deletions=0,
            drift_indicators=drift,
        )
        assert result.decision == "PASS"

    def test_combined_file_and_line_soft_fail(self):
        cfg = ScopeConfig(max_files=2, max_lines=100)
        result = self.guard.evaluate(
            "agent-1", cfg,
            changed_files=["a.py", "b.py", "c.py"],
            insertions=80, deletions=40,
        )
        assert result.decision == "SOFT_FAIL"
        assert "files" in result.reason
        assert "lines" in result.reason

    def test_hard_fail_dominates_soft_fail(self):
        cfg = ScopeConfig(max_files=2, max_lines=100)
        files = [f"f{i}.py" for i in range(5)]
        result = self.guard.evaluate(
            "agent-1", cfg,
            changed_files=files,
            insertions=120, deletions=0,
        )
        assert result.decision == "HARD_FAIL"

    def test_max_files_zero_disables_file_check(self):
        cfg = ScopeConfig(max_files=0, max_lines=500)
        result = self.guard.evaluate(
            "agent-1", cfg,
            changed_files=["a.py"] * 100,
            insertions=10, deletions=0,
        )
        assert result.decision == "PASS"

    def test_max_lines_zero_disables_line_check(self):
        cfg = ScopeConfig(max_files=10, max_lines=0)
        result = self.guard.evaluate(
            "agent-1", cfg,
            changed_files=["a.py"],
            insertions=99999, deletions=99999,
        )
        assert result.decision == "PASS"


# ── Policy engine integration ─────────────────────────────────


class TestScopeGuardPolicyEngine:
    def test_records_event_to_policy_engine(self):
        engine = MagicMock()
        guard = ScopeGuard(policy_engine=engine)
        cfg = ScopeConfig(max_files=10, max_lines=500)
        guard.evaluate("agent-1", cfg, ["a.py"], 10, 0)
        engine.record_event.assert_called_once()
        event = engine.record_event.call_args[0][0]
        assert event["type"] == "scope_evaluation"
        assert event["agent_id"] == "agent-1"

    def test_no_error_without_policy_engine(self):
        guard = ScopeGuard(policy_engine=None)
        cfg = ScopeConfig()
        result = guard.evaluate("agent-1", cfg, ["a.py"], 1, 0)
        assert result.decision == "PASS"


# ── evaluate_from_git ─────────────────────────────────────────


class TestEvaluateFromGit:
    @patch("agent_os.integrations.scope_guard._get_diff_stats")
    def test_delegates_to_evaluate(self, mock_stats):
        mock_stats.return_value = (["a.py", "b.py"], 100, 50, None)
        guard = ScopeGuard()
        cfg = ScopeConfig(max_files=10, max_lines=500)
        result = guard.evaluate_from_git("agent-1", cfg, "/repo", "main")
        assert result.files_changed == 2
        assert result.lines_changed == 150
        assert result.decision == "PASS"

    @patch("agent_os.integrations.scope_guard._get_diff_stats")
    def test_measurement_error_hard_fails(self, mock_stats):
        mock_stats.return_value = ([], 0, 0, "git diff exited with status 128")
        guard = ScopeGuard()
        cfg = ScopeConfig(max_files=10, max_lines=500)

        result = guard.evaluate_from_git("agent-1", cfg, "/repo", "main")

        assert result.decision == "HARD_FAIL"
        assert result.files_changed == 0
        assert result.lines_changed == 0
        assert result.error == "git diff exited with status 128"
        assert "Unable to measure git diff" in result.reason

    @patch("agent_os.integrations.scope_guard._get_diff_stats")
    def test_mode_off_ignores_measurement_error(self, mock_stats):
        mock_stats.return_value = ([], 0, 0, "git diff exited with status 128")
        guard = ScopeGuard()
        cfg = ScopeConfig(max_files=10, max_lines=500, mode="off")

        result = guard.evaluate_from_git("agent-1", cfg, "/repo", "main")

        assert result.decision == "PASS"
        assert result.error is None
        assert "disabled" in result.reason.lower()

    @patch("agent_os.integrations.scope_guard._get_diff_stats")
    def test_measurement_error_is_recorded(self, mock_stats):
        mock_stats.return_value = ([], 0, 0, "git diff exited with status 128")
        engine = MagicMock()
        guard = ScopeGuard(policy_engine=engine)
        cfg = ScopeConfig(max_files=10, max_lines=500)

        guard.evaluate_from_git("agent-1", cfg, "/repo", "main")

        event = engine.record_event.call_args[0][0]
        assert event["decision"] == "HARD_FAIL"
        assert event["error"] == "git diff exited with status 128"

    @pytest.mark.parametrize("base_branch", ["--stat", "b.py"])
    @patch("agent_os.integrations.scope_guard.subprocess.run")
    def test_option_like_or_path_like_base_branch_hard_fails(
        self, mock_run, base_branch
    ):
        mock_run.return_value = subprocess.CompletedProcess(
            args=[], returncode=128, stdout="", stderr="fatal: bad revision\n",
        )
        guard = ScopeGuard()
        cfg = ScopeConfig(max_files=10, max_lines=500)

        result = guard.evaluate_from_git("agent-1", cfg, "/repo", base_branch)

        assert result.decision == "HARD_FAIL"
        assert mock_run.call_args.args[0] == [
            "git",
            "diff",
            "--numstat",
            "--end-of-options",
            base_branch,
            "--",
        ]

# ── _get_diff_stats ───────────────────────────────────────────


class TestGetDiffStats:
    @patch("agent_os.integrations.scope_guard.subprocess.run")
    def test_parses_numstat(self, mock_run):
        mock_run.return_value = subprocess.CompletedProcess(
            args=[], returncode=0,
            stdout="10\t5\tsrc/main.py\n20\t3\tsrc/util.py\n",
        )
        files, ins, deletions, error = _get_diff_stats("/repo", "main")
        assert files == ["src/main.py", "src/util.py"]
        assert ins == 30
        assert deletions == 8
        assert error is None

    @patch("agent_os.integrations.scope_guard.subprocess.run")
    def test_handles_binary_dashes(self, mock_run):
        mock_run.return_value = subprocess.CompletedProcess(
            args=[], returncode=0,
            stdout="-\t-\timage.png\n",
        )
        files, ins, deletions, error = _get_diff_stats("/repo")
        assert files == ["image.png"]
        assert ins == 0
        assert deletions == 0
        assert error is None

    @patch("agent_os.integrations.scope_guard.subprocess.run")
    def test_empty_output(self, mock_run):
        mock_run.return_value = subprocess.CompletedProcess(
            args=[], returncode=0, stdout="",
        )
        files, ins, deletions, error = _get_diff_stats("/repo")
        assert files == []
        assert ins == 0
        assert deletions == 0
        assert error is None

    @patch(
        "agent_os.integrations.scope_guard.subprocess.run",
        side_effect=FileNotFoundError("git not found"),
    )
    def test_handles_missing_git(self, mock_run):
        files, ins, deletions, error = _get_diff_stats("/repo")
        assert files == []
        assert ins == 0
        assert deletions == 0
        assert "git not found" in error

    @patch(
        "agent_os.integrations.scope_guard.subprocess.run",
        side_effect=NotADirectoryError("not a repository"),
    )
    def test_handles_invalid_repo_path(self, mock_run):
        files, ins, deletions, error = _get_diff_stats("/not-a-repo")
        assert files == []
        assert ins == 0
        assert deletions == 0
        assert "not a repository" in error

    @patch(
        "agent_os.integrations.scope_guard.subprocess.run",
        side_effect=subprocess.TimeoutExpired(["git", "diff"], 30),
    )
    def test_handles_diff_timeout(self, mock_run):
        files, ins, deletions, error = _get_diff_stats("/repo")
        assert files == []
        assert ins == 0
        assert deletions == 0
        assert "TimeoutExpired" in error

    @patch("agent_os.integrations.scope_guard.subprocess.run")
    def test_handles_nonzero_git_exit(self, mock_run):
        mock_run.return_value = subprocess.CompletedProcess(
            args=[], returncode=128, stdout="", stderr="fatal: bad revision 'main'\n",
        )

        files, ins, deletions, error = _get_diff_stats("/repo", "main")

        assert files == []
        assert ins == 0
        assert deletions == 0
        assert error == "git diff exited with status 128: fatal: bad revision 'main'"

    @patch("agent_os.integrations.scope_guard.subprocess.run")
    def test_truncates_git_error_output(self, mock_run):
        mock_run.return_value = subprocess.CompletedProcess(
            args=[],
            returncode=129,
            stdout="",
            stderr="fatal: not a repository\n" + ("usage: git diff\n" * 1000),
        )

        files, ins, deletions, error = _get_diff_stats("/repo")

        assert files == []
        assert ins == 0
        assert deletions == 0
        assert error == "git diff exited with status 129: fatal: not a repository"

    @pytest.mark.parametrize(
        "stdout",
        [
            "10\t5\n",
            "not-a-number\t5\tsrc/main.py\n",
        ],
    )
    @patch("agent_os.integrations.scope_guard.subprocess.run")
    def test_handles_unparseable_diff_row(self, mock_run, stdout):
        mock_run.return_value = subprocess.CompletedProcess(
            args=[], returncode=0, stdout=stdout,
        )

        files, ins, deletions, error = _get_diff_stats("/repo")

        assert files == []
        assert ins == 0
        assert deletions == 0
        assert "unparseable" in error
