# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""Tests for the Scope Guard integration module."""

from __future__ import annotations

import subprocess
from unittest.mock import MagicMock, patch

import pytest

from agent_os.integrations.scope_guard import (
    ScopeConfig,
    ScopeEvaluation,
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
        assert result.error is None


# ── evaluate_from_git — unmeasurable diffs fail closed ────────


class TestEvaluateFromGitFailsClosed:
    """An unreadable diff must block, not pass.

    ``_get_diff_stats`` reported every failure as ``([], 0, 0)``, which the
    limit checks read as a zero-file, zero-line change — the most in-scope
    change possible. So a wrong base branch, a path that is not a repository,
    a missing ``git`` or a timeout each turned the guard off and reported
    ``PASS`` with reason "All scope checks passed", for a change of any size.
    """

    def setup_method(self):
        self.guard = ScopeGuard()
        self.cfg = ScopeConfig(max_files=10, max_lines=500)

    @pytest.mark.parametrize(
        ("returncode", "stderr"),
        [
            # Unknown base branch: a shallow clone or a repo whose default
            # branch is not "main". The likeliest failure in practice.
            (128, "fatal: ambiguous argument 'main': unknown revision"),
            (129, "warning: Not a git repository."),
            (1, ""),  # nonzero with no stderr must still fail closed
        ],
    )
    @patch("agent_os.integrations.scope_guard.subprocess.run")
    def test_nonzero_exit_hard_fails(self, mock_run, returncode, stderr):
        mock_run.return_value = subprocess.CompletedProcess(
            args=[], returncode=returncode, stdout="", stderr=stderr,
        )
        result = self.guard.evaluate_from_git("agent-1", self.cfg, "/repo", "main")
        assert result.decision == "HARD_FAIL"
        assert result.error is not None
        assert "could not be measured" in result.reason

    @pytest.mark.parametrize(
        "exc",
        [
            FileNotFoundError("git not found"),
            NotADirectoryError("repo_path is not a directory"),
            PermissionError("repo_path is unreadable"),
            subprocess.TimeoutExpired(cmd="git", timeout=30),
        ],
    )
    @patch("agent_os.integrations.scope_guard.subprocess.run")
    def test_subprocess_failure_hard_fails(self, mock_run, exc):
        # NotADirectoryError and PermissionError were not caught at all, so a
        # bad repo_path propagated out of a governance check as a raw OSError.
        mock_run.side_effect = exc
        result = self.guard.evaluate_from_git("agent-1", self.cfg, "/repo", "main")
        assert result.decision == "HARD_FAIL"
        assert result.error is not None

    @patch("agent_os.integrations.scope_guard.subprocess.run")
    def test_mode_off_still_passes_when_unmeasurable(self, mock_run):
        # Failing closed applies to a check that is meant to run. With mode=off
        # the operator has opted out, so there is nothing to fail closed on.
        mock_run.return_value = subprocess.CompletedProcess(
            args=[], returncode=128, stdout="", stderr="fatal: bad revision",
        )
        cfg = ScopeConfig(max_files=10, max_lines=500, mode="off")
        result = self.guard.evaluate_from_git("agent-1", cfg, "/repo", "main")
        assert result.decision == "PASS"

    @patch("agent_os.integrations.scope_guard.subprocess.run")
    def test_failure_is_recorded_to_the_policy_engine(self, mock_run):
        # The audit trail has to show the block; a governance decision that no
        # one can see afterwards is not much better than no decision.
        mock_run.return_value = subprocess.CompletedProcess(
            args=[], returncode=128, stdout="", stderr="fatal: bad revision",
        )
        engine = MagicMock()
        ScopeGuard(policy_engine=engine).evaluate_from_git(
            "agent-1", self.cfg, "/repo", "main"
        )
        engine.record_event.assert_called_once()
        event = engine.record_event.call_args[0][0]
        assert event["decision"] == "HARD_FAIL"
        assert event["error"] is not None

    @patch("agent_os.integrations.scope_guard.subprocess.run")
    def test_empty_diff_still_passes(self, mock_run):
        # The other side of the fix: a genuinely empty diff is in scope and must
        # not be confused with an unreadable one, since both once produced the
        # same ([], 0, 0).
        mock_run.return_value = subprocess.CompletedProcess(
            args=[], returncode=0, stdout="", stderr="",
        )
        result = self.guard.evaluate_from_git("agent-1", self.cfg, "/repo", "main")
        assert result.decision == "PASS"
        assert result.error is None


# ── _get_diff_stats ───────────────────────────────────────────


class TestGetDiffStats:
    @patch("agent_os.integrations.scope_guard.subprocess.run")
    def test_parses_numstat(self, mock_run):
        mock_run.return_value = subprocess.CompletedProcess(
            args=[], returncode=0,
            stdout="10\t5\tsrc/main.py\n20\t3\tsrc/util.py\n",
        )
        files, ins, dels, error = _get_diff_stats("/repo", "main")
        assert files == ["src/main.py", "src/util.py"]
        assert ins == 30
        assert dels == 8
        assert error is None

    @patch("agent_os.integrations.scope_guard.subprocess.run")
    def test_handles_binary_dashes(self, mock_run):
        mock_run.return_value = subprocess.CompletedProcess(
            args=[], returncode=0,
            stdout="-\t-\timage.png\n",
        )
        files, ins, dels, error = _get_diff_stats("/repo")
        assert files == ["image.png"]
        assert ins == 0
        assert dels == 0
        assert error is None

    @patch("agent_os.integrations.scope_guard.subprocess.run")
    def test_empty_output(self, mock_run):
        mock_run.return_value = subprocess.CompletedProcess(
            args=[], returncode=0, stdout="",
        )
        files, ins, dels, error = _get_diff_stats("/repo")
        assert files == []
        assert ins == 0
        assert dels == 0
        assert error is None

    @patch(
        "agent_os.integrations.scope_guard.subprocess.run",
        side_effect=FileNotFoundError("git not found"),
    )
    def test_handles_missing_git(self, mock_run):
        files, ins, dels, error = _get_diff_stats("/repo")
        assert files == []
        assert ins == 0
        assert dels == 0
        assert error is not None

    @patch("agent_os.integrations.scope_guard.subprocess.run")
    def test_reports_nonzero_exit(self, mock_run):
        mock_run.return_value = subprocess.CompletedProcess(
            args=[], returncode=128, stdout="",
            stderr="fatal: ambiguous argument 'main': unknown revision\n",
        )
        files, ins, dels, error = _get_diff_stats("/repo", "main")
        assert (files, ins, dels) == ([], 0, 0)
        assert error is not None
        assert "128" in error

    @patch("agent_os.integrations.scope_guard.subprocess.run")
    def test_rename_row_is_parsed(self, mock_run):
        # A rename is one tab-separated row with a brace-expanded path; it must
        # not be mistaken for an unparseable row.
        mock_run.return_value = subprocess.CompletedProcess(
            args=[], returncode=0,
            stdout="0\t0\tsrc/{old.py => new.py}\n",
        )
        files, ins, dels, error = _get_diff_stats("/repo")
        assert files == ["src/{old.py => new.py}"]
        assert error is None

    @pytest.mark.parametrize(
        "stdout",
        [
            "10\tsrc/main.py\n",  # too few fields
            "10\t5\n",
            "abc\t5\tsrc/main.py\n",  # non-numeric count
        ],
    )
    @patch("agent_os.integrations.scope_guard.subprocess.run")
    def test_unparseable_row_is_an_error(self, mock_run, stdout):
        # Skipping such a row lowers the totals the limits are compared against,
        # which is the same under-measurement as a failed invocation.
        mock_run.return_value = subprocess.CompletedProcess(
            args=[], returncode=0, stdout=stdout,
        )
        files, ins, dels, error = _get_diff_stats("/repo")
        assert (files, ins, dels) == ([], 0, 0)
        assert error is not None
