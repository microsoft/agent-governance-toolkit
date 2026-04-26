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
        mock_stats.return_value = (["a.py", "b.py"], 100, 50)
        guard = ScopeGuard()
        cfg = ScopeConfig(max_files=10, max_lines=500)
        result = guard.evaluate_from_git("agent-1", cfg, "/repo", "main")
        assert result.files_changed == 2
        assert result.lines_changed == 150
        assert result.decision == "PASS"


# ── _get_diff_stats ───────────────────────────────────────────


class TestGetDiffStats:
    @patch("agent_os.integrations.scope_guard.subprocess.run")
    def test_parses_numstat(self, mock_run):
        mock_run.return_value = subprocess.CompletedProcess(
            args=[], returncode=0,
            stdout="10\t5\tsrc/main.py\n20\t3\tsrc/util.py\n",
        )
        files, ins, dels = _get_diff_stats("/repo", "main")
        assert files == ["src/main.py", "src/util.py"]
        assert ins == 30
        assert dels == 8

    @patch("agent_os.integrations.scope_guard.subprocess.run")
    def test_handles_binary_dashes(self, mock_run):
        mock_run.return_value = subprocess.CompletedProcess(
            args=[], returncode=0,
            stdout="-\t-\timage.png\n",
        )
        files, ins, dels = _get_diff_stats("/repo")
        assert files == ["image.png"]
        assert ins == 0
        assert dels == 0

    @patch("agent_os.integrations.scope_guard.subprocess.run")
    def test_empty_output(self, mock_run):
        mock_run.return_value = subprocess.CompletedProcess(
            args=[], returncode=0, stdout="",
        )
        files, ins, dels = _get_diff_stats("/repo")
        assert files == []
        assert ins == 0
        assert dels == 0

    @patch(
        "agent_os.integrations.scope_guard.subprocess.run",
        side_effect=FileNotFoundError("git not found"),
    )
    def test_handles_missing_git(self, mock_run):
        files, ins, dels = _get_diff_stats("/repo")
        assert files == []
        assert ins == 0
        assert dels == 0
