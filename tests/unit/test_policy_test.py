# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""Tests for the agt test replay engine."""

from __future__ import annotations

import json
import textwrap
from pathlib import Path

import pytest

from agent_compliance.policy_test import (
    FixtureResult,
    ReplayReport,
    _load_fixtures,
    replay,
)


# ── Helpers ────────────────────────────────────────────────────────────


def _write_policy(tmp_path: Path, *, default_action: str = "deny") -> Path:
    """Write a minimal native ACS manifest and Rego bundle."""
    bundle_dir = tmp_path / "bundle"
    bundle_dir.mkdir()
    bundle = bundle_dir / "policy.rego"
    bundle.write_text(
        textwrap.dedent(
            f"""\
            package test.policy

            import rego.v1

            action := object.get(input.policy_target.value, "action", "")

            result := {{"decision": "allow", "reason": "allow-reads"}} if action == "read"
            result := {{"decision": "deny", "reason": "deny-writes", "message": "Writes are blocked"}} if action == "write"
            result := {{"decision": "warn", "reason": "audit-list"}} if action == "list"
            result := {{"decision": "{default_action}", "reason": "default-{default_action}"}} if not action in {{"read", "write", "list"}}
            """
        ),
        encoding="utf-8",
    )
    policy = tmp_path / "policy.yaml"
    policy.write_text(
        textwrap.dedent(
            """\
            agent_control_specification_version: 0.3.1-beta
            metadata:
              name: test-policy
              version: "1.0"
            extends: []
            policies:
              test_policy:
                type: rego
                bundle: bundle
                query: data.test.policy.result
            intervention_points:
              input:
                policy_target: $.input.body
                policy:
                  id: test_policy
            """
        ),
        encoding="utf-8",
    )
    return policy


def _write_fixtures_json(tmp_path: Path, fixtures: list[dict]) -> Path:
    """Write a fixture JSON file."""
    path = tmp_path / "fixtures.json"
    path.write_text(json.dumps(fixtures, indent=2))
    return path


def _write_fixtures_yaml(tmp_path: Path, content: str) -> Path:
    """Write a fixture YAML file."""
    path = tmp_path / "fixtures.yaml"
    path.write_text(content)
    return path


# ── Fixture loading ────────────────────────────────────────────────────


class TestLoadFixtures:
    def test_load_json_array(self, tmp_path: Path) -> None:
        fixtures = [
            {"id": "f1", "input": {"action": "read"}, "expected_verdict": "allow"},
            {"id": "f2", "input": {"action": "write"}, "expected_verdict": "deny"},
        ]
        path = _write_fixtures_json(tmp_path, fixtures)
        loaded = _load_fixtures(path)
        assert len(loaded) == 2
        assert loaded[0]["id"] == "f1"

    def test_load_yaml_scenarios(self, tmp_path: Path) -> None:
        content = textwrap.dedent("""\
        scenarios:
          - name: read-ok
            context: {action: read}
            expected_action: allow
          - name: write-blocked
            context: {action: write}
            expected_action: deny
        """)
        path = _write_fixtures_yaml(tmp_path, content)
        loaded = _load_fixtures(path)
        assert len(loaded) == 2
        assert loaded[0]["name"] == "read-ok"

    def test_load_directory(self, tmp_path: Path) -> None:
        _write_fixtures_json(
            tmp_path,
            [{"id": "from-json", "input": {"action": "read"}, "expected_verdict": "allow"}],
        )
        (tmp_path / "more.yaml").write_text(
            "scenarios:\n  - name: from-yaml\n    context: {action: write}\n    expected_action: deny\n"
        )
        loaded = _load_fixtures(tmp_path)
        assert len(loaded) == 2

    def test_load_nonexistent_raises(self, tmp_path: Path) -> None:
        with pytest.raises(FileNotFoundError):
            _load_fixtures(tmp_path / "does-not-exist")

    def test_load_empty_dir_raises(self, tmp_path: Path) -> None:
        empty_dir = tmp_path / "empty"
        empty_dir.mkdir()
        with pytest.raises(FileNotFoundError):
            _load_fixtures(empty_dir)


# ── Replay engine ──────────────────────────────────────────────────────


class TestReplay:
    def test_all_pass(self, tmp_path: Path) -> None:
        policy = _write_policy(tmp_path)
        fixtures = _write_fixtures_json(
            tmp_path,
            [
                {"id": "read-ok", "input": {"action": "read"}, "expected_verdict": "allow"},
                {"id": "write-blocked", "input": {"action": "write"}, "expected_verdict": "deny"},
            ],
        )
        report = replay(policy, fixtures)
        assert report.ok
        assert report.total == 2
        assert report.passed == 2
        assert report.failed == 0

    def test_verdict_mismatch(self, tmp_path: Path) -> None:
        policy = _write_policy(tmp_path)
        fixtures = _write_fixtures_json(
            tmp_path,
            [
                # This expects allow but will get deny (default action)
                {"id": "wrong", "input": {"action": "delete"}, "expected_verdict": "allow"},
            ],
        )
        report = replay(policy, fixtures)
        assert not report.ok
        assert report.failed == 1
        mismatch = report.mismatches[0]
        assert mismatch.fixture_id == "wrong"
        assert mismatch.expected_verdict == "allow"
        assert mismatch.actual_verdict == "deny"

    def test_expected_allowed_boolean(self, tmp_path: Path) -> None:
        policy = _write_policy(tmp_path)
        fixtures = _write_fixtures_json(
            tmp_path,
            [
                {"id": "bool-true", "input": {"action": "read"}, "expected_allowed": True},
                {"id": "bool-false", "input": {"action": "write"}, "expected_allowed": False},
            ],
        )
        report = replay(policy, fixtures)
        assert report.ok
        assert report.total == 2

    def test_audit_action(self, tmp_path: Path) -> None:
        policy = _write_policy(tmp_path)
        fixtures = _write_fixtures_json(
            tmp_path,
            [{"id": "audit-ok", "input": {"action": "list"}, "expected_verdict": "warn"}],
        )
        report = replay(policy, fixtures)
        assert report.ok

    def test_default_action(self, tmp_path: Path) -> None:
        policy = _write_policy(tmp_path, default_action="deny")
        fixtures = _write_fixtures_json(
            tmp_path,
            [{"id": "unknown-denied", "input": {"action": "unknown"}, "expected_verdict": "deny"}],
        )
        report = replay(policy, fixtures)
        assert report.ok

    def test_policy_dir(self, tmp_path: Path) -> None:
        policy_dir = tmp_path / "policies"
        policy_dir.mkdir()
        _write_policy(policy_dir)
        fixtures = _write_fixtures_json(
            tmp_path,
            [{"id": "read-ok", "input": {"action": "read"}, "expected_verdict": "allow"}],
        )
        with pytest.raises(FileNotFoundError, match="Manifest path"):
            replay(policy_dir, fixtures)

    def test_fixture_dir(self, tmp_path: Path) -> None:
        policy = _write_policy(tmp_path)
        fixture_dir = tmp_path / "fixtures"
        fixture_dir.mkdir()
        (fixture_dir / "test.json").write_text(
            json.dumps([{"id": "f1", "input": {"action": "read"}, "expected_verdict": "allow"}])
        )
        report = replay(policy, fixture_dir)
        assert report.ok


# ── Report ─────────────────────────────────────────────────────────────


class TestReplayReport:
    def test_to_dict(self) -> None:
        report = ReplayReport(
            results=[
                FixtureResult(
                    fixture_id="f1",
                    passed=True,
                    expected_verdict="allow",
                    actual_verdict="allow",
                ),
                FixtureResult(
                    fixture_id="f2",
                    passed=False,
                    expected_verdict="allow",
                    actual_verdict="deny",
                ),
            ]
        )
        d = report.to_dict()
        assert d["total"] == 2
        assert d["passed"] == 1
        assert d["failed"] == 1
        assert d["ok"] is False

    def test_mismatch_summary(self) -> None:
        result = FixtureResult(
            fixture_id="test",
            passed=False,
            expected_verdict="allow",
            actual_verdict="deny",
        )
        summary = result.mismatch_summary()
        assert "allow" in summary
        assert "deny" in summary


# ── Example fixture files ─────────────────────────────────────────────────


class TestExampleFixtures:
    """Verify the bundled example fixture files replay correctly."""

    _FIXTURES_DIR = (
        Path(__file__).resolve().parent.parent.parent
        / "examples"
        / "policy-templates"
        / "fixtures"
    )
    _POLICY = (
        Path(__file__).resolve().parent.parent.parent
        / "examples"
        / "policy-templates"
        / "general-saas.yaml"
    )

    def test_general_saas_fixtures_exist(self) -> None:
        assert (self._FIXTURES_DIR / "general-saas-fixtures.json").exists()

    def test_sql_agent_fixtures_exist(self) -> None:
        assert (self._FIXTURES_DIR / "sql-agent-fixtures.json").exists()

    def test_k8s_agent_fixtures_exist(self) -> None:
        assert (self._FIXTURES_DIR / "k8s-agent-fixtures.json").exists()

    def test_general_saas_replay(self) -> None:
        report = replay(self._POLICY, self._FIXTURES_DIR / "general-saas-fixtures.json")
        assert report.total > 0
        # All fixtures must pass against the bundled policy
        failed_ids = [r.fixture_id for r in report.mismatches]
        assert failed_ids == [], f"Fixture mismatches: {failed_ids}"

    def test_sql_agent_replay(self) -> None:
        report = replay(self._POLICY, self._FIXTURES_DIR / "sql-agent-fixtures.json")
        assert report.total == 3
        failed_ids = [r.fixture_id for r in report.mismatches]
        assert failed_ids == [], f"Fixture mismatches: {failed_ids}"

    def test_k8s_agent_replay(self) -> None:
        report = replay(self._POLICY, self._FIXTURES_DIR / "k8s-agent-fixtures.json")
        assert report.total == 3
        failed_ids = [r.fixture_id for r in report.mismatches]
        assert failed_ids == [], f"Fixture mismatches: {failed_ids}"

    def test_replay_all_fixture_files(self) -> None:
        """Running replay over the whole fixtures dir must exit cleanly."""
        report = replay(self._POLICY, self._FIXTURES_DIR)
        assert report.total > 0

    def test_ci_exit_code_zero_on_all_pass(self, tmp_path: Path) -> None:
        """Exit code contract: 0 when all fixtures pass."""
        policy = _write_policy(tmp_path)
        fixtures = _write_fixtures_json(
            tmp_path,
            [{"id": "ok", "input": {"action": "read"}, "expected_verdict": "allow"}],
        )
        report = replay(policy, fixtures)
        assert report.ok
        # Callers must map report.ok to sys.exit(0 if ok else 1)
        expected_exit = 0 if report.ok else 1
        assert expected_exit == 0

    def test_ci_exit_code_one_on_failure(self, tmp_path: Path) -> None:
        """Exit code contract: 1 when any fixture fails."""
        policy = _write_policy(tmp_path)
        fixtures = _write_fixtures_json(
            tmp_path,
            [{"id": "bad", "input": {"action": "delete"}, "expected_verdict": "allow"}],
        )
        report = replay(policy, fixtures)
        assert not report.ok
        expected_exit = 0 if report.ok else 1
        assert expected_exit == 1
