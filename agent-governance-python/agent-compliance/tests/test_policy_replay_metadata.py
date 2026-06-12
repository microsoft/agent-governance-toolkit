# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""Tests for resolution_metadata support in policy_test replay engine."""

from __future__ import annotations

import json
import pytest
from pathlib import Path
from unittest.mock import patch, MagicMock

from agent_compliance.policy_test import (
    replay,
    FixtureResult,
    ReplayReport,
    _load_fixtures,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_decision(action: str = "deny", allowed: bool = False, matched_rule: str = "test-rule"):
    """Create a mock PolicyDecision."""
    decision = MagicMock()
    decision.action = action
    decision.allowed = allowed
    decision.matched_rule = matched_rule
    return decision


def _write_fixture(tmp_path: Path, fixtures: list[dict], filename: str = "test.json") -> Path:
    """Write fixture(s) to a JSON file and return the path."""
    p = tmp_path / filename
    p.write_text(json.dumps(fixtures if len(fixtures) > 1 else fixtures[0], indent=2))
    return p


# ---------------------------------------------------------------------------
# FixtureResult with resolution_metadata
# ---------------------------------------------------------------------------

class TestFixtureResultResolutionMetadata:
    def test_default_none(self):
        r = FixtureResult(fixture_id="t1", passed=True, expected_verdict="deny", actual_verdict="deny")
        assert r.resolution_metadata is None

    def test_stored_metadata(self):
        meta = {"rule_id": "deny-dangerous-ddl", "strategy": "deny-overrides"}
        r = FixtureResult(
            fixture_id="t1", passed=True, expected_verdict="deny", actual_verdict="deny",
            resolution_metadata=meta,
        )
        assert r.resolution_metadata == meta


# ---------------------------------------------------------------------------
# ReplayReport.to_dict includes resolution_metadata
# ---------------------------------------------------------------------------

class TestReplayReportSerialization:
    def test_to_dict_includes_resolution_metadata(self):
        meta = {"rule_id": "rule-a", "strategy": "first-match"}
        r = FixtureResult(
            fixture_id="t1", passed=True, expected_verdict="deny", actual_verdict="deny",
            resolution_metadata=meta,
        )
        report = ReplayReport(results=[r])
        d = report.to_dict()
        assert d["results"][0]["resolution_metadata"] == meta

    def test_to_dict_none_metadata(self):
        r = FixtureResult(
            fixture_id="t2", passed=False, expected_verdict="allow", actual_verdict="deny",
        )
        report = ReplayReport(results=[r])
        d = report.to_dict()
        assert d["results"][0]["resolution_metadata"] is None


# ---------------------------------------------------------------------------
# replay() extracts and passes resolution_metadata
# ---------------------------------------------------------------------------

class TestReplayResolutionMetadata:
    @patch("agent_os.policies.evaluator.PolicyEvaluator")
    @patch("agent_os.policies.schema.PolicyDocument")
    def test_metadata_extracted_from_fixture(self, mock_policy_doc, mock_eval_cls, tmp_path):
        """resolution_metadata is extracted from fixture and stored in result."""
        # Setup mocks
        mock_policy_doc.from_yaml.return_value = MagicMock()
        mock_eval = MagicMock()
        mock_eval_cls.return_value = mock_eval
        mock_eval.evaluate.return_value = _make_decision("deny", False, "deny-dangerous-ddl")

        # Write fixture with resolution_metadata
        fixture = {
            "id": "deny-ddl",
            "input": {"action": "sql_execute"},
            "expected_verdict": "deny",
            "expected_rule": "deny-dangerous-ddl",
            "resolution_metadata": {
                "rule_id": "deny-dangerous-ddl",
                "strategy": "deny-overrides",
            },
        }
        policy_path = tmp_path / "policy.yaml"
        policy_path.write_text("version: '1.0'\nname: test\nrules: []\n")
        fixture_path = _write_fixture(tmp_path / "fixtures", [fixture])

        report = replay(policy_path, fixture_path)
        assert report.total == 1
        assert report.results[0].passed is True
        assert report.results[0].resolution_metadata["strategy"] == "deny-overrides"

    @patch("agent_os.policies.evaluator.PolicyEvaluator")
    @patch("agent_os.policies.schema.PolicyDocument")
    def test_rule_id_mismatch_causes_fail(self, mock_policy_doc, mock_eval_cls, tmp_path):
        """resolution_metadata.rule_id mismatching actual_rule causes failure."""
        mock_policy_doc.from_yaml.return_value = MagicMock()
        mock_eval = MagicMock()
        mock_eval_cls.return_value = mock_eval
        # Engine returns a different rule than what metadata expects
        mock_eval.evaluate.return_value = _make_decision("deny", False, "other-rule")

        fixture = {
            "id": "rule-id-mismatch",
            "input": {"action": "sql_execute"},
            "expected_verdict": "deny",
            "resolution_metadata": {
                "rule_id": "deny-dangerous-ddl",
                "strategy": "deny-overrides",
            },
        }
        policy_path = tmp_path / "policy.yaml"
        policy_path.write_text("version: '1.0'\nname: test\nrules: []\n")
        fixture_path = _write_fixture(tmp_path / "fixtures", [fixture])

        report = replay(policy_path, fixture_path)
        assert report.total == 1
        assert report.results[0].passed is False

    @patch("agent_os.policies.evaluator.PolicyEvaluator")
    @patch("agent_os.policies.schema.PolicyDocument")
    def test_strategy_is_not_validated(self, mock_policy_doc, mock_eval_cls, tmp_path):
        """resolution_metadata.strategy is informational only — wrong value doesn't fail."""
        mock_policy_doc.from_yaml.return_value = MagicMock()
        mock_eval = MagicMock()
        mock_eval_cls.return_value = mock_eval
        mock_eval.evaluate.return_value = _make_decision("deny", False, "deny-dangerous-ddl")

        fixture = {
            "id": "strategy-info-only",
            "input": {"action": "sql_execute"},
            "expected_verdict": "deny",
            "expected_rule": "deny-dangerous-ddl",
            "resolution_metadata": {
                "rule_id": "deny-dangerous-ddl",
                "strategy": "wrong-strategy-value",
            },
        }
        policy_path = tmp_path / "policy.yaml"
        policy_path.write_text("version: '1.0'\nname: test\nrules: []\n")
        fixture_path = _write_fixture(tmp_path / "fixtures", [fixture])

        report = replay(policy_path, fixture_path)
        assert report.results[0].passed is True  # strategy not validated

    @patch("agent_os.policies.evaluator.PolicyEvaluator")
    @patch("agent_os.policies.schema.PolicyDocument")
    def test_no_metadata_still_works(self, mock_policy_doc, mock_eval_cls, tmp_path):
        """Fixture without resolution_metadata still works normally."""
        mock_policy_doc.from_yaml.return_value = MagicMock()
        mock_eval = MagicMock()
        mock_eval_cls.return_value = mock_eval
        mock_eval.evaluate.return_value = _make_decision("deny", False, "test-rule")

        fixture = {
            "id": "no-metadata",
            "input": {"action": "sql_execute"},
            "expected_verdict": "deny",
        }
        policy_path = tmp_path / "policy.yaml"
        policy_path.write_text("version: '1.0'\nname: test\nrules: []\n")
        fixture_path = _write_fixture(tmp_path / "fixtures", [fixture])

        report = replay(policy_path, fixture_path)
        assert report.results[0].passed is True
        assert report.results[0].resolution_metadata is None


# ---------------------------------------------------------------------------
# _load_fixtures preserves resolution_metadata
# ---------------------------------------------------------------------------

class TestLoadFixturesMetadata:
    def test_metadata_preserved_in_load(self, tmp_path):
        """_load_fixtures keeps resolution_metadata from JSON."""
        fixture = {
            "id": "load-test",
            "input": {"action": "test"},
            "expected_verdict": "deny",
            "resolution_metadata": {"rule_id": "r1", "strategy": "deny-overrides"},
        }
        p = tmp_path / "f.json"
        p.write_text(json.dumps(fixture))
        loaded = _load_fixtures(tmp_path)
        assert loaded[0]["resolution_metadata"]["strategy"] == "deny-overrides"
