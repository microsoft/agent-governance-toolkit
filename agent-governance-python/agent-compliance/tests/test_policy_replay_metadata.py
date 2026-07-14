# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""Tests for native replay metadata handling."""

from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import patch

import agt.policies as policies
from agt.policies import PolicyEvaluation

from agent_compliance.policy_test import FixtureResult, ReplayReport, _load_fixtures, replay


class _Runtime:
    def __init__(self, reason_code: str) -> None:
        self.reason_code = reason_code

    def evaluate(self, intervention_point: str, snapshot: dict) -> PolicyEvaluation:
        return PolicyEvaluation(
            verdict="deny",
            reason_code=self.reason_code,
            intervention_point=intervention_point,
        )

    def close(self) -> None:
        pass


def _write_fixture(tmp_path: Path, fixture: dict) -> Path:
    path = tmp_path / "fixtures.json"
    path.write_text(json.dumps(fixture), encoding="utf-8")
    return path


def test_report_serializes_resolution_metadata() -> None:
    result = FixtureResult(
        fixture_id="one",
        passed=True,
        expected_verdict="deny",
        actual_verdict="deny",
        resolution_metadata={"rule_id": "rule-a"},
    )
    assert ReplayReport([result]).to_dict()["results"][0]["resolution_metadata"] == {
        "rule_id": "rule-a"
    }


def test_replay_preserves_metadata_without_inventing_rule_identity(
    tmp_path: Path,
) -> None:
    manifest = tmp_path / "manifest.yaml"
    manifest.write_text("acs_version: '1.0'\n", encoding="utf-8")
    fixture = _write_fixture(
        tmp_path,
        {
            "id": "deny-ddl",
            "input": {"tool": "sql_execute"},
            "expected_verdict": "deny",
            "resolution_metadata": {"rule_id": "policy:deny-dangerous-ddl"},
        },
    )
    class RuntimeFactory:
        @staticmethod
        def from_manifest(path):
            return _Runtime("policy:deny-dangerous-ddl")

    with patch.dict(vars(policies), {"AgtRuntime": RuntimeFactory}):
        report = replay(manifest, fixture)
    assert report.ok
    assert report.results[0].resolution_metadata == {
        "rule_id": "policy:deny-dangerous-ddl"
    }


def test_load_fixtures_preserves_metadata(tmp_path: Path) -> None:
    _write_fixture(
        tmp_path,
        {
            "id": "load",
            "input": {},
            "expected_verdict": "deny",
            "resolution_metadata": {"rule_id": "r1"},
        },
    )
    assert _load_fixtures(tmp_path)[0]["resolution_metadata"] == {"rule_id": "r1"}
