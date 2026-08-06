# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""Tests for the external evaluator handoff example."""

from __future__ import annotations

import copy
import importlib.util
from datetime import datetime, timezone
from pathlib import Path

import pytest
from agentmesh.governance.decision_bom import BOMField, BOMFieldCategory, DecisionBOM


MODULE_PATH = Path(__file__).with_name("external_evaluator_handoff.py")
SPEC = importlib.util.spec_from_file_location("external_evaluator_handoff", MODULE_PATH)
if SPEC is None or SPEC.loader is None:
    raise RuntimeError(f"could not load external evaluator handoff from {MODULE_PATH}")
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)


def _decision(*, value: object = 42) -> DecisionBOM:
    observed_at = datetime(2026, 7, 22, 12, 0, tzinfo=timezone.utc)
    return DecisionBOM(
        decision_id="decision-001",
        timestamp=observed_at,
        agent_id="did:mesh:synthetic-agent",
        action_requested="read_inventory",
        outcome="allow",
        fields=[
            BOMField(
                name="latency_ms",
                category=BOMFieldCategory.OUTCOME,
                value=value,
                source="synthetic_trace",
            ),
            BOMField(
                name="private_context",
                category=BOMFieldCategory.CONTEXT,
                value="must-not-cross-by-default",
                source="synthetic_context",
            ),
        ],
        sources_queried=["audit", "trace"],
        completeness_score=0.8,
    )


def test_handoff_is_deterministic_allowlisted_and_read_only() -> None:
    decision = _decision()
    original = copy.deepcopy(decision.to_dict())
    generated_at = datetime(2026, 7, 22, 12, 1, tzinfo=timezone.utc)

    first = MODULE.build_external_evaluation_request(
        [decision],
        generated_at=generated_at,
        allowed_field_names={"latency_ms"},
    )
    second = MODULE.build_external_evaluation_request(
        [decision],
        generated_at=generated_at,
        allowed_field_names={"latency_ms"},
    )

    assert first == second
    assert decision.to_dict() == original
    assert first["request_id"].startswith("eval_")
    assert first["observations"][0]["fields"] == [
        {
            "name": "latency_ms",
            "category": "outcome",
            "value": 42,
            "source": "synthetic_trace",
            "confidence": 1.0,
            "inferred": False,
        }
    ]
    assert first["authority_boundary"] == {
        "read_only": True,
        "source_records_mutated": False,
        "execution_authorized": False,
        "policy_decision_overridden": False,
        "evaluation_result_is_governance_decision": False,
    }


def test_handoff_exports_no_optional_fields_by_default() -> None:
    request = MODULE.build_external_evaluation_request(
        [_decision()],
        generated_at=datetime(2026, 7, 22, 12, 1, tzinfo=timezone.utc),
    )

    assert request["observations"][0]["fields"] == []


def test_handoff_detaches_mutable_allowlisted_values_from_source() -> None:
    decision = _decision(value={"nested": ["original"]})
    request = MODULE.build_external_evaluation_request(
        [decision],
        generated_at=datetime(2026, 7, 22, 12, 1, tzinfo=timezone.utc),
        allowed_field_names={"latency_ms"},
    )

    exported_value = request["observations"][0]["fields"][0]["value"]
    exported_value["nested"].append("request-only")
    assert decision.fields[0].value == {"nested": ["original"]}

    decision.fields[0].value["nested"].append("source-only")
    assert exported_value == {"nested": ["original", "request-only"]}


def test_handoff_rejects_empty_decision_set() -> None:
    with pytest.raises(ValueError, match="at least one Decision BOM"):
        MODULE.build_external_evaluation_request(
            [],
            generated_at=datetime(2026, 7, 22, 12, 1, tzinfo=timezone.utc),
        )


def test_handoff_rejects_timezone_free_timestamps() -> None:
    with pytest.raises(ValueError, match="timestamps must include a timezone"):
        MODULE.build_external_evaluation_request(
            [_decision()],
            generated_at=datetime(2026, 7, 22, 12, 1),
        )


def test_handoff_rejects_non_json_allowlisted_values() -> None:
    with pytest.raises(ValueError, match="not strict-JSON serializable"):
        MODULE.build_external_evaluation_request(
            [_decision(value=object())],
            generated_at=datetime(2026, 7, 22, 12, 1, tzinfo=timezone.utc),
            allowed_field_names={"latency_ms"},
        )
