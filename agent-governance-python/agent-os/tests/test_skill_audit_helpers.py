# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""Tests for shared skill-aware audit helpers in BaseIntegration."""

from __future__ import annotations

import json
from datetime import datetime
from typing import Any

from agent_os.integrations.base import BaseIntegration, GovernanceEventType


class _ConcreteIntegration(BaseIntegration):
    def wrap(self, agent: Any) -> Any:
        return agent

    def unwrap(self, governed_agent: Any) -> Any:
        return governed_agent


def test_build_skill_audit_fields_defaults_are_nullable() -> None:
    integration = _ConcreteIntegration()

    fields = integration.build_skill_audit_fields()

    assert fields == {
        "skill_name": None,
        "skill_origin": None,
        "provenance_source_trust": None,
        "context_hash_before": None,
        "context_hash_after": None,
    }


def test_extract_skill_metadata_from_trusted_source_only() -> None:
    integration = _ConcreteIntegration()
    trusted = integration.trusted_skill_metadata_source(
        skill_name="finance_skill",
        skill_origin="catalog",
    )
    assert trusted is not None

    fields = integration.build_skill_audit_fields(
        trusted_sources=(trusted,),
        context_before={"x": 1},
    )

    assert fields["skill_name"] == "finance_skill"
    assert fields["skill_origin"] == "catalog"
    assert fields["provenance_source_trust"] == "trusted"
    assert fields["context_hash_before"] is not None
    assert fields["context_hash_after"] is None


def test_untrusted_payload_spoof_is_ignored() -> None:
    integration = _ConcreteIntegration()

    fields = integration.build_skill_audit_fields(
        context_before={
            "skill_name": "malicious_skill",
            "metadata": {"skill_origin": "attacker"},
        },
    )

    assert fields["skill_name"] is None
    assert fields["skill_origin"] is None
    assert fields["provenance_source_trust"] is None


def test_context_hash_is_stable_for_same_value() -> None:
    integration = _ConcreteIntegration()

    left = integration.hash_context({"b": 2, "a": 1})
    right = integration.hash_context({"a": 1, "b": 2})

    assert left is not None
    assert left == right


def test_context_hash_stable_for_nested_dict_key_ordering() -> None:
    integration = _ConcreteIntegration()

    left = integration.hash_context(
        {"outer": {"z": 2, "a": 1}, "items": [{"b": 2, "a": 1}]}
    )
    right = integration.hash_context(
        {"items": [{"a": 1, "b": 2}], "outer": {"a": 1, "z": 2}}
    )

    assert left is not None
    assert left == right


def test_context_hash_returns_none_for_non_serializable_object() -> None:
    integration = _ConcreteIntegration()

    class _NonSerializable:
        pass

    assert integration.hash_context(_NonSerializable()) is None


def test_emit_skill_audit_event_is_json_serializable() -> None:
    integration = _ConcreteIntegration()
    captured: list[dict[str, Any]] = []
    integration.on(GovernanceEventType.POLICY_CHECK, captured.append)
    trusted = integration.trusted_skill_metadata_source(skill_name="search_skill")
    assert trusted is not None

    payload = integration.emit_skill_audit_event(
        GovernanceEventType.POLICY_CHECK,
        agent_id="agent-1",
        action="tool_call",
        trusted_sources=(trusted,),
        default_origin="langchain",
        context_before={"query": "hello"},
    )

    assert payload["skill_name"] == "search_skill"
    assert payload["skill_origin"] == "langchain"
    assert payload["provenance_source_trust"] == "trusted"
    assert payload["context_hash_before"] is not None
    assert payload["context_hash_after"] is None
    assert captured and captured[-1]["skill_name"] == "search_skill"
    assert datetime.fromisoformat(payload["timestamp"]).tzinfo is not None

    # Backward-compatible serialization path: nullable additive fields.
    json.dumps(payload)


def test_trusted_sources_from_attrs_filters_missing_metadata() -> None:
    integration = _ConcreteIntegration()

    class _WithAttrs:
        skill_name = "planner"
        skill_origin = "catalog"

    class _WithoutAttrs:
        pass

    trusted_sources = integration.trusted_sources_from_attrs(
        _WithAttrs(),
        _WithoutAttrs(),
    )

    assert len(trusted_sources) == 1
    assert trusted_sources[0].skill_name == "planner"
    assert trusted_sources[0].skill_origin == "catalog"


def test_trusted_sources_filters_none_values() -> None:
    integration = _ConcreteIntegration()
    trusted = integration.trusted_skill_metadata_source(skill_name="router")

    trusted_sources = integration.trusted_sources(None, trusted)

    assert trusted is not None
    assert trusted_sources == (trusted,)
