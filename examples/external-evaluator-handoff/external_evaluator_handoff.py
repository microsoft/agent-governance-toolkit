# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""Export AGT Decision BOMs to a read-only external-evaluation request.

This example deliberately stops at the interoperability boundary.  It does not
call an evaluator, mutate AGT records, or turn an evaluation result into a
governance decision.
"""

from __future__ import annotations

import hashlib
import json
from collections.abc import Collection, Sequence
from datetime import datetime, timezone
from typing import Any

from agentmesh.governance.decision_bom import BOMField, BOMFieldCategory, DecisionBOM


SCHEMA_VERSION = "0.1"


def _utc_timestamp(value: datetime) -> str:
    """Return an RFC 3339 UTC timestamp, rejecting timezone-free values."""
    if value.tzinfo is None or value.utcoffset() is None:
        raise ValueError("timestamps must include a timezone")
    return value.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")


def _export_field(field: BOMField) -> dict[str, Any]:
    """Export one explicitly allowlisted BOM field with fail-closed JSON checks."""
    try:
        serialized_value = json.dumps(
            field.value,
            allow_nan=False,
            ensure_ascii=False,
            separators=(",", ":"),
            sort_keys=True,
        )
        exported_value = json.loads(serialized_value)
    except (TypeError, ValueError) as exc:
        raise ValueError(
            f"field {field.name!r} is not strict-JSON serializable"
        ) from exc

    return {
        "name": field.name,
        "category": field.category.value,
        "value": exported_value,
        "source": field.source,
        "confidence": field.confidence,
        "inferred": field.inferred,
    }


def build_external_evaluation_request(
    decisions: Sequence[DecisionBOM],
    *,
    generated_at: datetime,
    allowed_field_names: Collection[str] = (),
) -> dict[str, Any]:
    """Build a deterministic, offline request for a downstream evaluator.

    Args:
        decisions: Reconstructed AGT decisions to expose as observations.
        generated_at: Time at which this handoff request was created.  Callers
            must pass a timezone-aware value so replays are unambiguous.
        allowed_field_names: Exact Decision BOM field names permitted to cross
            the boundary.  The default is empty to avoid exporting arbitrary
            policy, context, or trace data by accident.

    Returns:
        A strict-JSON-compatible dictionary.  Its authority boundary is
        intentionally fixed: the downstream evaluator receives observations
        but cannot authorize actions, override policy, or mutate source records.

    Raises:
        ValueError: If no decisions are provided, timestamps are timezone-free,
            or an allowlisted value is not strict-JSON serializable.
    """
    if not decisions:
        raise ValueError("at least one Decision BOM is required")

    generated_at_utc = _utc_timestamp(generated_at)
    allowlist = frozenset(allowed_field_names)
    observations: list[dict[str, Any]] = []

    for decision in decisions:
        fields = [
            _export_field(field) for field in decision.fields if field.name in allowlist
        ]
        observations.append(
            {
                "decision_id": decision.decision_id,
                "observed_at": _utc_timestamp(decision.timestamp),
                "agent_id": decision.agent_id,
                "action_requested": decision.action_requested,
                "governance_outcome": decision.outcome,
                "source_completeness": decision.completeness_score,
                "sources_queried": list(decision.sources_queried),
                "fields": fields,
            }
        )

    request: dict[str, Any] = {
        "schema_version": SCHEMA_VERSION,
        "purpose": "post_execution_external_evaluation",
        "generated_at": generated_at_utc,
        "source": {
            "system": "agent-governance-toolkit",
            "representation": "decision_bom",
            "decision_count": len(observations),
        },
        "observations": observations,
        "authority_boundary": {
            "read_only": True,
            "source_records_mutated": False,
            "execution_authorized": False,
            "policy_decision_overridden": False,
            "evaluation_result_is_governance_decision": False,
        },
    }

    canonical = json.dumps(
        request,
        allow_nan=False,
        ensure_ascii=False,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")
    request["request_id"] = f"eval_{hashlib.sha256(canonical).hexdigest()}"
    return request


def _sample_decisions(now: datetime) -> list[DecisionBOM]:
    """Create synthetic Decision BOMs for the runnable example."""
    return [
        DecisionBOM(
            decision_id="decision-001",
            timestamp=now,
            agent_id="did:mesh:synthetic-agent",
            action_requested="read_inventory",
            outcome="allow",
            fields=[
                BOMField(
                    name="latency_ms",
                    category=BOMFieldCategory.OUTCOME,
                    value=42,
                    source="synthetic_trace",
                ),
                BOMField(
                    name="internal_policy_context",
                    category=BOMFieldCategory.POLICY,
                    value={"rule": "allow-read"},
                    source="synthetic_policy",
                ),
            ],
            sources_queried=["audit", "policy", "trace"],
            completeness_score=0.8,
        )
    ]


def main() -> None:
    """Print one synthetic, offline evaluation handoff request."""
    now = datetime.now(timezone.utc)
    request = build_external_evaluation_request(
        _sample_decisions(now),
        generated_at=now,
        allowed_field_names={"latency_ms"},
    )
    print(json.dumps(request, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
