# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""Keyed provenance certificates for governed learning artifacts."""

from __future__ import annotations

import json
from collections.abc import Mapping
from typing import Any

from agent_os import GovernanceEventSigner

_ALGORITHM = "HMAC-SHA256"
_SIGNATURE_ALGORITHM_FIELD = "agtsignaturealg"
_SIGNATURE_FIELD = "agtsignature"
_PROCESS_KEY = GovernanceEventSigner.generate_key()


def resolve_provenance_key(value: bytes | str | None) -> bytes:
    """Return a validated key, using an ephemeral process key when omitted."""
    if value is None:
        return _PROCESS_KEY
    if isinstance(value, str):
        key = value.encode("utf-8")
    elif isinstance(value, bytes):
        key = value
    else:
        raise TypeError("provenance_key must be bytes, a string, or None")
    if len(key) < 32:
        raise ValueError("provenance_key must contain at least 32 bytes")
    return key


def sign_decision_certificate(
    certificate: Mapping[str, Any],
    key: bytes,
) -> dict[str, Any]:
    unsigned = {name: value for name, value in certificate.items() if name != "provenance"}
    signed = dict(unsigned)
    signed["provenance"] = _sign(key, "decision", unsigned)
    return signed


def verify_decision_certificate(
    certificate: Mapping[str, Any],
    key: bytes,
) -> bool:
    provenance = certificate.get("provenance")
    if not isinstance(provenance, Mapping):
        return False
    unsigned = {name: value for name, value in certificate.items() if name != "provenance"}
    return _verify(key, "decision", unsigned, provenance)


def candidate_payload(policy: Any) -> dict[str, Any]:
    metadata = getattr(policy, "metadata", {}) or {}
    namespace = metadata.get("agent_governance", {}) if isinstance(metadata, Mapping) else {}
    lineage = namespace.get("lineage", {}) if isinstance(namespace, Mapping) else {}
    policy_metadata = (
        {name: value for name, value in metadata.items() if name != "agent_governance"}
        if isinstance(metadata, Mapping)
        else {}
    )
    return {
        "id": policy.id,
        "agent_id": policy.agent_id,
        "task_id": policy.task_id,
        "version": policy.version,
        "actions": [
            {
                "id": action.id,
                "description": getattr(action, "description", None),
                "parameters": dict(getattr(action, "parameters", {}) or {}),
            }
            for action in policy.actions
        ],
        "logits": dict(getattr(policy, "logits", {}) or {}),
        "baseline": getattr(policy, "baseline", None),
        "episodes_seen": getattr(policy, "episodes_seen", None),
        "updates_applied": getattr(policy, "updates_applied", None),
        "metadata": policy_metadata,
        "lineage": dict(lineage) if isinstance(lineage, Mapping) else {},
    }


def candidate_provenance(policy: Any, key: bytes) -> dict[str, str]:
    return _sign(key, "candidate", candidate_payload(policy))


def verify_candidate(policy: Any, key: bytes) -> bool:
    metadata = getattr(policy, "metadata", {}) or {}
    namespace = metadata.get("agent_governance", {}) if isinstance(metadata, Mapping) else {}
    provenance = namespace.get("candidate_provenance") if isinstance(namespace, Mapping) else None
    return isinstance(provenance, Mapping) and _verify(
        key,
        "candidate",
        candidate_payload(policy),
        provenance,
    )


def sign_promotion_receipt(
    policy: Any,
    entry: Mapping[str, Any],
    key: bytes,
) -> dict[str, str]:
    return _sign(key, "promotion", _promotion_payload(policy, entry))


def verify_promotion_receipt(
    policy: Any,
    entry: Mapping[str, Any],
    key: bytes,
) -> bool:
    receipt = entry.get("receipt")
    return isinstance(receipt, Mapping) and _verify(
        key,
        "promotion",
        _promotion_payload(policy, entry),
        receipt,
    )


def _promotion_payload(policy: Any, entry: Mapping[str, Any]) -> dict[str, Any]:
    return {
        "candidate": candidate_payload(policy),
        "stage": entry.get("stage"),
        "status": entry.get("status"),
        "reason": entry.get("reason"),
        "timestamp": entry.get("timestamp"),
        "validation_passed": entry.get("validation_passed"),
    }


def _sign(key: bytes, purpose: str, payload: Mapping[str, Any]) -> dict[str, str]:
    signed = GovernanceEventSigner(key).sign(_envelope(purpose, payload))
    return {
        "algorithm": signed[_SIGNATURE_ALGORITHM_FIELD],
        "signature": signed[_SIGNATURE_FIELD],
    }


def _verify(
    key: bytes,
    purpose: str,
    payload: Mapping[str, Any],
    provenance: Mapping[str, Any],
) -> bool:
    if provenance.get("algorithm") != _ALGORITHM:
        return False
    signature = provenance.get("signature")
    if not isinstance(signature, str):
        return False
    signed = _envelope(purpose, payload)
    signed[_SIGNATURE_ALGORITHM_FIELD] = _ALGORITHM
    signed[_SIGNATURE_FIELD] = signature
    return GovernanceEventSigner(key).verify(signed)


def _envelope(purpose: str, payload: Mapping[str, Any]) -> dict[str, Any]:
    envelope = {"purpose": purpose, "payload": dict(payload)}
    json.dumps(
        envelope,
        allow_nan=False,
        ensure_ascii=True,
        separators=(",", ":"),
        sort_keys=True,
    )
    return envelope


__all__ = [
    "candidate_provenance",
    "resolve_provenance_key",
    "sign_decision_certificate",
    "sign_promotion_receipt",
    "verify_candidate",
    "verify_decision_certificate",
    "verify_promotion_receipt",
]
