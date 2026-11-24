"""Fail-closed verification of Parmana execution trust records.

The verifier is offline. It makes no network calls and trusts only the keys in
the trust document that the caller passes in.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from parmana_verifier import parse_trust_policy, verify_execution_trust_record


@dataclass(frozen=True)
class RecordVerdict:
    """The outcome of one verification. ``allowed`` is True only for a valid record."""

    allowed: bool
    coverage: str | None
    errors: tuple[str, ...]


def verify_record(record: Any, trust_document: Any) -> RecordVerdict:
    """Return whether ``record`` verifies against the keys in ``trust_document``.

    Any malformed input, or any exception raised while verifying, returns a
    denial rather than an error, so a workflow never proceeds on a failed check.
    """
    try:
        policy = parse_trust_policy(trust_document)
    except ValueError as exc:
        return RecordVerdict(
            allowed=False, coverage=None, errors=(f"trust set rejected: {exc}",)
        )

    try:
        result = verify_execution_trust_record(
            record, policy.keys, policy.hybrid_required_from
        )
    except Exception as exc:  # noqa: BLE001 - a failed check must deny, never raise into the workflow.
        return RecordVerdict(
            allowed=False, coverage=None, errors=(f"verification failed: {exc!r}",)
        )

    return RecordVerdict(
        allowed=result["valid"] is True,
        coverage=result.get("coverage"),
        errors=tuple(result.get("errors", [])),
    )
