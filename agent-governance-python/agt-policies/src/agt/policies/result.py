# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""Native AGT policy evaluation contracts."""

from __future__ import annotations

from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator

Verdict = Literal["allow", "warn", "deny", "escalate", "transform"]
_PERMITTING_VERDICTS = frozenset({"allow", "warn", "transform"})


class TransformResult(BaseModel):
    """Materialized transform returned by ACS."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    path: str
    value: Any
    applied_value: Any | None = None


class EvidenceResult(BaseModel):
    """Opaque proof artifact and verification pointers returned by ACS."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    artefact: Any
    verification_pointers: dict[str, Any] = Field(default_factory=dict)


class PolicyAuditRecord(BaseModel):
    """Versioned restricted audit envelope for a native evaluation."""

    model_config = ConfigDict(extra="forbid", frozen=True, populate_by_name=True)

    schema_version: Literal["agt.policy_evaluation.v1"] = Field(
        default="agt.policy_evaluation.v1",
        alias="schema",
    )
    verdict: Verdict
    reason_code: str = ""
    message: str = ""
    intervention_point: str = ""
    transform: TransformResult | None = None
    evidence: EvidenceResult | None = None
    result_labels: tuple[str, ...] = ()
    input_identity: str | None = None
    enforced_identity: str | None = None
    approval: dict[str, Any] = Field(default_factory=dict)


class PolicyEvaluation(BaseModel):
    """Immutable result from one ACS intervention-point evaluation."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    verdict: Verdict
    reason_code: str = ""
    message: str = ""
    intervention_point: str = ""
    transform: TransformResult | None = None
    evidence: EvidenceResult | None = None
    result_labels: tuple[str, ...] = ()
    input_identity: str | None = None
    enforced_identity: str | None = None
    approval: dict[str, Any] = Field(default_factory=dict)

    @field_validator("reason_code", mode="before")
    @classmethod
    def namespace_reason_code(cls, value: Any) -> str:
        reason = str(value or "")
        if not reason or ":" in reason:
            return reason
        return f"policy:{reason}"

    def is_allowed(self) -> bool:
        """Return whether the host may continue without approval."""

        return self.verdict in _PERMITTING_VERDICTS

    def audit_record(self) -> dict[str, Any]:
        """Return the stable restricted audit payload."""

        return PolicyAuditRecord(
            verdict=self.verdict,
            reason_code=self.reason_code,
            message=self.message,
            intervention_point=self.intervention_point,
            transform=self.transform,
            evidence=self.evidence,
            result_labels=self.result_labels,
            input_identity=self.input_identity,
            enforced_identity=self.enforced_identity,
            approval=self.approval,
        ).model_dump(mode="json", by_alias=True, exclude_none=True)

    def public_error_message(self) -> str:
        """Return a stable message that does not expose policy or user detail."""

        if self.verdict == "escalate":
            return "Request requires policy approval."
        if self.reason_code.startswith("runtime_error:"):
            return "Policy evaluation failed closed."
        return "Request blocked by policy."


__all__ = [
    "EvidenceResult",
    "PolicyAuditRecord",
    "PolicyEvaluation",
    "TransformResult",
    "Verdict",
]
