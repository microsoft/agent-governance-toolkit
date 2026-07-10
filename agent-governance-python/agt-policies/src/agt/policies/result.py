# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""AGT v5 evaluation result.

:class:`EvaluationResult` is the v5 successor to
``agent_os.policies.decision.PolicyCheckResult``. It keeps the v4
``PolicyCheckResult`` field surface for back-compat callers (``allowed``,
``category``, ``matched_rule``, ``public_message``, ``detail``,
``reason``, ``audit_entry``) and adds the AGT-side fields produced by
the ACS engine per ``policy-engine/spec/SPECIFICATION.md``
§14 (the ``transform`` verdict and its payload) and §13.1 (the
``input_identity`` / ``enforced_identity`` pair).

Callers ride the v5 surface (``verdict``, ``transform``, ``evidence``,
``input_identity``, ``enforced_identity``) directly; legacy callers can
unwrap to a v4 ``PolicyCheckResult`` via :meth:`EvaluationResult.to_v4_check_result`
for the deprecation window. The legacy unwrap is gated by a try-import
on ``agent_os`` so :mod:`agt.policies.result` stays importable without
the v4 package installed.
"""

from __future__ import annotations

from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator

Verdict = Literal["allow", "warn", "deny", "escalate", "transform"]

# AGT D1 / D1.4: the v5 verdicts the engine returns. ``escalate`` and
# ``transform`` map to specific v4 ViolationCategory / audit shapes via
# to_v4_check_result.
_PERMITTING_VERDICTS = frozenset({"allow", "warn", "transform"})

# Generic engine fallback message that carries no host-actionable detail.
_GENERIC_BLOCK_MESSAGE = "Request blocked by Agent Control Specification."


class TransformResult(BaseModel):
    """Materialized transform returned by ACS."""

    model_config = ConfigDict(extra="forbid")

    path: str
    value: Any
    applied_value: Any | None = None


class EvidenceResult(BaseModel):
    """Opaque proof artifact and verification pointers returned by ACS."""

    model_config = ConfigDict(extra="forbid")

    artefact: Any
    verification_pointers: dict[str, Any] = Field(default_factory=dict)


class PolicyAuditRecord(BaseModel):
    """Versioned restricted audit envelope for a native evaluation."""

    model_config = ConfigDict(extra="forbid", frozen=True, populate_by_name=True)

    schema_version: Literal["agt.policy_evaluation.v1"] = Field(
        default="agt.policy_evaluation.v1", alias="schema"
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


class PolicyEvaluation(BaseModel):
    """Native v5 result for one intervention-point evaluation.

    The ACS result does not currently expose ``policy_id`` or ``rule_id``.
    Callers must not infer either value from ``reason_code``. Policy identity
    remains telemetry metadata until the engine carries it on
    ``InterventionPointResult``.
    """

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
        """Return the versioned v5 audit payload for this evaluation."""
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
        ).model_dump(mode="json", by_alias=True, exclude_none=True)

    def public_error_message(self) -> str:
        """Return a stable message that does not expose policy or user detail."""
        if self.verdict == "escalate":
            return "Request requires policy approval."
        if self.reason_code.startswith("runtime_error:"):
            return "Policy evaluation failed closed."
        return "Request blocked by policy."


def _friendly_public_message(reason: str, verdict: str, original: str) -> str:
    """Return a host-friendly ``public_message`` for a blocking verdict.

    The v5 ACS runtime surfaces terse wire reasons (``runtime_error:tool_unknown``,
    ``blocked_pattern_input``, ``budget_tool_calls_exceeded``) or a generic
    fallback. v4 hosts and their tests match on human-readable phrases, so we
    derive one from the reason/verdict while preserving any useful detail the
    engine attached. ``original`` is returned unchanged when no mapping applies
    so bespoke messages are never clobbered.
    """
    r = (reason or "").lower()
    detail = "" if original.strip() == _GENERIC_BLOCK_MESSAGE else original.strip()

    if "tool_unknown" in r or "tool_not_allowed" in r:
        base = "Tool not allowed; not in the allowed list"
    elif "blocked_pattern" in r:
        base = "Blocked pattern detected; request blocked"
    elif "budget_tool_calls" in r or "max_tool_calls" in r:
        base = "Tool call limit exceeded"
    elif "budget_tokens" in r or "max_tokens" in r:
        base = "Token budget exceeded"
    elif verdict == "escalate" or "human_approval" in r:
        base = "Requires human approval"
    else:
        return original

    return f"{base}: {detail}" if detail else base


class EvaluationResult(BaseModel):
    """Result of one intervention-point evaluation.

    The v4 fields are preserved verbatim so adapters that still consume
    :class:`agent_os.policies.decision.PolicyCheckResult` keep working
    through :meth:`to_v4_check_result`. The new AGT-side fields are:

    - ``verdict``: the five-state ACS+AGT decision (``allow`` | ``warn`` |
      ``deny`` | ``escalate`` | ``transform``) per AGT-DELTA D1.
    - ``transform``: when ``verdict == "transform"`` carries the AGT D1.1
      ``{path, value}`` replacement payload that was applied to the
      policy target. ``None`` for every other verdict.
    - ``evidence``: AGT D2 opaque proof artefact + verification pointers
      attached to the verdict by a high-assurance dispatcher.
    - ``input_identity`` / ``enforced_identity``: AGT D1.4 bisected
      action identities. Equal for non-transform verdicts.
    """

    model_config = ConfigDict(extra="forbid")

    # ── v4 back-compat surface ────────────────────────────────────
    allowed: bool = True
    category: str | None = None
    matched_rule: str | None = None
    public_message: str = ""
    detail: str = ""
    reason: str = ""
    audit_entry: dict[str, Any] = Field(default_factory=dict)

    # ── v5 verdict surface ────────────────────────────────────────
    verdict: Verdict = "allow"
    transform: dict[str, Any] | None = None
    evidence: dict[str, Any] | None = None
    input_identity: str | None = None
    enforced_identity: str | None = None
    message: str = ""

    @classmethod
    def from_native(cls, result: PolicyEvaluation) -> "EvaluationResult":
        """Build the temporary bridge result from the native contract."""
        reason = result.reason_code
        if reason.startswith("policy:"):
            reason = reason.removeprefix("policy:")
        audit = result.audit_record()
        audit["reason"] = reason
        return cls(
            allowed=result.is_allowed(),
            public_message=result.message,
            detail=result.message,
            reason=reason,
            audit_entry=audit,
            verdict=result.verdict,
            transform=(
                result.transform.model_dump(mode="python", exclude_none=True)
                if result.transform is not None
                else None
            ),
            evidence=(
                result.evidence.model_dump(mode="python", exclude_none=True)
                if result.evidence is not None
                else None
            ),
            input_identity=result.input_identity,
            enforced_identity=result.enforced_identity,
            message=result.message,
        )

    def is_allowed(self) -> bool:
        """True for verdicts that permit the action (``allow``/``warn``/``transform``).

        Mirrors the v4 ``PolicyCheckResult.allowed`` boolean but reads
        the v5 ``verdict`` field so the two stay in sync even when a
        caller constructs the result with only the v5 verdict set.
        """
        return self.verdict in _PERMITTING_VERDICTS

    def to_native(self) -> PolicyEvaluation:
        """Return the native v5 contract without compatibility fields."""
        transform = (
            TransformResult.model_validate(self.transform)
            if self.transform is not None
            else None
        )
        evidence = (
            EvidenceResult.model_validate(self.evidence)
            if self.evidence is not None
            else None
        )
        raw_labels = self.audit_entry.get("result_labels", ())
        labels = (
            tuple(str(label) for label in raw_labels)
            if isinstance(raw_labels, (list, tuple))
            else ()
        )
        return PolicyEvaluation(
            verdict=self.verdict,
            reason_code=self.reason,
            message=self.message,
            intervention_point=str(
                self.audit_entry.get("intervention_point", "")
            ),
            transform=transform,
            evidence=evidence,
            result_labels=labels,
            input_identity=self.input_identity,
            enforced_identity=self.enforced_identity,
        )

    def to_v4_check_result(self) -> Any:
        """Return a v4 ``PolicyCheckResult`` populated from this result.

        Only importable when ``agent_os`` is installed. Hosts that have
        not yet migrated their dispatchers can keep consuming the v4
        Pydantic model while the engine is the new ACS runtime. Raises
        ``ImportError`` when the v4 package is not available.

        The mapping mirrors the verdict translation table in
        ``architecture-exploration.md`` Q3:

        - ``allow`` -> ``PolicyCheckResult(allowed=True, action="allow")``
        - ``warn`` -> ``allowed=True, action="audit"``
          (v4 used ``AUDIT`` for permit+log)
        - ``transform`` -> ``allowed=True, action="allow"`` with the
          transform payload mirrored into ``audit_entry["transform"]``
        - ``deny`` -> ``allowed=False, action="deny"``
        - ``escalate`` -> ``allowed=False, action="block"``,
          ``category=ViolationCategory.HUMAN_APPROVAL`` when v4 is
          available.
        """
        try:
            from agent_os.policies.decision import PolicyCheckResult, ViolationCategory
        except ImportError as exc:  # pragma: no cover - depends on v4 install
            raise ImportError(
                "to_v4_check_result requires the v4 agent_os package. "
                "Install agent_os to use the back-compat wrapper, or call the "
                "v5 EvaluationResult fields directly."
            ) from exc

        action_map: dict[str, str] = {
            "allow": "allow",
            "warn": "audit",
            "deny": "deny",
            "escalate": "block",
            "transform": "allow",
        }
        category: ViolationCategory | None = None
        if self.category is not None:
            try:
                category = ViolationCategory(self.category)
            except ValueError:
                category = None
        if category is None and self.verdict == "escalate":
            category = ViolationCategory.HUMAN_APPROVAL

        audit_entry = dict(self.audit_entry)
        if self.transform is not None:
            audit_entry.setdefault("transform", dict(self.transform))
        if self.evidence is not None:
            audit_entry.setdefault("evidence", dict(self.evidence))
        if self.input_identity is not None:
            audit_entry.setdefault("input_identity", self.input_identity)
        if self.enforced_identity is not None:
            audit_entry.setdefault("enforced_identity", self.enforced_identity)
        audit_entry.setdefault("verdict", self.verdict)
        if self.reason:
            audit_entry.setdefault("reason", self.reason)

        reason = self.reason or (self.message if not self.is_allowed() else "")
        public_message = self.public_message
        if not self.is_allowed():
            public_message = _friendly_public_message(
                reason, self.verdict, self.public_message
            )
        return PolicyCheckResult(
            allowed=self.is_allowed(),
            action=action_map[self.verdict],
            category=category,
            matched_rule=self.matched_rule,
            public_message=public_message,
            detail=self.detail,
            reason=reason,
            audit_entry=audit_entry,
        )


__all__ = [
    "EvaluationResult",
    "EvidenceResult",
    "PolicyAuditRecord",
    "PolicyEvaluation",
    "TransformResult",
    "Verdict",
]
