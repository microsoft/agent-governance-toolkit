# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""AGT v5 evaluation result.

:class:`EvaluationResult` is the v5 successor to
``agent_os.policies.decision.PolicyCheckResult``. It keeps the v4
``PolicyCheckResult`` field surface for back-compat callers (``allowed``,
``category``, ``matched_rule``, ``public_message``, ``detail``,
``reason``, ``audit_entry``) and adds the AGT-side fields produced by
the ACS engine per ``policy-engine/spec/SPECIFICATION-AGT-DELTA.md``
D1 (the bisected ``transform`` verdict and its payload) and D1.4 (the
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

from pydantic import BaseModel, ConfigDict, Field

Verdict = Literal["allow", "warn", "deny", "escalate", "transform"]

# AGT D1 / D1.4: the v5 verdicts the engine returns. ``escalate`` and
# ``transform`` map to specific v4 ViolationCategory / audit shapes via
# to_v4_check_result.
_PERMITTING_VERDICTS = frozenset({"allow", "warn", "transform"})


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

    def is_allowed(self) -> bool:
        """True for verdicts that permit the action (``allow``/``warn``/``transform``).

        Mirrors the v4 ``PolicyCheckResult.allowed`` boolean but reads
        the v5 ``verdict`` field so the two stay in sync even when a
        caller constructs the result with only the v5 verdict set.
        """
        return self.verdict in _PERMITTING_VERDICTS

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

        reason = self.reason or (self.message if not self.is_allowed() else "")
        return PolicyCheckResult(
            allowed=self.is_allowed(),
            action=action_map[self.verdict],
            category=category,
            matched_rule=self.matched_rule,
            public_message=self.public_message,
            detail=self.detail,
            reason=reason,
            audit_entry=audit_entry,
        )


__all__ = ["EvaluationResult", "Verdict"]
