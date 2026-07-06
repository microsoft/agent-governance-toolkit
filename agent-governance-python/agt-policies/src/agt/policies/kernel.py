# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""Wire one ACS decision into the AGT kernel (trust, audit, rings).

An ACS intervention point produces a verdict, but the AGT kernel primitives that
should react to it are disconnected islands, each with its own types: trust
scoring (``agentmesh.trust_types.TrustTracker``), governance audit events
(``agent_os.event_sink.GovernanceEvent`` / ``GovernanceEventProcessor``) and
execution rings (``hypervisor.rings.RingEnforcer`` /
``hypervisor.rings.ActionClassifier``). Without glue a host has to feed the ACS
decision into every subsystem by hand and reconcile the two trust scales
(agentmesh 0..1 reputation vs hypervisor ``eff_score``) itself.

:class:`KernelBridge` is that glue. It is a composite, fail closed governance
gate. Given one :class:`KernelDecision` it drives trust, emits one governance
event and evaluates the execution ring, then returns a single
:class:`KernelOutcome` whose ``proceeds`` flag is the AND of every independent
gate.

``proceeds`` is true only when

- the ACS decision permits execution (``allow``, ``warn`` or ``transform``), and
- the execution ring permits the action for the agent's current ring
  (``RingEnforcer.check`` on ``ActionDescriptor.required_ring``), and
- when ``strict_audit`` is set, the governance event was accepted for delivery
  (``AuditEmissionResult.ACCEPTED``), and
- no injected dependency raised.

Any missing decision, unrecognized decision, dependency exception or (under
strict audit) undelivered event drives ``proceeds`` false. The gate never
flips a block into an allow.

The bridge owns only neutral primitives and local Protocols. It imports none of
``agentmesh``, ``agent_os`` or ``hypervisor``. The host injects concrete
implementations, so no import cycle forms with
``agent_os.integrations._v5_runtime_bridge`` (which already imports
``agt.policies``).
"""

from __future__ import annotations

import threading
from collections import OrderedDict
from dataclasses import dataclass, field
from enum import Enum
from types import SimpleNamespace
from typing import Any, Callable, Mapping, Optional, Protocol, runtime_checkable

# The five ACS decisions per policy-engine/spec/SPECIFICATION.md and
# agent_control_specification._types.Decision.
_RECOGNIZED_DECISIONS = frozenset({"allow", "warn", "deny", "escalate", "transform"})

# Decisions whose execution side proceeds. Mirrors Decision.permits: allow,
# warn and transform permit; deny and escalate halt until the host's approval
# path resolves an escalate.
_PERMITTING_DECISIONS = frozenset({"allow", "warn", "transform"})

# Tool intervention points. A block at one of these emits the more specific
# ``tool_call_blocked`` event kind instead of the generic ``policy_violation``.
# Mirrors agent_control_specification.InterventionPoint.is_tool_intervention_point.
_TOOL_INTERVENTION_POINTS = frozenset({"pre_tool_call", "post_tool_call"})

# effective decision -> (trust action, governance event kind, severity).
# trust action is one of "reward" (success=True), "penalty" (success=False) or
# "neutral" (no interaction recorded). Only allow rewards: a merely permitting
# verdict (warn/transform) is not evidence of healthy behavior, and escalate is
# pending host approval, so neither moves trust. deny penalizes. The event kind
# strings match agent_os.event_sink.GovernanceEventKind values but stay plain
# strings here so this module does not import agent_os.
_OUTCOME_MAP: dict[str, tuple[str, str, str]] = {
    "allow": ("reward", "policy_check", "info"),
    "warn": ("neutral", "policy_check", "warning"),
    "transform": ("neutral", "policy_check", "info"),
    "deny": ("penalty", "policy_violation", "high"),
    "escalate": ("neutral", "escalation_requested", "warning"),
}

# Fail closed when the decision is missing or unrecognized: treat as a deny that
# penalizes trust and emits a violation.
_FAIL_CLOSED_TRUST = "penalty"
_FAIL_CLOSED_SEVERITY = "high"

# Bounds on per-bridge state so a long-lived bridge does not grow without limit.
_LOCK_STRIPES = 64
_DEFAULT_MAX_SEEN_KEYS = 100_000


def _block_event_kind(intervention_point: str | None) -> str:
    """Event kind for a BLOCKED action: tool_call_blocked at a tool point."""
    if intervention_point in _TOOL_INTERVENTION_POINTS:
        return "tool_call_blocked"
    return "policy_violation"


class AuditEmissionResult(str, Enum):
    """Outcome of delivering one governance event to the host audit path.

    The emitter returns this so audit delivery is observable. A ``-> None``
    emitter would hide the fact that ``GovernanceEventProcessor.on_event`` can
    drop an event on queue overflow, no-op after shutdown, or find no sink
    registered, which would let a governed action proceed with no audit trail.
    Only ``ACCEPTED`` counts as delivered for the fail closed gate.
    """

    ACCEPTED = "accepted"
    DROPPED = "dropped"
    NO_SINK = "no_sink"
    FAILED = "failed"

    @property
    def delivered(self) -> bool:
        """True only for ``ACCEPTED``. Every other result is a delivery gap."""
        return self is AuditEmissionResult.ACCEPTED


@dataclass(frozen=True)
class GovernanceEventSpec:
    """Neutral description of the governance event the bridge wants emitted.

    The host adapter maps this to a concrete
    ``agent_os.event_sink.GovernanceEvent`` (``kind`` -> ``GovernanceEventKind``)
    and routes it through its ``GovernanceEventProcessor``. Keeping the spec
    neutral is what lets this module stay free of the ``agent_os`` schema and
    import.
    """

    kind: str
    severity: str
    agent_id: str
    action: str
    decision: str
    reason: str
    attributes: Mapping[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class KernelDecision:
    """Normalized ACS decision carrying both the raw and effective verdicts.

    ``effective_decision`` is the verdict that actually took effect (what the
    action executes against). ``raw_decision`` is the verdict the engine first
    produced. They differ when the ACS runtime routes an ``escalate`` through
    the host approval path and rewrites it to ``allow`` or ``deny``; the raw
    ``escalate`` must survive so trust and audit reflect that an approval was
    requested. See :meth:`from_evaluation_result` for why the plain
    :class:`~agt.policies.result.EvaluationResult` seam alone is lossy.
    """

    effective_decision: str
    raw_decision: str
    reason: str = ""
    approval_outcome: str | None = None
    intervention_point: str | None = None
    input_identity: str | None = None
    enforced_identity: str | None = None
    transform: Mapping[str, Any] | None = None
    evidence: Mapping[str, Any] | None = None

    @property
    def is_recognized(self) -> bool:
        """True when ``effective_decision`` is one of the five ACS decisions."""
        return self.effective_decision in _RECOGNIZED_DECISIONS

    @property
    def permits(self) -> bool:
        """True when the effective decision permits execution.

        Unrecognized decisions never permit (fail closed).
        """
        return self.effective_decision in _PERMITTING_DECISIONS

    @property
    def was_escalated(self) -> bool:
        """True when the raw engine verdict was ``escalate``.

        Stays true even after the approval path rewrites the effective
        decision to ``allow`` or ``deny``.
        """
        return self.raw_decision == "escalate"

    @classmethod
    def from_decision(
        cls,
        effective_decision: str,
        *,
        raw_decision: str | None = None,
        reason: str = "",
        **kwargs: Any,
    ) -> "KernelDecision":
        """Build from a bare decision string.

        ``raw_decision`` defaults to ``effective_decision`` when the caller has
        no separate raw verdict to preserve.
        """
        return cls(
            effective_decision=effective_decision,
            raw_decision=raw_decision if raw_decision is not None else effective_decision,
            reason=reason,
            **kwargs,
        )

    @classmethod
    def from_evaluation_result(cls, result: Any) -> "KernelDecision":
        """Build from an ``agt.policies.result.EvaluationResult``.

        ``EvaluationResult.verdict`` is the effective decision after the ACS
        runtime has applied any approval routing, so an ``escalate`` that was
        approved arrives here as ``allow``. The raw ``escalate`` is recovered
        best effort from ``audit_entry`` (``raw_decision`` / ``original_verdict``
        keys) or from a ``HUMAN_APPROVAL`` category. When neither is present the
        raw decision equals the effective one and the escalation signal is not
        recoverable from this seam. Hosts that need a lossless signal should
        build from the raw ACS ``InterventionPointResult`` via
        :meth:`from_intervention_point_result`.
        """
        effective = getattr(result, "verdict", None)
        if not isinstance(effective, str):
            effective = str(effective) if effective is not None else "deny"

        audit_entry = getattr(result, "audit_entry", None) or {}
        raw = None
        approval_outcome = None
        intervention_point = None
        if isinstance(audit_entry, Mapping):
            # AgtRuntime._result_from_intervention records the raw engine verdict
            # under audit_entry["verdict"] (runtime.py) and keeps it there even
            # after the approval path rewrites the effective verdict, so an
            # approved escalate survives as audit_entry["verdict"] == "escalate"
            # while result.verdict == "allow". Recover it from there (falling back
            # to older raw_decision/original_verdict keys). approval_outcome and
            # intervention_point are written under the same audit_entry.
            raw = (
                audit_entry.get("raw_decision")
                or audit_entry.get("original_verdict")
                or audit_entry.get("verdict")
            )
            approval_outcome = audit_entry.get("approval_outcome")
            intervention_point = audit_entry.get("intervention_point") or None
        if raw is None:
            category = getattr(result, "category", None)
            category_value = getattr(category, "value", category)
            if isinstance(category_value, str) and category_value.upper() in {
                "HUMAN_APPROVAL",
                "HUMAN_APPROVAL_REQUIRED",
            }:
                raw = "escalate"
        if raw is None:
            raw = effective

        return cls(
            effective_decision=effective,
            raw_decision=str(raw),
            reason=getattr(result, "reason", "") or "",
            approval_outcome=approval_outcome,
            intervention_point=intervention_point,
            input_identity=getattr(result, "input_identity", None),
            enforced_identity=getattr(result, "enforced_identity", None),
            transform=getattr(result, "transform", None),
            evidence=getattr(result, "evidence", None),
        )

    @classmethod
    def from_intervention_point_result(
        cls, result: Any, *, intervention_point: str | None = None
    ) -> "KernelDecision":
        """Build from a raw ACS ``InterventionPointResult``.

        This is the lossless seam for hosts that do not use ``AgtRuntime``. The
        ``InterventionPointResult`` carries the verdict as the engine produced
        it (before host approval routing), so ``raw_decision`` and
        ``effective_decision`` are equal and an ``escalate`` is preserved
        verbatim. ``intervention_point`` (which the raw result does not carry)
        can be passed so a tool-point block audits as ``tool_call_blocked``.
        """
        verdict = getattr(result, "verdict", None)
        decision = getattr(verdict, "decision", None)
        decision_value = getattr(decision, "value", decision)
        if not isinstance(decision_value, str):
            decision_value = str(decision_value) if decision_value is not None else "deny"
        return cls(
            effective_decision=decision_value,
            raw_decision=decision_value,
            reason=getattr(verdict, "reason", None) or "",
            intervention_point=intervention_point,
            input_identity=getattr(result, "input_identity", None),
            enforced_identity=getattr(result, "enforced_identity", None),
            transform=getattr(verdict, "transform", None),
            evidence=getattr(verdict, "evidence", None),
        )


@dataclass(frozen=True)
class KernelOutcome:
    """The single object a host reads instead of hand wiring three subsystems.

    ``proceeds`` is the composite gate result. ``blocked_reason`` is set only
    when ``proceeds`` is false and names which gate blocked (decision, ring or
    audit), so callers do not have to reverse engineer it.
    """

    proceeds: bool
    raw_decision: str
    effective_decision: str
    reason: str
    trust_score: float
    trust_delta: float
    ring: Any
    demoted: bool
    ring_allowed: bool
    audit: AuditEmissionResult
    event: GovernanceEventSpec
    blocked_reason: str | None = None


@runtime_checkable
class TrustTrackerLike(Protocol):
    """Structural surface of ``agentmesh.trust_types.TrustTracker`` the bridge needs."""

    def record_interaction(
        self, agent_id: str, peer_id: str, action: str, success: bool
    ) -> float:
        ...

    def get_score(self, agent_id: str) -> float:
        ...


@runtime_checkable
class RingEnforcerLike(Protocol):
    """Structural surface of ``hypervisor.rings.RingEnforcer`` the bridge needs."""

    def compute_ring(self, eff_score: float, has_consensus: bool = ...) -> Any:
        ...

    def should_demote(self, current_ring: Any, eff_score: float) -> bool:
        ...

    def check(
        self,
        agent_ring: Any,
        action: Any,
        eff_score: float,
        has_consensus: bool = ...,
        has_sre_witness: bool = ...,
    ) -> Any:
        ...


@runtime_checkable
class ActionClassifierLike(Protocol):
    """Structural surface of ``hypervisor.rings.ActionClassifier`` the bridge needs."""

    def classify(self, action: Any) -> Any:
        ...


# Host callback that delivers one governance event and reports whether it was
# accepted for delivery. Returning anything other than an AuditEmissionResult
# (including None) is treated as FAILED under the fail closed contract.
EmitEvent = Callable[[GovernanceEventSpec], AuditEmissionResult]


def _action_name(action: Any) -> str:
    """Derive a stable string label for an action (descriptor or bare string)."""
    if action is None:
        return ""
    name = getattr(action, "name", None)
    if isinstance(name, str) and name:
        return name
    action_id = getattr(action, "action_id", None)
    if isinstance(action_id, str) and action_id:
        return action_id
    return str(action)


def _is_action_descriptor(action: Any) -> bool:
    """True when ``action`` carries the ring surface ``RingEnforcer.check`` reads."""
    return hasattr(action, "required_ring")


def _tighten_required_ring(action: Any, classified_ring: Any) -> Any:
    """Return ``action``, or a shim with a stricter ``required_ring``.

    ``RingEnforcer.check`` reads only ``action.required_ring``. When a classifier
    assigns a more privileged ring (lower ``.value``) than the action declares,
    return a lightweight shim carrying the tighter requirement so the gate
    honors the classifier. The requirement is only ever TIGHTENED, never
    loosened: a classifier that returns a more permissive ring is ignored so the
    gate cannot be weakened. When there is no tightening the original action is
    returned unchanged.
    """
    declared = getattr(action, "required_ring", None)
    declared_value = getattr(declared, "value", None)
    classified_value = getattr(classified_ring, "value", None)
    if (
        classified_ring is not None
        and classified_value is not None
        and declared_value is not None
        and classified_value < declared_value
    ):
        return SimpleNamespace(required_ring=classified_ring)
    return action


class KernelBridge:
    """Compose one ACS decision into trust, audit and ring outcomes.

    Dependencies are injected so this class imports none of ``agentmesh``,
    ``agent_os`` or ``hypervisor``. ``trust_tracker`` and ``emit_event`` are
    required; ``ring_enforcer`` and ``action_classifier`` are optional. When no
    ring enforcer is injected the ring gate is inactive (``ring_allowed`` stays
    true) because there is no configured ring constraint to violate.
    """

    def __init__(
        self,
        *,
        trust_tracker: TrustTrackerLike,
        emit_event: EmitEvent,
        ring_enforcer: Optional[RingEnforcerLike] = None,
        action_classifier: Optional[ActionClassifierLike] = None,
        max_seen_keys: int = _DEFAULT_MAX_SEEN_KEYS,
    ) -> None:
        if trust_tracker is None:
            raise ValueError("trust_tracker is required")
        if emit_event is None:
            raise ValueError("emit_event is required")
        self._trust = trust_tracker
        self._emit = emit_event
        self._rings = ring_enforcer
        self._classifier = action_classifier
        # Fixed-size striped lock pool keyed by hash(agent_id): bounds memory for
        # long-lived bridges with high agent-id cardinality while still
        # serializing concurrent apply() calls for the same agent (a given
        # agent_id always maps to the same stripe). Distinct agents may share a
        # stripe, which only costs occasional contention.
        self._locks: tuple[threading.Lock, ...] = tuple(
            threading.Lock() for _ in range(_LOCK_STRIPES)
        )
        # Idempotency ledger, bounded LRU. Guarded by its own lock because it is
        # shared across stripes.
        self._max_seen_keys = max(1, max_seen_keys)
        self._seen_keys: "OrderedDict[tuple[str, str], None]" = OrderedDict()
        self._seen_lock = threading.Lock()

    def _lock_for(self, agent_id: str) -> threading.Lock:
        return self._locks[hash(agent_id) % _LOCK_STRIPES]

    def _seen_contains(self, key: tuple[str, str]) -> bool:
        with self._seen_lock:
            if key in self._seen_keys:
                self._seen_keys.move_to_end(key)
                return True
            return False

    def _seen_add(self, key: tuple[str, str]) -> None:
        with self._seen_lock:
            self._seen_keys[key] = None
            self._seen_keys.move_to_end(key)
            while len(self._seen_keys) > self._max_seen_keys:
                self._seen_keys.popitem(last=False)

    def apply(
        self,
        decision: Optional[KernelDecision],
        *,
        agent_id: str,
        peer_id: str = "",
        action: Any = "",
        current_ring: Any = None,
        has_consensus: bool = False,
        strict_audit: bool = True,
        idempotency_key: str | None = None,
    ) -> KernelOutcome:
        """Drive trust, audit and rings from one ACS decision.

        Args:
            decision: The normalized ACS decision. ``None`` is treated as a fail
                closed deny.
            agent_id: Subject of the trust update and ring evaluation. Must be a
                non-empty string.
            peer_id: Counterparty recorded in the trust interaction.
            action: Either a ``hypervisor.models.ActionDescriptor`` (enables the
                ring gate via ``required_ring``; an injected classifier may
                tighten that required ring) or a bare string (trust and audit
                only; the ring gate is not applicable).
            current_ring: The agent's current execution ring. When a ring
                enforcer is injected and ``action`` is a descriptor, a ``None``
                ring fails the gate closed (the action is blocked) rather than
                skipping it.
            has_consensus: Passed through to ring computation and the check.
            strict_audit: When true, a governance event that is not accepted for
                delivery drives ``proceeds`` false.
            idempotency_key: When repeated for the same ``agent_id``, the trust
                delta is not applied twice (guards audit-failure retries). The
                key is scoped per agent, so one agent's key never suppresses
                another agent's update.

        Trust semantics: a penalty (deny or fail-closed) is applied immediately
        and unconditionally because it drives ring demotion. A reward (allow) is
        deferred and committed only if the action ultimately ``proceeds`` -- a
        blocked allow is never recorded as a trust success. Warn, transform and
        escalate are trust-neutral.

        Returns:
            A :class:`KernelOutcome` whose ``proceeds`` is the AND of the
            decision, ring and (strict) audit gates.
        """
        if not isinstance(agent_id, str) or not agent_id.strip():
            raise ValueError("agent_id must be a non-empty string")

        if decision is None:
            decision = KernelDecision.from_decision(
                "deny", reason="fail_closed:missing_decision"
            )

        # ``block_kind`` is the event kind used for any BLOCKED outcome: the more
        # specific ``tool_call_blocked`` at a tool intervention point, else the
        # generic ``policy_violation``.
        block_kind = _block_event_kind(decision.intervention_point)

        if decision.is_recognized:
            effective = decision.effective_decision
            trust_action, event_kind, severity = _OUTCOME_MAP[effective]
            if effective == "deny":
                event_kind = block_kind
            reason = decision.reason
        else:
            effective = "deny"
            trust_action, event_kind, severity = (
                _FAIL_CLOSED_TRUST,
                block_kind,
                _FAIL_CLOSED_SEVERITY,
            )
            reason = (
                decision.reason
                or f"fail_closed:unrecognized_decision:{decision.effective_decision}"
            )

        # A raw escalate keeps its escalation semantics for trust and audit even
        # after the approval path rewrote the effective decision. The human made
        # the call, so trust stays neutral (the agent neither earned nor lost
        # reputation) and the event records the escalation, regardless of whether
        # the effective decision permits (approved) or blocks (rejected). The
        # effective decision still drives ``acs_permits`` below, so an approved
        # escalate can proceed subject to the ring and audit gates.
        if decision.was_escalated:
            trust_action = "neutral"
            event_kind = "escalation_requested"
            severity = "warning"

        acs_permits = effective in _PERMITTING_DECISIONS
        action_name = _action_name(action)

        dep_error: str | None = None

        # --- Trust (atomic per agent; idempotent on retry) --------------------
        # Penalties are applied here, unconditionally: a denied or fail-closed
        # action loses trust and drives ring demotion below. A REWARD is deferred
        # (pending_reward) and only committed after the composite gate confirms
        # the action proceeds, so a blocked allow is never recorded as a success
        # (which would contradict the emitted block event).
        trust_score = 0.0
        trust_delta = 0.0
        pending_reward = False
        seen_key: tuple[str, str] | None = None
        already_applied = False
        try:
            with self._lock_for(agent_id):
                # Scope the idempotency key per agent: a host that derives the key
                # from a shared correlation id must not let one agent's key
                # suppress a different agent's trust/ring update.
                seen_key = (
                    (agent_id, idempotency_key) if idempotency_key is not None else None
                )
                already_applied = seen_key is not None and self._seen_contains(seen_key)
                before = self._trust.get_score(agent_id)
                trust_score = before
                if already_applied or trust_action == "neutral":
                    trust_delta = 0.0
                elif trust_action == "penalty":
                    trust_score = self._trust.record_interaction(
                        agent_id, peer_id, action_name, False
                    )
                    trust_delta = trust_score - before
                    if seen_key is not None:
                        self._seen_add(seen_key)
                else:  # reward: defer until the gate confirms the action proceeds
                    pending_reward = True
        except Exception as exc:  # fail closed: never proceed on a trust error
            dep_error = f"trust_error:{exc}"

        # --- Classification (advisory ring, may TIGHTEN the required ring) -----
        # Compute before the ring gate so the classifier's ring can raise the
        # privilege the action requires. ActionClassifier.set_override is
        # documented to take precedence, but RingEnforcer.check reads
        # action.required_ring directly, so without this the injected classifier
        # would be ignored by the gate.
        classified_ring: Any = None
        risk_weight: Any = None
        if self._classifier is not None and _is_action_descriptor(action):
            try:
                classification = self._classifier.classify(action)
                classified_ring = getattr(classification, "ring", None)
                risk_weight = getattr(classification, "risk_weight", None)
            except Exception:  # classification is advisory, not a gate
                classified_ring = None
                risk_weight = None

        # --- Rings: conservative demotion, then the action gate ---------------
        ring = current_ring
        demoted = False
        ring_allowed = True
        ring_reason = ""
        if self._rings is not None and dep_error is None:
            try:
                # Demote only in reaction to a penalizing ACS decision (deny or
                # fail closed). Never demote on a permitting decision: agentmesh
                # reputation and hypervisor eff_score are different scales (a
                # neutral agentmesh 0.5 is below the RING_2 floor 0.60), so a
                # permitted action must not spontaneously trip a ring, and trust
                # must never auto-promote a ring here.
                if (
                    trust_action == "penalty"
                    and current_ring is not None
                    and self._rings.should_demote(current_ring, trust_score)
                ):
                    demoted = True
                    ring = self._rings.compute_ring(trust_score, has_consensus)
            except Exception as exc:
                dep_error = f"ring_demote_error:{exc}"

            # The ring gate applies to descriptor actions (those carrying a
            # required_ring). A bare-string action has no ring surface, so the
            # gate is intentionally not applicable and ring_allowed stays True.
            if dep_error is None and _is_action_descriptor(action):
                if current_ring is None:
                    # Enforcer configured for a descriptor action but no agent
                    # ring to evaluate against: fail closed rather than skip.
                    ring_allowed = False
                    ring_reason = "ring_state_missing:current_ring"
                else:
                    try:
                        gate_action = _tighten_required_ring(action, classified_ring)
                        check = self._rings.check(
                            ring, gate_action, trust_score, has_consensus=has_consensus
                        )
                        allowed_attr = getattr(check, "allowed", None)
                        # Fail closed when the check result omits .allowed rather
                        # than defaulting an ambiguous result to allowed.
                        ring_allowed = bool(allowed_attr) if allowed_attr is not None else False
                        if not ring_allowed:
                            ring_reason = (
                                getattr(check, "reason", "")
                                or ("ring_check_indeterminate" if allowed_attr is None else "ring_denied")
                            )
                    except Exception as exc:
                        ring_allowed = False  # fail closed
                        ring_reason = f"ring_check_error:{exc}"

        # --- Audit ------------------------------------------------------------
        attributes: dict[str, Any] = {
            "peer_id": peer_id,
            "raw_decision": decision.raw_decision,
            "effective_decision": effective,
            "was_escalated": decision.was_escalated,
            "has_consensus": has_consensus,
            "trust_score": trust_score,
            "trust_delta": trust_delta,
            "demoted": demoted,
            "ring_allowed": ring_allowed,
        }
        if decision.approval_outcome is not None:
            attributes["approval_outcome"] = decision.approval_outcome
        if decision.input_identity is not None:
            attributes["input_identity"] = decision.input_identity
        if decision.enforced_identity is not None:
            attributes["enforced_identity"] = decision.enforced_identity
        if decision.transform is not None:
            attributes["transform"] = dict(decision.transform)
        if decision.evidence is not None:
            attributes["evidence"] = dict(decision.evidence)
        if classified_ring is not None:
            attributes["classified_ring"] = getattr(
                classified_ring, "value", classified_ring
            )
        if risk_weight is not None:
            attributes["risk_weight"] = risk_weight
        if dep_error is not None:
            attributes["dep_error"] = dep_error

        # Keep the audit record consistent with the enforced outcome: a permit
        # (policy_check) that a dependency error or ring denial actually blocked
        # must not be logged as benign. Relabel it to the block kind. Escalation
        # events keep their kind (the escalation is the salient signal); deny is
        # already the block kind.
        if (dep_error is not None or not ring_allowed) and event_kind == "policy_check":
            event_kind = block_kind
            severity = "high"

        event = GovernanceEventSpec(
            kind=event_kind,
            severity=severity,
            agent_id=agent_id,
            action=action_name,
            decision=effective,
            reason=reason,
            attributes=attributes,
        )

        try:
            audit = self._emit(event)
        except Exception:
            audit = AuditEmissionResult.FAILED
        if not isinstance(audit, AuditEmissionResult):
            audit = AuditEmissionResult.FAILED

        # --- Composite gate ---------------------------------------------------
        proceeds = acs_permits and ring_allowed and dep_error is None
        if strict_audit and not audit.delivered:
            proceeds = False

        # Commit a deferred reward only now that the action is confirmed to
        # proceed. A trust error here is post-authorization bookkeeping: it must
        # not retroactively block the already-permitted, already-audited action,
        # so it is captured in an attribute without flipping ``proceeds``.
        if pending_reward and proceeds:
            try:
                with self._lock_for(agent_id):
                    # Re-check the ledger under the lock: two concurrent same-key
                    # allows both defer in phase 1 (the key is not added until a
                    # reward commits), so phase 2 must confirm no other call
                    # already committed this key before recording.
                    if seen_key is not None and self._seen_contains(seen_key):
                        trust_score = self._trust.get_score(agent_id)
                        trust_delta = 0.0
                    else:
                        before_reward = self._trust.get_score(agent_id)
                        trust_score = self._trust.record_interaction(
                            agent_id, peer_id, action_name, True
                        )
                        trust_delta = trust_score - before_reward
                        if seen_key is not None:
                            self._seen_add(seen_key)
            except Exception:  # pragma: no cover - defensive
                # Bookkeeping failure after authorization: leave trust unchanged
                # (trust_delta stays 0) rather than blocking an approved action.
                trust_delta = 0.0

        blocked_reason: str | None = None
        if not proceeds:
            if dep_error is not None:
                blocked_reason = dep_error
            elif not acs_permits:
                blocked_reason = reason or f"decision:{effective}"
            elif not ring_allowed:
                blocked_reason = ring_reason or "ring_denied"
            elif strict_audit and not audit.delivered:
                blocked_reason = f"audit:{audit.value}"
            else:
                blocked_reason = "blocked"

        return KernelOutcome(
            proceeds=proceeds,
            raw_decision=decision.raw_decision,
            effective_decision=effective,
            reason=reason,
            trust_score=trust_score,
            trust_delta=trust_delta,
            ring=ring,
            demoted=demoted,
            ring_allowed=ring_allowed,
            audit=audit,
            event=event,
            blocked_reason=blocked_reason,
        )


__all__ = [
    "AuditEmissionResult",
    "GovernanceEventSpec",
    "KernelDecision",
    "KernelOutcome",
    "KernelBridge",
    "TrustTrackerLike",
    "RingEnforcerLike",
    "ActionClassifierLike",
    "EmitEvent",
]
