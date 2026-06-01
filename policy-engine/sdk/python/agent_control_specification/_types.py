from __future__ import annotations

from collections.abc import Awaitable, Callable
from dataclasses import dataclass, field
import hashlib
import json
import warnings
from enum import Enum, IntEnum
from typing import Any, Mapping, MutableMapping, Sequence, Union

JsonValue = Any
JsonObject = MutableMapping[str, JsonValue]


class InterventionPoint(str, Enum):
    AGENT_STARTUP = "agent_startup"
    INPUT = "input"
    PRE_MODEL_CALL = "pre_model_call"
    POST_MODEL_CALL = "post_model_call"
    PRE_TOOL_CALL = "pre_tool_call"
    POST_TOOL_CALL = "post_tool_call"
    OUTPUT = "output"
    AGENT_SHUTDOWN = "agent_shutdown"

    @property
    def is_tool_intervention_point(self) -> bool:
        return self in {InterventionPoint.PRE_TOOL_CALL, InterventionPoint.POST_TOOL_CALL}


class EnforcementMode(str, Enum):
    ENFORCE = "enforce"
    EVALUATE_ONLY = "evaluate_only"


class Decision(str, Enum):
    ALLOW = "allow"
    DENY = "deny"
    WARN = "warn"
    ESCALATE = "escalate"
    TRANSFORM = "transform"

    @property
    def permits(self) -> bool:
        """True for decisions whose execution side proceeds with the action.

        Mirrors `core/src/verdict.rs::Decision::permits`: ``allow``, ``warn``,
        and ``transform`` permit execution; ``deny`` and ``escalate`` halt it
        until the host's approval path resolves an ``escalate``.
        """
        return self in {Decision.ALLOW, Decision.WARN, Decision.TRANSFORM}

    @property
    def applies_transform(self) -> bool:
        """True only for ``transform``, the sole mutating decision per AGT D1.

        Effects[] was removed by AGT D1, so only ``transform`` can rewrite the
        policy target. ``allow``, ``warn``, ``deny``, and ``escalate`` never
        mutate the action.
        """
        return self is Decision.TRANSFORM

    @property
    def applies_effects(self) -> bool:
        """Deprecated. Use ``applies_transform`` (or ``permits`` to check
        whether the action proceeds).

        AGT D1 removed the effects[] surface; only ``transform`` mutates. This
        property previously returned True for ``allow``, ``warn``, and
        ``escalate``, none of which can mutate under AGT. It now returns
        ``applies_transform`` and emits a DeprecationWarning to surface the
        rename. Hosts that relied on the old "may apply mutations" semantics
        should use ``applies_transform``; hosts that meant "execution
        proceeds" should use ``permits``.
        """
        warnings.warn(
            "Decision.applies_effects is deprecated per AGT D1; "
            "use Decision.applies_transform (only transform mutates) "
            "or Decision.permits (action proceeds).",
            DeprecationWarning,
            stacklevel=2,
        )
        return self.applies_transform


class PerfTelemetry(IntEnum):
    OFF = 0
    EXTERNAL = 1
    FULL = 2


@dataclass(frozen=True)
class Transform:
    """AGT D1.1 single-target replacement payload.

    The runtime applies ``value`` at ``path`` rooted at ``$policy_target``
    before propagating the result. SDK consumers can persist this object to
    capture what the policy asked for, independent of the
    ``transformed_policy_target`` snapshot.
    """

    path: str
    value: JsonValue

    @classmethod
    def from_mapping(cls, value: Mapping[str, JsonValue]) -> "Transform":
        if "path" not in value:
            raise ValueError("transform.path is required")
        return cls(path=str(value["path"]), value=value.get("value"))


@dataclass(frozen=True)
class Evidence:
    """AGT D2 opaque evidence payload propagated verbatim from the dispatcher.

    ``artefact`` is a content address (typically ``sha256:<hex>``) of an
    offline-verifiable proof. ``verification_pointers`` maps named pointer
    keys to URLs an auditor can consult to re-verify the decision. The SDK
    does not validate or fetch either field; AGT-EVIDENCE-1.0 §3 restricts
    telemetry to artefact + sorted keys, and §4 keeps the full pointer map
    in the audit record.
    """

    artefact: str | None = None
    verification_pointers: Mapping[str, str] = field(default_factory=dict)

    @classmethod
    def from_mapping(cls, value: Mapping[str, JsonValue]) -> "Evidence":
        if not isinstance(value, Mapping):
            raise ValueError("evidence must be a mapping")
        artefact = value.get("artefact")
        if artefact is not None and not isinstance(artefact, str):
            raise ValueError("evidence.artefact must be a string when present")
        raw_pointers = value.get("verification_pointers") or {}
        if not isinstance(raw_pointers, Mapping):
            raise ValueError("evidence.verification_pointers must be a mapping")
        pointers: dict[str, str] = {}
        for key, url in raw_pointers.items():
            if not isinstance(url, str):
                raise ValueError(
                    f"evidence.verification_pointers.{key} must be a string"
                )
            pointers[str(key)] = url
        return cls(artefact=artefact, verification_pointers=pointers)


@dataclass(frozen=True)
class Verdict:
    decision: Decision
    reason: str | None = None
    message: str | None = None
    transform: Transform | None = None
    evidence: Evidence | None = None
    result_labels: Sequence[str] = field(default_factory=tuple)

    @classmethod
    def from_mapping(cls, value: Mapping[str, JsonValue]) -> "Verdict":
        raw_labels = value.get("result_labels") or ()
        if not isinstance(raw_labels, Sequence) or isinstance(raw_labels, (str, bytes)):
            raise ValueError("verdict result_labels must be a sequence")
        raw_transform = value.get("transform")
        transform: Transform | None = None
        if raw_transform is not None:
            if not isinstance(raw_transform, Mapping):
                raise ValueError("verdict transform must be a mapping when present")
            transform = Transform.from_mapping(raw_transform)
        raw_evidence = value.get("evidence")
        evidence: Evidence | None = None
        if raw_evidence is not None:
            if not isinstance(raw_evidence, Mapping):
                raise ValueError("verdict evidence must be a mapping when present")
            evidence = Evidence.from_mapping(raw_evidence)
        return cls(
            decision=Decision(value["decision"]),
            reason=value.get("reason"),
            message=value.get("message"),
            transform=transform,
            evidence=evidence,
            result_labels=tuple(raw_labels),
        )


@dataclass(frozen=True)
class InterventionPointRequest:
    intervention_point: InterventionPoint | str
    snapshot: Mapping[str, JsonValue]
    mode: EnforcementMode = EnforcementMode.ENFORCE


@dataclass(frozen=True)
class InterventionPointResult:
    verdict: Verdict
    transformed_policy_target: JsonValue | None = None
    transformed_policy_target_applied: bool = False
    policy_input: JsonValue | None = None
    # AGT D1.4: bisected identity. ``input_identity`` pins the policy input
    # that was evaluated; ``enforced_identity`` pins the policy input AFTER
    # the transform path is applied (equal to ``input_identity`` for every
    # non-transform decision). Audit records MUST carry both.
    input_identity: str | None = None
    enforced_identity: str | None = None

    @property
    def action_identity(self) -> str | None:
        """Backwards-compatible alias for ``enforced_identity``.

        Per AGT D1.4 the single-identity surface that pre-bisection callers
        consumed maps to ``enforced_identity`` (the action that actually
        executes). New callers should reach for ``input_identity`` and
        ``enforced_identity`` directly.
        """
        return self.enforced_identity


@dataclass(frozen=True)
class RunResult:
    value: JsonValue
    input_result: InterventionPointResult
    output_result: InterventionPointResult


@dataclass(frozen=True)
class ToolRunResult:
    value: JsonValue
    pre_tool_call_result: InterventionPointResult
    post_tool_call_result: InterventionPointResult


class AgentControlInterruption(RuntimeError):
    """Base for control-flow interruptions raised by enforcing wrappers.

    Distinguishes a policy-driven interruption (block or approval suspension)
    from ordinary runtime errors so callers can catch one without conflating
    the two.
    """


class AgentControlBlocked(AgentControlInterruption):
    """Raised when an enforcing wrapper receives a deny or unapproved escalate verdict.

    For a ``post_*`` intervention point the guarded action has already executed;
    a block prevents the result from propagating, it does not undo the side effect.
    Use ``pre_*`` points to prevent side effects.
    """

    def __init__(self, intervention_point: InterventionPoint, result: InterventionPointResult):
        self.intervention_point = intervention_point
        self.result = result
        reason = f" ({result.verdict.reason})" if result.verdict.reason else ""
        super().__init__(f"Agent Control Specification blocked {intervention_point.value}{reason}.")


class AgentControlSuspended(AgentControlInterruption):
    """Raised when an approval resolver suspends an escalate verdict for deferred approval.

    This is a terminal unwinding signal for the current call. ``run()`` and
    ``run_tool()`` do not resume automatically; resumption is owned by the
    adapter or host using ``handle``. As with :class:`AgentControlBlocked`, a
    suspension at a ``post_*`` point does not undo an already-executed action.
    """

    def __init__(
        self,
        intervention_point: InterventionPoint,
        result: InterventionPointResult,
        handle: JsonValue | None = None,
    ):
        self.intervention_point = intervention_point
        self.result = result
        self.handle = handle
        reason = f" ({result.verdict.reason})" if result.verdict.reason else ""
        super().__init__(
            f"Agent Control Specification suspended {intervention_point.value} pending approval{reason}."
        )


class ApprovalOutcome(str, Enum):
    """Outcome of resolving an ``escalate`` verdict through an approval resolver."""

    ALLOW = "allow"
    DENY = "deny"
    SUSPEND = "suspend"


@dataclass(frozen=True)
class ApprovalResolution:
    """Result returned by an :data:`ApprovalResolver`.

    ``handle`` is an opaque, host-owned value carried on
    :class:`AgentControlSuspended` so the host can later resume the suspended
    interaction. The runtime never stores or interprets it.
    """

    outcome: ApprovalOutcome
    handle: JsonValue | None = None
    action_identity: str | None = None

    @classmethod
    def allow(cls, action_identity: str) -> "ApprovalResolution":
        return cls(ApprovalOutcome.ALLOW, action_identity=action_identity)

    @classmethod
    def deny(cls) -> "ApprovalResolution":
        return cls(ApprovalOutcome.DENY)

    @classmethod
    def suspend(cls, handle: JsonValue | None = None, action_identity: str | None = None) -> "ApprovalResolution":
        return cls(ApprovalOutcome.SUSPEND, handle, action_identity)


ApprovalResolver = Callable[
    ["InterventionPoint", "InterventionPointResult"],
    Union[
        "ApprovalResolution",
        "ApprovalOutcome",
        Awaitable[Union["ApprovalResolution", "ApprovalOutcome"]],
    ],
]
"""Host-supplied callback invoked for an ``escalate`` verdict in enforce mode.

It receives the intervention point and its result and returns an
:class:`ApprovalResolution` (or a bare :class:`ApprovalOutcome` for
allow/deny). It may be synchronous or asynchronous. An invalid return value
fails closed (treated as a block).
"""


def action_identity(policy_input: JsonValue) -> str:
    canonical = json.dumps(policy_input, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    return "sha256:" + hashlib.sha256(canonical.encode("utf-8")).hexdigest()
