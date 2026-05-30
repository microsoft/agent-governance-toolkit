from __future__ import annotations

from collections.abc import Awaitable, Callable
from dataclasses import dataclass, field
import hashlib
import json
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

    @property
    def applies_effects(self) -> bool:
        return self in {Decision.ALLOW, Decision.WARN, Decision.ESCALATE}


class PerfTelemetry(IntEnum):
    OFF = 0
    EXTERNAL = 1
    FULL = 2


@dataclass(frozen=True)
class Verdict:
    decision: Decision
    reason: str | None = None
    message: str | None = None
    effects: Sequence[Mapping[str, JsonValue]] = field(default_factory=tuple)
    result_labels: Sequence[str] = field(default_factory=tuple)

    @classmethod
    def from_mapping(cls, value: Mapping[str, JsonValue]) -> "Verdict":
        raw_effects = value.get("effects") or ()
        if not isinstance(raw_effects, Sequence) or isinstance(raw_effects, (str, bytes)):
            raise ValueError("verdict effects must be a sequence")
        raw_labels = value.get("result_labels") or ()
        if not isinstance(raw_labels, Sequence) or isinstance(raw_labels, (str, bytes)):
            raise ValueError("verdict result_labels must be a sequence")
        return cls(
            decision=Decision(value["decision"]),
            reason=value.get("reason"),
            message=value.get("message"),
            effects=tuple(raw_effects),
            result_labels=tuple(raw_labels),
        )


@dataclass(frozen=True)
class InterventionPointRequest:
    intervention_point: InterventionPoint
    snapshot: Mapping[str, JsonValue]
    mode: EnforcementMode = EnforcementMode.ENFORCE


@dataclass(frozen=True)
class InterventionPointResult:
    verdict: Verdict
    transformed_policy_target: JsonValue | None = None
    policy_input: JsonValue | None = None
    action_identity: str | None = None


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
