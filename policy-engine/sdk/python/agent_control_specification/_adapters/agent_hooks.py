# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""Expose ACS to any agent-hooks host as an :class:`Interceptor`.

The `agent-hooks <https://github.com/responsibleai/agent-hooks>`_ contract is
the framework-neutral seam that agent runtimes (crewAI, LangGraph, AutoGen, ...)
already speak: a host emits a wire-shaped ``AgentContext`` at each lifecycle
interception point and enforces the ``Verdict`` an *interceptor* returns.

:class:`AcsInterceptor` turns an ACS :class:`~agent_control_specification.AgentControl`
into exactly such an interceptor. A single instance therefore lets *every*
agent-hooks host inject ACS governance with no framework-specific glue::

    from agent_control_specification import AcsInterceptor

    acs = AcsInterceptor.from_manifest("governance.yaml")

    # crewAI: inject ACS into every agent in the crew.
    from crewai.hooks import use_agent_hooks

    with use_agent_hooks(acs):
        crew.kickoff(inputs={"topic": "quarterly report"})

For each emitted context the interceptor

1. reads the interception point (``context["interception_point"]``),
2. translates the agent-hooks context into the snapshot body an ACS
   :class:`~agent_control_specification.HostSession` evaluates,
3. evaluates it through the session, and
4. maps the returned :class:`~agent_control_specification.InterventionPointResult`
   back to an agent-hooks verdict.

The interceptor returns a *wire-shaped* verdict ``dict`` rather than the host's
own verdict type, so this module stays importable in hosts that only speak the
wire format; the host normalizes and validates it (agent-hooks §5). The five ACS
decisions are mapped onto the three agent-hooks decisions: ``allow`` and ``deny``
pass through, ``warn`` becomes an ``allow`` carrying a warning, ``escalate``
becomes a liftable ``deny`` (a ``deny`` with an ``approval`` block that the
agent-hooks host MAY resolve, §9), and ``transform`` carries the replacement.

Because the agent-hooks host owns enforcement, the interceptor evaluates in
:attr:`~agent_control_specification.EnforcementMode.EVALUATE_ONLY`: it decides,
the host applies the transform, denies, or lifts the approval.

Fail-closed: a missing interception point, an untranslatable context, a
snapshot-build error, or a runtime error is turned into a ``deny``. ACS is a
fail-closed decision runtime; this adapter never turns an error into an
``allow``.
"""

from __future__ import annotations

import logging
import threading
from collections import OrderedDict
from collections.abc import Callable
from pathlib import Path
from typing import TYPE_CHECKING, Any, Protocol, cast

from .._host import HostSession, SnapshotBuilder
from .._orchestration import AgentControl
from .._types import (
    Decision,
    EnforcementMode,
    InterventionPoint,
    InterventionPointResult,
    Verdict,
)

if TYPE_CHECKING:
    from collections.abc import Mapping

    from .._client import AnnotatorDispatcher, PolicyDispatcher


logger = logging.getLogger(__name__)


#: Wire-shaped agent-hooks context (agent-hooks §4): a JSON object.
AgentContext = dict[str, Any]
#: Wire-shaped agent-hooks verdict (agent-hooks §5); the host validates it.
WireVerdict = dict[str, Any]

#: A per-``(session, agent)`` decision session. Structurally a
#: :class:`~agent_control_specification.HostSession`; declared so a test can
#: inject a scripted session without the native core.
_SessionFactory = Callable[[SnapshotBuilder], "_Session"]

# The eight ACS and agent-hooks intervention points share identical string
# names, so no name translation is needed between the two contracts.
_KNOWN_POINTS: frozenset[str] = frozenset(point.value for point in InterventionPoint)

# Points whose agent-hooks ``target`` is a ``{"content": ...}`` envelope, so a
# transform must be rooted at ``$target.content`` rather than ``$target``.
_CONTENT_ENVELOPE_POINTS: frozenset[str] = frozenset(
    {"input", "output", "post_model_call"}
)

# Post-action points whose completion advances host-side budget counters. Their
# resource use is real, so it is recorded even when the point is not governed --
# otherwise the budgets that governed points read would under-count.
_BUDGET_POINTS: frozenset[str] = frozenset({"post_tool_call", "post_model_call"})

_GENERIC_DENY_MESSAGE = "Request blocked by Agent Control Specification."

# ACS fails closed on an intervention point a manifest does not declare, tagging
# the result with this reason code. agent-hooks hosts emit all eight lifecycle
# points regardless of the manifest, so the adapter treats this specific signal
# as "not governed here" and passes the action through -- but only when the
# governed set is unknown (see AcsInterceptor.intercept).
_UNGOVERNED_POINT_REASON = "runtime_error:intervention_point_unknown"

# Upper bound on the per-``(session, agent)`` session cache. The keys derive
# from untrusted context ids, so an unbounded cache is a memory-DoS vector for a
# long-lived, high-cardinality (e.g. multi-tenant) host.
#
# Eviction is not free of policy meaning: each session carries the running
# budget counters (tool calls, tokens) a budget policy reads, so evicting a
# session resets those counters to zero. Under session cardinality above this
# cap a budget policy therefore under-counts for the evicted sessions. The bound
# trades that for a hard memory ceiling; raise it, or supply an explicit
# ``governed_points`` set without budget policies, if that trade does not suit
# the host.
_MAX_SESSIONS = 4096

# Adapter-synthesized fail-closed reasons. They are namespaced ``acs_adapter:``
# and deliberately avoid the agent-hooks-reserved ``host_error:`` prefix (§11)
# and the ACS-reserved ``runtime_error:`` prefix.
_REASON_CONTEXT_INVALID = "acs_adapter:context_invalid"
_REASON_SNAPSHOT_ERROR = "acs_adapter:snapshot_error"
_REASON_RUNTIME_ERROR = "acs_adapter:runtime_error"
_REASON_TRANSFORM_UNAVAILABLE = "acs_adapter:transform_unavailable"


class _Session(Protocol):
    """Minimal structural view of :class:`HostSession` the adapter drives.

    Depending on this protocol (rather than the concrete session) keeps the
    adapter unit-testable without the native ACS core, and lets a host inject
    its own evaluator.
    """

    builder: SnapshotBuilder

    def evaluate(
        self, intervention_point: str, **body: Any
    ) -> InterventionPointResult: ...


def _as_mapping(value: Any) -> dict[str, Any]:
    """Coerce an untrusted context member into a ``dict[str, Any]``."""
    if isinstance(value, dict):
        typed = cast("dict[Any, Any]", value)
        return {str(key): item for key, item in typed.items()}
    return {}


def _as_list(value: Any) -> list[Any]:
    """Coerce an untrusted context member into a ``list``."""
    if isinstance(value, (list, tuple)):
        return list(cast("list[Any] | tuple[Any, ...]", value))
    return []


def _as_text(value: Any) -> str:
    """Render an untrusted scalar/object as text for a snapshot body."""
    if isinstance(value, str):
        return value
    return str(value)


def _as_body(value: Any) -> str | dict[str, Any]:
    """Coerce an untrusted content member into a snapshot body."""
    if isinstance(value, str):
        return value
    if isinstance(value, dict):
        return _as_mapping(value)
    return _as_text(value)


def _int_or_zero(value: Any) -> int:
    """Return ``value`` if it is a non-bool ``int``, else ``0``."""
    if isinstance(value, int) and not isinstance(value, bool):
        return value
    return 0


def _deny(reason: str, message: str) -> WireVerdict:
    """Build a fail-closed ``deny`` wire verdict."""
    return {"decision": "deny", "reason": reason, "message": message}


def _control_from_manifest(
    manifest: str | Path | Mapping[str, Any],
    policy_dispatcher: PolicyDispatcher | None,
    annotator_dispatcher: AnnotatorDispatcher | None,
) -> AgentControl:
    """Build an :class:`AgentControl` from a manifest path or mapping."""
    if isinstance(manifest, (str, Path)):
        return AgentControl.from_path(
            str(manifest), annotator_dispatcher, policy_dispatcher
        )
    return AgentControl.from_native(manifest, annotator_dispatcher, policy_dispatcher)


class AcsInterceptor:
    """An agent-hooks ``Interceptor`` backed by an ACS ``AgentControl``.

    Construct one with :meth:`from_manifest` (the common path) or
    :meth:`from_control`, then hand it to any agent-hooks host. The interceptor
    is stateless with respect to policy decisions -- ACS evaluates each snapshot
    independently -- but it keeps one :class:`HostSession` per
    ``(session, agent)`` pair so per-session budget counters (tool calls,
    tokens) accumulate across a run.

    Instances are safe to share across the threads/tasks of a single host: the
    per-session cache and its budget mutations are guarded by a lock.
    """

    __slots__ = ("_governed_points", "_lock", "_session_factory", "_sessions")

    def __init__(
        self,
        session_factory: _SessionFactory,
        *,
        governed_points: frozenset[str] | None = None,
    ) -> None:
        """Wrap a session factory as an interceptor.

        Args:
            session_factory: Builds the :class:`HostSession` for a
                ``(session, agent)`` pair from the identity-bearing
                :class:`SnapshotBuilder` the adapter constructs.
            governed_points: The intervention points this interceptor should
                evaluate. Points outside the set pass through as ``allow``,
                because an agent-hooks host emits every lifecycle point but a
                manifest governs only a subset. When ``None`` every point is
                evaluated and the adapter relies on the engine's
                ``intervention_point_unknown`` signal to pass an ungoverned
                point through.
        """
        self._session_factory = session_factory
        self._sessions: OrderedDict[tuple[str, str], _Session] = OrderedDict()
        self._lock = threading.Lock()
        self._governed_points = governed_points

    @classmethod
    def from_manifest(
        cls,
        manifest: str | Path | Mapping[str, Any],
        *,
        policy_dispatcher: PolicyDispatcher | None = None,
        annotator_dispatcher: AnnotatorDispatcher | None = None,
        governed_points: frozenset[str] | None = None,
    ) -> AcsInterceptor:
        """Build an interceptor from an ACS manifest.

        Args:
            manifest: A manifest filesystem path, or a parsed manifest mapping.
            policy_dispatcher: Optional host policy dispatcher (ACS §12.3) -- for
                ``custom`` policies or to run without the bundled dispatcher.
            annotator_dispatcher: Optional host annotator dispatcher.
            governed_points: See :meth:`__init__`.

        Returns:
            A ready-to-register :class:`AcsInterceptor`.
        """
        control = _control_from_manifest(
            manifest, policy_dispatcher, annotator_dispatcher
        )
        return cls.from_control(control, governed_points=governed_points)

    @classmethod
    def from_control(
        cls,
        control: AgentControl,
        *,
        governed_points: frozenset[str] | None = None,
    ) -> AcsInterceptor:
        """Build an interceptor from an already-constructed ``AgentControl``."""

        def _factory(builder: SnapshotBuilder) -> _Session:
            return HostSession(
                control, builder=builder, mode=EnforcementMode.EVALUATE_ONLY
            )

        return cls(_factory, governed_points=governed_points)

    # -- agent-hooks Interceptor contract -------------------------------------

    def intercept(self, context: AgentContext, /) -> WireVerdict:
        """Evaluate one agent-hooks context and return a wire verdict.

        This is the agent-hooks ``Interceptor`` entry point. It never raises:
        every failure is mapped to a fail-closed ``deny`` so the host blocks
        rather than proceeding ungoverned.
        """
        point = context.get("interception_point")
        if not isinstance(point, str) or point not in _KNOWN_POINTS:
            logger.warning("ACS interceptor: unknown interception point %r", point)
            return _deny(_REASON_CONTEXT_INVALID, _GENERIC_DENY_MESSAGE)

        if self._governed_points is not None and point not in self._governed_points:
            # Not governed here, but resource use at post_* points must still
            # advance the budget counters that governed points read.
            if point in _BUDGET_POINTS:
                self._record_budget(point, context, self._session(context))
            return {"decision": "allow"}

        session = self._session(context)

        try:
            body = self._build_body(point, context)
        except Exception:
            logger.exception("ACS interceptor: snapshot build failed at %s", point)
            return _deny(_REASON_SNAPSHOT_ERROR, _GENERIC_DENY_MESSAGE)

        try:
            result = session.evaluate(point, **body)
        except Exception:
            logger.exception("ACS interceptor: evaluation failed at %s", point)
            return _deny(_REASON_RUNTIME_ERROR, _GENERIC_DENY_MESSAGE)

        if (
            self._governed_points is None
            and result.verdict.decision is Decision.DENY
            and result.verdict.reason == _UNGOVERNED_POINT_REASON
        ):
            # Defense in depth ONLY when the governed set is unknown: an
            # undeclared point is "not governed", not denied. When the governed
            # set IS known, a governed point's deny stays a deny -- a policy that
            # fails to bind must fail closed, never open.
            if point in _BUDGET_POINTS:
                self._record_budget(point, context, session)
            return {"decision": "allow"}

        self._record_budget(point, context, session)
        verdict = _to_wire_verdict(result, point)
        logger.debug(
            "ACS interceptor: %s -> %s (%s)",
            point,
            result.verdict.decision.value,
            result.verdict.reason or "-",
        )
        return verdict

    # -- snapshot translation -------------------------------------------------

    def _session(self, context: AgentContext) -> _Session:
        """Return the :class:`HostSession` for this context's ``(session, agent)``."""
        agent = _as_mapping(context.get("agent"))
        session_ctx = _as_mapping(context.get("session"))
        agent_id = _as_text(agent.get("id") or "agent")
        session_id = _as_text(session_ctx.get("id") or "session")
        name = agent.get("name")
        agent_name = name if isinstance(name, str) else None
        tenant = _as_mapping(context.get("tenant"))
        tenant_raw = tenant.get("id")
        tenant_id = tenant_raw if isinstance(tenant_raw, str) else None
        # Tuple key avoids delimiter-injection collisions between untrusted ids.
        key = (session_id, agent_id)
        with self._lock:
            session = self._sessions.get(key)
            if session is None:
                builder = SnapshotBuilder(
                    agent_id=agent_id,
                    session_id=session_id,
                    agent_name=agent_name,
                    tenant_id=tenant_id,
                )
                session = self._session_factory(builder)
                self._sessions[key] = session
                # Bound the cache: evict the least-recently-used session when it
                # grows past the cap (see _MAX_SESSIONS).
                if len(self._sessions) > _MAX_SESSIONS:
                    self._sessions.popitem(last=False)
            else:
                self._sessions.move_to_end(key)
            return session

    def _build_body(self, point: str, context: AgentContext) -> dict[str, Any]:
        """Translate an agent-hooks context into the snapshot body for ``point``."""
        if point == "input":
            inp = _as_mapping(context.get("input"))
            role = inp.get("role")
            return {
                "input": {
                    "body": _as_body(inp.get("content")),
                    "source": role if isinstance(role, str) else "user",
                }
            }

        if point == "pre_model_call":
            model = _as_mapping(context.get("model"))
            return {
                "model": {"name": _as_text(model.get("id") or "unknown")},
                "messages": _as_list(context.get("messages")),
            }

        if point == "post_model_call":
            model = _as_mapping(context.get("model"))
            usage_raw = context.get("usage")
            return {
                "model": {"name": _as_text(model.get("id") or "unknown")},
                "response": _as_mapping(context.get("response")),
                "usage": _as_mapping(usage_raw) if isinstance(usage_raw, dict) else {},
            }

        if point == "pre_tool_call":
            tool_call = _as_mapping(context.get("tool_call"))
            return {
                "tool_call": {
                    "name": _as_text(tool_call.get("name") or ""),
                    "args": _as_mapping(tool_call.get("args")),
                    "id": _as_text(tool_call.get("id") or "call-1"),
                }
            }

        if point == "post_tool_call":
            tool_call = _as_mapping(context.get("tool_call"))
            tool_result = _as_mapping(context.get("tool_result"))
            duration = tool_result.get("duration_ms")
            return {
                "tool_call": {
                    "name": _as_text(tool_call.get("name") or ""),
                    "args": _as_mapping(tool_call.get("args")),
                    "id": _as_text(tool_call.get("id") or "call-1"),
                },
                "tool_result": {
                    "value": tool_result.get("value"),
                    "error": "error" if tool_result.get("is_error") else None,
                    "duration_ms": float(duration)
                    if isinstance(duration, (int, float)) and not isinstance(duration, bool)
                    else 0.0,
                },
            }

        if point == "output":
            out = _as_mapping(context.get("output"))
            return {"response": {"content": _as_body(out.get("content"))}}

        if point == "agent_startup":
            init = _as_mapping(context.get("agent_init"))
            return {
                "agent": {
                    "tools_registered": [
                        _as_text(t) for t in _as_list(init.get("tools_registered"))
                    ],
                    "capabilities": [
                        _as_text(c) for c in _as_list(init.get("capabilities"))
                    ],
                }
            }

        # point == "agent_shutdown" (the only remaining known point).
        return {"summary": _as_mapping(context.get("summary"))}

    def _record_budget(
        self, point: str, context: AgentContext, session: _Session
    ) -> None:
        """Advance host-side budget counters after a completed action.

        Counters are read at the start of each ACS evaluation, so recording a
        completed tool call / token spend here surfaces it to the *next*
        intervention point. Best-effort and never raises.
        """
        if point == "post_tool_call":
            with self._lock:
                session.builder.record_tool_call()
        elif point == "post_model_call":
            usage = _as_mapping(context.get("usage"))
            total = _int_or_zero(usage.get("total_tokens"))
            if total == 0:
                total = _int_or_zero(usage.get("prompt_tokens")) + _int_or_zero(
                    usage.get("completion_tokens")
                )
            if total > 0:
                with self._lock:
                    session.builder.record_tokens(total)


# -- verdict mapping ----------------------------------------------------------


def _transform_root(point: str) -> str:
    """Return the ``$target`` root a transform must use for ``point``."""
    if point in _CONTENT_ENVELOPE_POINTS:
        return "$target.content"
    return "$target"


def _wire_reason(reason: str | None) -> str:
    """Namespace a bare policy reason as ``policy:<reason>`` for the wire.

    The native engine reports a policy-origin reason bare (``blocked_pii``) and a
    runtime reason already namespaced (``runtime_error:...``). agent-hooks hosts
    categorize a verdict by its reason namespace, so a bare reason is tagged
    ``policy:`` while an already-namespaced one is left untouched.
    """
    if not reason:
        return "policy:blocked"
    if ":" in reason:
        return reason
    return f"policy:{reason}"


def _to_wire_verdict(result: InterventionPointResult, point: str) -> WireVerdict:
    """Map an ACS :class:`InterventionPointResult` to an agent-hooks wire verdict.

    ACS exposes five decisions; agent-hooks encodes three (§5.1):

    - ``allow``    -> ``allow``
    - ``warn``     -> ``allow`` + a ``warnings`` entry
    - ``transform``-> ``transform`` with a ``$target``-rooted replacement
    - ``deny``     -> ``deny`` (reason + full message)
    - ``escalate`` -> ``deny`` + an ``approval`` block (a liftable deny, §9)
    """
    verdict = result.verdict
    decision = verdict.decision
    reason = verdict.reason or None
    message = verdict.message or None

    if decision is Decision.TRANSFORM:
        return _transform_verdict(result, point)

    if decision in (Decision.DENY, Decision.ESCALATE):
        out: WireVerdict = {
            "decision": "deny",
            "reason": _wire_reason(reason),
            "message": message or _public_message(result),
        }
        if decision is Decision.ESCALATE:
            # A liftable deny: the agent-hooks host approval seam (§9) MAY lift
            # it; without a resolver it stays denied and fails closed.
            out["approval"] = {}
        return out

    # allow / warn both permit the action in agent-hooks terms.
    allow: WireVerdict = {"decision": "allow"}
    if decision is Decision.WARN:
        warning: dict[str, Any] = {}
        if reason is not None:
            warning["reason"] = _wire_reason(reason)
        if message is not None:
            warning["message"] = message
        allow["warnings"] = [warning]
    labels = list(verdict.result_labels)
    if labels:
        allow["result_labels"] = labels
    _attach_evidence(allow, verdict)
    return allow


def _transform_verdict(result: InterventionPointResult, point: str) -> WireVerdict:
    """Map an ACS ``transform`` decision onto an agent-hooks transform.

    ACS confines a transform to the policy target. The materialized replacement
    is ``result.transformed_policy_target`` when the runtime applied it, else the
    declared ``verdict.transform.value`` (the case in evaluate-only mode, where
    the agent-hooks host applies it). Because the agent-hooks ``target`` mirrors
    the policy target, the replacement is re-rooted at ``$target`` (or
    ``$target.content`` for the content-envelope points). With no replacement
    value the verdict fails closed to ``deny`` rather than proceeding unmodified.
    """
    transform = result.verdict.transform
    if transform is None:
        return _deny(_REASON_TRANSFORM_UNAVAILABLE, _GENERIC_DENY_MESSAGE)
    value = (
        result.transformed_policy_target
        if result.transformed_policy_target_applied
        else transform.value
    )
    if value is None:
        return _deny(_REASON_TRANSFORM_UNAVAILABLE, _GENERIC_DENY_MESSAGE)
    out: WireVerdict = {
        "decision": "transform",
        "transform": {"path": _transform_root(point), "value": value},
    }
    if result.verdict.reason:
        out["reason"] = _wire_reason(result.verdict.reason)
    if result.verdict.message:
        out["message"] = result.verdict.message
    labels = list(result.verdict.result_labels)
    if labels:
        out["result_labels"] = labels
    _attach_evidence(out, result.verdict)
    return out


def _attach_evidence(wire: WireVerdict, verdict: Verdict) -> None:
    """Copy any ACS evidence onto ``wire`` in the agent-hooks wire shape."""
    evidence = verdict.evidence
    if evidence is None:
        return
    payload: dict[str, Any] = {}
    if evidence.artefact is not None:
        payload["artefact"] = _as_text(evidence.artefact)
    pointers = {
        str(key): _as_text(url) for key, url in evidence.verification_pointers.items()
    }
    if pointers:
        payload["verification_pointers"] = pointers
    if payload:
        wire["evidence"] = payload


def _public_message(result: InterventionPointResult) -> str:
    """A denial message that leaks neither policy nor user content."""
    verdict = result.verdict
    if verdict.decision is Decision.ESCALATE:
        return "Request requires policy approval."
    if (verdict.reason or "").startswith("runtime_error:"):
        return "Policy evaluation failed closed."
    return _GENERIC_DENY_MESSAGE


__all__ = ["AcsInterceptor", "AgentContext", "WireVerdict"]
