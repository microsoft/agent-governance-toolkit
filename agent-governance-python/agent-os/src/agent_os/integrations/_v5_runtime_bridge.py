# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""v5 runtime bridge for v4 framework adapters.

This module is the seam that lets a v4 framework adapter
(``OpenAIKernel``, ``LangChainKernel``, etc.) keep its public surface
intact while internally routing policy evaluation through the AGT 5.0
ACS-backed :class:`agt.policies.runtime.AgtRuntime`.

The bridge:

- Translates a v4
  :class:`agent_os.integrations.base.GovernancePolicy` into an AGT
  manifest via :func:`agt.policies.bridge.governance_to_acs_manifest`,
  materialises the manifest to disk in the bundle directory the bridge
  picks, and stands up an :class:`agt.policies.runtime.AgtRuntime` on
  it. The (policy, approval-resolver) pair is memoised so repeated
  intervention-point evaluations reuse the same runtime.
- Delegates session snapshots and counters to
  :class:`agt.policies.session.AdapterRuntimeSession`, while mirroring the
  existing :class:`~agent_os.integrations.base.ExecutionContext` counters until
  each adapter moves to the native session in phase 3.
- Translates each intervention point hook into a snapshot, evaluates
  it through the runtime, and maps the returned
  :class:`agt.policies.result.EvaluationResult` into both the v4
  :class:`agent_os.policies.decision.PolicyCheckResult` and the legacy
  ``(allowed, reason)`` tuple. The bisected ``input_identity`` /
  ``enforced_identity`` per AGT-DELTA D1.4 ride into
  ``PolicyCheckResult.audit_entry``.
- Surfaces transform verdicts (AGT-DELTA D1.1) to the adapter as a
  :class:`TransformOutcome` so the adapter can rewrite the outbound
  payload before forwarding the call to the wrapped client.
- Wires the optional v4 escalation manager as the AGT approval
  resolver per AGT-DELTA D1.4.

The bridge fails closed. If the AGT 5.0 SDK is not importable (e.g.
the ACS native binding is not built), :func:`get_runtime_bridge`
raises a :class:`RuntimeError` with installation guidance. Adapters
that want the same v4-only test-time behaviour can ``except`` that
error and fall back to the v4 :class:`PolicyInterceptor`.
"""

from __future__ import annotations

import logging
import tempfile
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Protocol

import yaml

from .base import ExecutionContext, GovernancePolicy

logger = logging.getLogger("agent_os.integrations.v5_bridge")


class _ExecutionContextLike(Protocol):
    agent_id: str
    session_id: str
    call_count: int
    total_tokens: int


@dataclass
class TransformOutcome:
    """Payload rewrite produced by an AGT transform verdict (D1.1).

    ``path`` is the AGT D1.1 path the engine resolved against
    ``$policy_target``; ``value`` is the replacement value that the
    adapter must substitute into the outbound call before forwarding
    it to the wrapped framework client.
    """

    path: str
    value: Any
    applied_value: Any = None


@dataclass
class BridgeResult:
    """Aggregated AGT evaluation result the adapter consumes.

    Wraps the v5 :class:`agt.policies.result.EvaluationResult` and the
    derived v4 :class:`PolicyCheckResult` so adapters can keep emitting
    the v4 audit shape while gaining access to the new verdicts.
    """

    evaluation: Any  # agt.policies.result.EvaluationResult
    check_result: Any  # agent_os.policies.decision.PolicyCheckResult
    transform: TransformOutcome | None = None

    @property
    def allowed(self) -> bool:
        return bool(self.evaluation.is_allowed())

    @property
    def verdict(self) -> str:
        return str(self.evaluation.verdict)

    @property
    def reason(self) -> str:
        return str(self.evaluation.reason or "")

    @property
    def input_identity(self) -> str | None:
        return self.evaluation.input_identity

    @property
    def enforced_identity(self) -> str | None:
        return self.evaluation.enforced_identity

    @property
    def transformed_value(self) -> Any:
        if self.transform is None:
            return None
        if self.transform.applied_value is not None:
            return self.transform.applied_value
        return self.transform.value

    def to_legacy_tuple(self) -> tuple[bool, str]:
        """Return the v4 ``(allowed, reason)`` tuple."""
        return self.allowed, self.reason

    @property
    def public_message(self) -> str:
        return str(self.check_result.public_message or self.reason)

    def to_policy_violation(self, error_type: Any) -> Exception:
        result = self.check_result
        details = {
            "category": result.category.value if result.category else None,
            "matched_rule": result.matched_rule,
            "detail": result.detail,
            "scope": result.scope,
            "operation": result.operation,
            "tool_name": result.tool_name,
            **result.audit_entry,
        }
        error = error_type(result.public_message, "POLICY_VIOLATION", details)
        error.check_result = result
        return error


class AdapterRuntimeBridge:
    """v4 → v5 routing helper attached to every v5-routed adapter kernel.

    Construct one bridge per adapter kernel instance. The bridge owns the
    per-policy memoisation cache and one native session per v4 execution
    context, so a single kernel can govern many concurrent agents without
    re-translating the manifest.
    """

    _cache: dict[tuple[int, int], Any] = {}

    def __init__(
        self,
        policy: GovernancePolicy,
        *,
        approval_resolver: Callable[..., Any] | None = None,
        runtime: Any | None = None,
        runtime_factory: Callable[[GovernancePolicy], Any] | None = None,
    ) -> None:
        if not isinstance(policy, GovernancePolicy):
            raise TypeError(
                "AdapterRuntimeBridge requires a GovernancePolicy, "
                f"got {type(policy).__name__}"
            )
        self._policy = policy
        self._approval_resolver = approval_resolver
        self._runtime_factory = runtime_factory
        self._injected_runtime = runtime
        self._factory_runtime: Any | None = None
        self._sessions: dict[str, Any] = {}

    @property
    def policy(self) -> GovernancePolicy:
        return self._policy

    @property
    def runtime(self) -> Any:
        """Return the underlying :class:`AgtRuntime`, building it once.

        The cache key is ``(hash(policy), id(approval_resolver))`` so
        two kernels sharing a structurally-equal policy object reuse
        the same runtime. ``hash(policy)`` is content-based per the v4
        :class:`GovernancePolicy.__hash__` so the cache stays correct
        when Python recycles object ``id``s across tests.
        """
        if self._injected_runtime is not None:
            return self._injected_runtime
        if self._runtime_factory is not None:
            if self._factory_runtime is None:
                self._factory_runtime = self._runtime_factory(self._policy)
            return self._factory_runtime
        try:
            policy_key = hash(self._policy)
        except TypeError:
            policy_key = id(self._policy)
        key = (policy_key, id(self._approval_resolver))
        cached = AdapterRuntimeBridge._cache.get(key)
        if cached is not None:
            return cached
        runtime = _build_runtime(self._policy, self._approval_resolver)
        AdapterRuntimeBridge._cache[key] = runtime
        return runtime

    # ── snapshot builder lifecycle ─────────────────────────────────

    def builder_for(self, ctx: ExecutionContext) -> Any:
        """Return the :class:`SnapshotBuilder` bound to ``ctx``.

        The builder is created on first access and reused across
        intervention points. Host counters such as ``ctx.call_count``
        and ``ctx.total_tokens`` are mirrored into the builder on every
        access so the AGT engine sees the current budget values.
        """
        return self._session_for(ctx).builder

    def _session_for(self, ctx: _ExecutionContextLike) -> Any:
        """Return the native session shim bound to ``ctx``."""
        from agt.policies.session import AdapterRuntimeSession

        key = ctx.session_id or ctx.agent_id
        session = self._sessions.get(key)
        if session is None:
            session = AdapterRuntimeSession(
                self.runtime,
                agent_id=ctx.agent_id,
                session_id=ctx.session_id or f"{ctx.agent_id}-session",
            )
            self._sessions[key] = session
        session.synchronize_counters(
            tool_call_count=int(ctx.call_count),
            token_count=int(ctx.total_tokens),
        )
        return session

    def evaluate_tool_budget(
        self, ctx: ExecutionContext
    ) -> BridgeResult | None:
        """Return a deny ``BridgeResult`` if the call/token budget is exceeded.

        For governed surfaces that are budgeted operations but are not named
        tool calls routed through ``pre_tool_call`` (e.g. a LlamaIndex
        ``.query()``), this mirrors the v4 direct ``ctx.call_count`` /
        ``ctx.total_tokens`` comparison so ``max_tool_calls`` / ``max_tokens``
        stay enforced. Returns ``None`` when within limits.
        """
        return _host_budget_check(self._policy, ctx)

    def record_post_execute(
        self, ctx: ExecutionContext, *, tokens: int = 0, tool_calls: int = 0
    ) -> None:
        """Advance the SnapshotBuilder budgets after a successful call.

        Mirrors the v4 ``ctx.call_count += 1`` /
        ``ctx.total_tokens += usage`` pattern so the next intervention
        point sees the running budget.
        """
        self._session_for(ctx).record_usage(
            tool_calls=tool_calls,
            tokens=int(tokens),
        )

    # ── intervention-point dispatchers ─────────────────────────────

    def evaluate_input(
        self,
        ctx: ExecutionContext,
        *,
        body: Any,
        source: str = "user",
        headers: dict[str, str] | None = None,
    ) -> BridgeResult:
        evaluation = self._session_for(ctx).evaluate_input(
            body=body if isinstance(body, str | dict) else str(body),
            source=source,
            headers=headers,
        )
        result = self._bridge_native_evaluation(evaluation)
        # v4 ``require_human_approval`` blocks every pre-execute when no
        # resolver is wired (the v4 base evaluator returned a synthetic
        # deny). The AGT manifest bridge encodes the rule via the
        # stock ``approval.escalate_if_approver_required`` helper that
        # fires at every bound intervention point — but the bridge only
        # binds ``input`` when ``blocked_patterns`` is non-empty, so a
        # policy with ``require_human_approval=True`` alone would slip
        # through. Apply the v4 contract as a host-side guard.
        if (
            result.verdict == "allow"
            and self._policy.require_human_approval
            and self._approval_resolver is None
        ):
            return _host_human_approval_deny()
        return result

    def evaluate_pre_tool_call(
        self,
        ctx: ExecutionContext,
        *,
        tool_name: str,
        args: Mapping[str, Any],
        call_id: str = "call-1",
    ) -> BridgeResult:
        evaluation = self._session_for(ctx).evaluate_pre_tool_call(
            tool_name=tool_name,
            args=dict(args),
            call_id=call_id,
            # Existing adapters charge successful calls through
            # record_post_execute. Phase 3 removes this compatibility override.
            count_attempt=False,
        )
        result = self._bridge_native_evaluation(evaluation)
        # AGT-M3 round-2 BLOCK A: after the bridge fix the manifest now
        # binds ``pre_tool_call`` whenever ``max_tool_calls >= 0`` (i.e.
        # always, since the field is a non-negative int) and emits the
        # stock ``budgets.deny_if_budget_exceeded`` rule even for
        # ``max_tool_calls == 0``. The engine therefore denies on the
        # very first call with ``budget_tool_calls_exceeded``; there is
        # no live execution path that leaves a v4 budget breach as
        # ``allow`` here. The fallback below is retained as
        # defense-in-depth only: it still fires if a future bridge
        # regression reintroduces the ``unbound_intervention_point``
        # rewrite for the v4 budget contract. Removing it would make
        # such a regression silent again, which is precisely the
        # round-2 BLOCK A failure mode.
        fallback = result.evaluation.audit_entry.get("v5_fallback")
        if result.verdict == "allow" and fallback == "unbound_intervention_point":
            host_check = _host_budget_check(self._policy, ctx)
            if host_check is not None:
                return host_check
        return result

    def evaluate_post_tool_call(
        self,
        ctx: ExecutionContext,
        *,
        tool_name: str,
        args: Mapping[str, Any],
        result: Any,
        error: Any = None,
        duration_ms: float = 0.0,
        call_id: str = "call-1",
    ) -> BridgeResult:
        evaluation = self._session_for(ctx).evaluate_post_tool_call(
            tool_name=tool_name,
            args=dict(args),
            result=result,
            error=error,
            duration_ms=duration_ms,
            call_id=call_id,
        )
        return self._bridge_native_evaluation(evaluation)

    def evaluate_pre_model_call(
        self,
        ctx: ExecutionContext,
        *,
        model_name: str,
        messages: list[dict[str, Any]],
        tools: list[dict[str, Any]] | None = None,
        request_id: str = "req-1",
        model_vendor: str = "test",
    ) -> BridgeResult:
        evaluation = self._session_for(ctx).evaluate_pre_model_call(
            model_name=model_name,
            messages=list(messages),
            tools=tools,
            request_id=request_id,
            model_vendor=model_vendor,
        )
        return self._bridge_native_evaluation(evaluation)

    def evaluate_post_model_call(
        self,
        ctx: ExecutionContext,
        *,
        model_name: str,
        response: dict[str, Any],
        usage: dict[str, int] | None = None,
        request_id: str = "req-1",
        model_vendor: str = "test",
    ) -> BridgeResult:
        evaluation = self._session_for(ctx).evaluate_post_model_call(
            model_name=model_name,
            response=response,
            usage=usage,
            request_id=request_id,
            model_vendor=model_vendor,
            # Existing adapters call record_post_execute with token usage.
            # Avoid charging twice until they move to the native session.
            charge_usage=False,
        )
        return self._bridge_native_evaluation(evaluation)

    def evaluate_output(
        self,
        ctx: ExecutionContext,
        *,
        content: Any,
        message_chain: list[dict[str, Any]] | None = None,
    ) -> BridgeResult:
        evaluation = self._session_for(ctx).evaluate_output(
            content=content if isinstance(content, str | dict) else str(content),
            message_chain=message_chain,
        )
        return self._bridge_native_evaluation(evaluation)

    # ── internals ──────────────────────────────────────────────────

    def _bridge_native_evaluation(self, native_evaluation: Any) -> BridgeResult:
        """Apply only v4 compatibility semantics to a native evaluation."""
        from agt.policies.result import EvaluationResult

        evaluation = EvaluationResult.from_native(native_evaluation)
        # The bridge-generated AGT manifest only binds the intervention
        # points that match the v4 GovernancePolicy fields it could
        # translate (per agt.policies.bridge). Calls at unbound
        # intervention points return ``runtime_error:intervention_point_unknown``
        # which is the ACS fail-closed default. For the v4 adapters that
        # is logically equivalent to ``allow`` (the v4 base did nothing
        # when no rule fired). Rewrite the result so the adapter does
        # not surface a synthetic deny.
        if (
            evaluation.verdict == "deny"
            and evaluation.reason == "runtime_error:intervention_point_unknown"
        ):
            evaluation = self._rewrite_as_allow(
                evaluation, fallback_tag="unbound_intervention_point"
            )
        # v4 semantics: an empty ``allowed_tools`` list means "no
        # allowlist" — every tool is permitted. The bridge still binds
        # ``pre_tool_call`` whenever ``max_tool_calls > 0`` and ACS
        # fails closed with ``runtime_error:tool_unknown`` for any tool
        # name absent from the catalog. Mirror the v4 default-permit
        # behaviour when the host has not configured an explicit tool
        # allowlist.
        elif (
            evaluation.verdict == "deny"
            and evaluation.reason == "runtime_error:tool_unknown"
            and not self._policy.allowed_tools
        ):
            evaluation = self._rewrite_as_allow(
                evaluation, fallback_tag="empty_allowed_tools"
            )
        transform: TransformOutcome | None = None
        if evaluation.verdict == "transform" and evaluation.transform is not None:
            transform = TransformOutcome(
                path=str(evaluation.transform.get("path", "")),
                value=evaluation.transform.get("value"),
                applied_value=evaluation.transform.get("applied_value"),
            )
        try:
            check_result = evaluation.to_v4_check_result()
        except ImportError:
            # Should not happen because the adapter that calls this
            # always has agent_os installed, but degrade safely.
            from agent_os.policies.decision import PolicyCheckResult

            check_result = PolicyCheckResult(
                allowed=evaluation.is_allowed(),
                action="allow" if evaluation.is_allowed() else "deny",
                reason=evaluation.reason or "",
            )
        return BridgeResult(
            evaluation=evaluation,
            check_result=check_result,
            transform=transform,
        )

    @staticmethod
    def _rewrite_as_allow(evaluation: Any, *, fallback_tag: str) -> Any:
        """Rewrite a fail-closed AGT runtime-error deny into an ``allow``.

        Used to bridge v4 default-permit semantics that the AGT manifest
        bridge translates into a fail-closed ACS verdict (e.g. an
        unbound intervention point, an empty tools allowlist). The
        verdict's ``audit_entry`` records the rewrite via
        ``v5_fallback`` so the audit consumer can still see that the
        engine fired but the adapter softened it.
        """
        return evaluation.model_copy(
            update={
                "verdict": "allow",
                "allowed": True,
                "reason": "",
                "message": "",
                "audit_entry": {
                    **evaluation.audit_entry,
                    "verdict": "allow",
                    "v5_fallback": fallback_tag,
                },
            }
        )


# ── runtime factory ──────────────────────────────────────────────────


def _host_human_approval_deny() -> BridgeResult:
    """Return the host-side deny for ``require_human_approval=True``.

    Reachable only on the ``input`` intervention point when:

    * the policy sets ``require_human_approval=True``;
    * the policy has no ``blocked_patterns`` (so the bridge does not
      bind ``input`` in the generated manifest and the engine
      auto-rewrites the result to ``allow`` via the
      ``runtime_error:intervention_point_unknown`` rewrite); and
    * no ``approval_resolver`` is wired on the AgtRuntime.

    Mirrors the v4 ``deny_human_approval`` factory so kernels that
    have not configured an approval resolver keep the v4 blocking
    semantics for ``require_human_approval=True``. The AGT-M3 bridge
    gap fix always binds ``pre_tool_call`` for this same policy, so
    the equivalent fallback on the pre-tool path is unreachable and
    intentionally absent.
    """
    from agt.policies.result import EvaluationResult

    evaluation = EvaluationResult(
        allowed=False,
        verdict="deny",
        reason="human_approval_required",
        message="action requires human approval",
        audit_entry={
            "verdict": "deny",
            "v5_fallback": "host_require_human_approval",
        },
    )
    return BridgeResult(
        evaluation=evaluation,
        check_result=evaluation.to_v4_check_result(),
        transform=None,
    )


def _host_budget_check(
    policy: GovernancePolicy, ctx: ExecutionContext
) -> BridgeResult | None:
    """Return a deny :class:`BridgeResult` when the v4 budgets fail.

    AGT-M3 round-2 BLOCK A defense-in-depth. The bridge fix now binds
    ``pre_tool_call`` and emits the stock
    ``budgets.deny_if_budget_exceeded`` rule for ``max_tool_calls >= 0``
    (any non-negative limit, including the v4 deny-every-call sentinel
    ``max_tool_calls == 0``), so the engine itself denies with the v5
    wire reason ``budget_tool_calls_exceeded`` before this fallback can
    run. Kept here so that a future bridge regression that drops the
    pre_tool_call binding back to the synthetic ``allow`` fallback
    cannot silently restore the round-2 BLOCK A failure mode where a
    v4 budget breach slipped through as ``allow``. Mirrors the v4
    semantics (the v4 base.py compared ``ctx.call_count`` and
    ``ctx.total_tokens`` directly). Returns ``None`` when the budgets
    are still within limits.
    """
    from agt.policies.result import EvaluationResult

    if policy.max_tool_calls >= 0 and ctx.call_count >= policy.max_tool_calls:
        evaluation = EvaluationResult(
            allowed=False,
            verdict="deny",
            reason="max_tool_calls",
            message=(
                f"tool_call_count {ctx.call_count} reached limit "
                f"{policy.max_tool_calls}"
            ),
            audit_entry={
                "verdict": "deny",
                "v5_fallback": "host_budget_max_tool_calls",
            },
        )
        return BridgeResult(
            evaluation=evaluation,
            check_result=evaluation.to_v4_check_result(),
            transform=None,
        )
    if policy.max_tokens > 0 and ctx.total_tokens >= policy.max_tokens:
        evaluation = EvaluationResult(
            allowed=False,
            verdict="deny",
            reason="max_tokens",
            message=(
                f"token_count {ctx.total_tokens} reached limit "
                f"{policy.max_tokens}"
            ),
            audit_entry={
                "verdict": "deny",
                "v5_fallback": "host_budget_max_tokens",
            },
        )
        return BridgeResult(
            evaluation=evaluation,
            check_result=evaluation.to_v4_check_result(),
            transform=None,
        )
    return None


def _build_runtime(
    policy: GovernancePolicy,
    approval_resolver: Callable[..., Any] | None,
) -> Any:
    """Build a real :class:`AgtRuntime` from a v4 ``GovernancePolicy``.

    Translates the policy to an AGT manifest via
    :func:`agt.policies.bridge.governance_to_acs_manifest`, writes the
    manifest YAML into the same bundle directory the bridge created
    for the generated Rego module, and constructs the runtime over the
    resulting manifest path.
    """
    try:
        from agt.policies.bridge import governance_to_acs_manifest
        from agt.policies.runtime import AgtRuntime
    except ImportError as exc:  # pragma: no cover - guarded by adapter callers
        raise RuntimeError(
            "AdapterRuntimeBridge requires the agt-policies package and the "
            "agent_control_specification native binding to be installed. "
            "Install agt-policies from agent-governance-python/agt-policies and "
            "build the ACS Python SDK from policy-engine/sdk/python."
        ) from exc

    bundle_dir = Path(tempfile.mkdtemp(prefix="agt_adapter_bundle_"))
    manifest = governance_to_acs_manifest(policy, bundle_dir=bundle_dir)
    # AGT-DELTA D5: the manifest bridge now emits a v5-valid ``approval``
    # section (an empty object) when ``require_human_approval=True``
    # (see agt.policies.bridge.governance_to_acs_manifest after commit
    # a19a7e09). The host wires the resolver on the AgtRuntime
    # constructor, and the Rego's ``approval.escalate_if_approver_required``
    # rule fires the escalate verdict that the runtime routes through
    # that resolver. Forwarding the section verbatim is required; the
    # earlier ``manifest.pop("approval", None)`` defense stripped the
    # section before the runtime could see it, which suppressed the
    # escalate path for every adapter using the bridge.
    manifest_path = bundle_dir / "manifest.yaml"
    manifest_path.write_text(
        yaml.safe_dump(manifest, sort_keys=False), encoding="utf-8"
    )
    return AgtRuntime(manifest_path, approval_resolver=approval_resolver)


def get_runtime_bridge(
    policy: GovernancePolicy,
    *,
    approval_resolver: Callable[..., Any] | None = None,
    runtime: Any | None = None,
    runtime_factory: Callable[[GovernancePolicy], Any] | None = None,
) -> AdapterRuntimeBridge:
    """Return a fresh :class:`AdapterRuntimeBridge` for ``policy``.

    Adapters call this once per kernel instance. Pass ``runtime`` to
    inject a pre-built :class:`AgtRuntime` (used by scenario tests
    that wire a scripted policy dispatcher). Pass ``runtime_factory``
    to override the default bridge-based factory while still using the
    per-(policy, resolver) memoisation cache.
    """
    return _new_compatibility_bridge(
        policy,
        approval_resolver=approval_resolver,
        runtime=runtime,
        runtime_factory=runtime_factory,
    )


def _new_compatibility_bridge(
    policy: Any,
    *,
    approval_resolver: Callable[..., Any] | None = None,
    runtime: Any | None = None,
    runtime_factory: Callable[[Any], Any] | None = None,
) -> Any:
    return AdapterRuntimeBridge(
        policy,
        approval_resolver=approval_resolver,
        runtime=runtime,
        runtime_factory=runtime_factory,
    )


def get_adapter_runtime(
    *,
    policy: Any,
    runtime: Any | None,
    approval_resolver: Callable[..., Any] | None = None,
    legacy_runtime: Any | None = None,
    legacy_runtime_factory: Callable[[Any], Any] | None = None,
) -> Any:
    """Select the native path or retain the compatibility edge."""
    if runtime is not None:
        owned_resolver = getattr(runtime, "_approval_resolver", None)
        if (
            approval_resolver is not None
            and owned_resolver is not approval_resolver
        ):
            raise ValueError(
                "approval_resolver belongs to AgtRuntime when runtime is provided"
            )
        if legacy_runtime is not None or legacy_runtime_factory is not None:
            raise ValueError(
                "runtime cannot be combined with _runtime or _runtime_factory"
            )
        from ._native_adapter_runtime import NativeAdapterRuntime

        return NativeAdapterRuntime(runtime)
    return _new_compatibility_bridge(
        policy,
        approval_resolver=approval_resolver,
        runtime=legacy_runtime,
        runtime_factory=legacy_runtime_factory,
    )


__all__ = [
    "AdapterRuntimeBridge",
    "BridgeResult",
    "TransformOutcome",
    "get_runtime_bridge",
    "get_adapter_runtime",
]
