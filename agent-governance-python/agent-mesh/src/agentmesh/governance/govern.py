# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""
High-level governance wrapper — 2-line integration for any agent framework.

Usage:
    from agentmesh.governance.govern import govern, GovernanceConfig

    governed_fn = govern(my_tool_function, policy="my-policy.yaml")
    result = governed_fn(action="read", resource="users")

Or wrap an entire callable (agent, tool, function):
    from agentmesh.governance import govern
    safe_agent = govern(agent.run, policy="org-policy.yaml")
"""

from __future__ import annotations

import functools
import logging
import os
import re
import time
from dataclasses import dataclass
from typing import TYPE_CHECKING, Any, Callable, Optional, Union

from .policy import Policy, PolicyDecision, PolicyEngine
from .audit import AuditLog
from .approval import ApprovalHandler, ApprovalRequest, AutoRejectApproval
from .advisory import AdvisoryCheck, AdvisoryDecision
from .approval_protocol import (
    ActionBinding,
    ActionTarget,
    ApprovalCoordinator,
    ApprovalProtocolError,
    ApproverKind,
    EntryDecision,
)

if TYPE_CHECKING:
    from hypervisor.models import ExecutionRing

logger = logging.getLogger(__name__)

# Module-level shared ring breach detector, keyed by (agent_id, session_id).
# A single agent's violation budget MUST be tracked across every governed
# callable it owns. Without sharing, a rogue agent with N tools could spend
# the full per-detector violation budget N times before the breaker trips.
_SHARED_BREACH_DETECTORS: "dict[tuple[str, str], Any]" = {}


def _get_shared_breach_detector(agent_id: str, session_id: str) -> Any:
    """Return the singleton RingBreachDetector for (agent_id, session_id)."""
    key = (agent_id, session_id)
    detector = _SHARED_BREACH_DETECTORS.get(key)
    if detector is None:
        from hypervisor.rings.breach_detector import RingBreachDetector
        detector = RingBreachDetector()
        _SHARED_BREACH_DETECTORS[key] = detector
    return detector


def _reset_shared_breach_detectors() -> None:
    """Test-only helper to clear the shared detector registry."""
    _SHARED_BREACH_DETECTORS.clear()


# Resource-type inference uses exact-token match on action strings split by
# non-alphanumeric chars. Substring matching was unsafe: e.g.
# "set_httponly_flag" must not infer NETWORK from "http", and
# "overwrite_protection_check" must not infer FILESYSTEM from "write".
_SUBPROCESS_TOKENS = frozenset({
    "subprocess", "exec", "shell", "spawn", "fork", "execve", "popen", "system",
})
_NETWORK_TOKENS = frozenset({
    "network", "http", "https", "request", "fetch", "url", "web",
    "socket", "tcp", "udp", "dns",
})
_FILESYSTEM_TOKENS = frozenset({
    "write", "filesystem", "mkdir", "rmdir", "rm", "chmod",
    "unlink", "rename", "truncate",
})

_TOKEN_SPLIT_RE = re.compile(r"[^a-z0-9]+")


def _infer_resource_type(action_type: str) -> Any:
    """Infer the ring ResourceType from an action string using exact token match."""
    from agentmesh.governance import ResourceType
    tokens = {t for t in _TOKEN_SPLIT_RE.split(action_type.lower()) if t}
    if tokens & _SUBPROCESS_TOKENS:
        return ResourceType.SUBPROCESS
    if tokens & _NETWORK_TOKENS:
        return ResourceType.NETWORK
    if tokens & _FILESYSTEM_TOKENS:
        return ResourceType.FILESYSTEM
    return ResourceType.TOOL_EXECUTION


@dataclass
class GovernanceConfig:
    """Configuration for the govern() wrapper.

    Attributes:
        policy: Policy file path, YAML string, or Policy object.
        agent_id: Agent identifier for policy evaluation. Defaults to "*".
        audit: Whether to enable audit logging. Defaults to True.
        audit_file: Path for file-based audit log. None = in-memory only.
        on_deny: Callback when a policy denies an action. Default: raise.
        conflict_strategy: Policy conflict resolution strategy.
        ring: Optional execution ring for the agent. When set, ring-level
            resource constraints are enforced before policy evaluation and
            injected into the evaluation context as ``ring.*`` fields.
        session_id: Agent session identifier used by RingBreachDetector
            to track per-session violation rates. Defaults to "".
    """

    policy: Union[str, Policy]
    agent_id: str = "*"
    audit: bool = True
    audit_file: Optional[str] = None
    on_deny: Optional[Callable[[PolicyDecision], Any]] = None
    approval_handler: Optional[ApprovalHandler] = None
    advisory: Optional[AdvisoryCheck] = None
    conflict_strategy: str = "deny_overrides"
    ring: Optional["ExecutionRing"] = None
    session_id: str = ""
    # Action-bound approval protocol (ADR-0030). When both an
    # ``approval_coordinator`` and an ``approval_chain_id`` are set,
    # ``require_approval`` decisions are routed through the coordinator
    # (action-binding, audit linkage, fail-closed timeout) instead of the
    # legacy approval-handler-only path. The ``approval_handler`` is reused as
    # the synchronous source of the approver's decision.
    approval_coordinator: Optional[ApprovalCoordinator] = None
    approval_chain_id: Optional[str] = None
    approval_ttl_seconds: float = 300.0


class GovernanceDenied(Exception):
    """Raised when a governed action is denied by policy."""

    def __init__(self, decision: PolicyDecision):
        self.decision = decision
        super().__init__(
            f"Action denied by policy rule '{decision.matched_rule}': "
            f"{decision.reason}"
        )


class GovernedCallable:
    """Wraps any callable with policy enforcement and audit logging.

    This is the core primitive — framework-specific wrappers build on it.
    """

    def __init__(self, fn: Callable, config: GovernanceConfig):
        self._fn = fn
        self._config = config
        self._engine = PolicyEngine(conflict_strategy=config.conflict_strategy)
        self._audit = AuditLog() if config.audit else None

        # Load policy
        policy = config.policy
        if isinstance(policy, str):
            if os.path.isfile(policy):
                loaded = self._engine.load_yaml_file(policy)
            else:
                loaded = self._engine.load_yaml(policy)
        elif isinstance(policy, Policy):
            loaded = policy
            self._engine.load_policy(loaded)
        else:
            raise TypeError(
                f"policy must be a file path, YAML string, or Policy object, "
                f"got {type(policy).__name__}"
            )

        # Ensure the policy applies to our agent_id. If no agents are
        # specified, default to wildcard so govern() works out of the box.
        if not loaded.agent and not loaded.agents:
            loaded.agents = ["*"]

        # Policy version stamped onto action-bound approval records (ADR-0030),
        # so an approval is bound to the policy revision in effect when granted.
        self._policy_version = getattr(loaded, "version", "1.0") or "1.0"

        # Ring enforcement — only active when a ring is explicitly configured.
        self._ring_enforcer: Any = None
        self._breach_detector: Any = None
        if config.ring is not None:
            from hypervisor.rings.enforcer import RingEnforcer
            self._ring_enforcer = RingEnforcer()
            # Shared, (agent_id, session_id)-scoped detector so the circuit
            # breaker counts violations across ALL of an agent's governed
            # callables, not per-callable in isolation.
            self._breach_detector = _get_shared_breach_detector(
                config.agent_id, config.session_id or "default",
            )

        functools.update_wrapper(self, fn)

    def __call__(self, *args: Any, **kwargs: Any) -> Any:
        """Execute the wrapped function with governance enforcement."""
        # Build evaluation context from kwargs
        context = self._build_context(args, kwargs)

        # Ring enforcement — runs before policy evaluation so a denied ring
        # never reaches the policy engine.
        if self._ring_enforcer is not None and self._config.ring is not None:
            ring_denial = self._check_ring(context)
            if ring_denial is not None:
                if self._config.on_deny:
                    return self._config.on_deny(ring_denial)
                raise GovernanceDenied(ring_denial)

        # Evaluate policy
        start = time.monotonic()
        decision = self._engine.evaluate(self._config.agent_id, context)
        eval_ms = (time.monotonic() - start) * 1000

        # Handle require_approval
        if decision.action == "require_approval":
            decision = self._handle_approval(decision, context)

        # Audit
        if self._audit:
            self._audit.log(
                event_type="policy_evaluation",
                agent_did=self._config.agent_id,
                action=context.get("action", {}).get("type", "unknown"),
                outcome=decision.action,
                policy_decision=decision.action,
                data={
                    "rule": decision.matched_rule or "",
                    "reason": decision.reason or "",
                    "evaluation_ms": round(eval_ms, 3),
                },
            )

        # Handle decision
        if not decision.allowed:
            if self._config.on_deny:
                return self._config.on_deny(decision)
            raise GovernanceDenied(decision)

        # Advisory layer — runs ONLY after deterministic allow
        if self._config.advisory and decision.allowed:
            advisory_result = self._run_advisory(context)
            if advisory_result and advisory_result.action == "block":
                blocked = PolicyDecision(
                    allowed=False,
                    action="deny",
                    matched_rule=f"advisory:{advisory_result.classifier}",
                    reason=f"[Advisory, non-deterministic] {advisory_result.reason}",
                )
                if self._config.on_deny:
                    return self._config.on_deny(blocked)
                raise GovernanceDenied(blocked)

        # Allowed — execute the wrapped function
        return self._fn(*args, **kwargs)

    def _check_ring(self, context: dict) -> Optional[PolicyDecision]:
        """Enforce ring-level resource constraints and inject ring context.

        Returns a denial PolicyDecision when the agent's ring forbids the
        requested resource, or None when access is permitted. Also injects
        ``ring`` and ``ring_constraints`` into *context* so downstream policy
        rules can reference them (e.g. ``ring.subprocess_allowed == false``).
        """
        from hypervisor.rings.enforcer import RING_CONSTRAINTS

        ring = self._config.ring

        # Circuit-breaker: if this agent/session has tripped the breaker from
        # prior violations, deny immediately without consulting the ring enforcer.
        session_id = self._config.session_id or "default"
        if self._breach_detector.is_breaker_tripped(self._config.agent_id, session_id):
            return PolicyDecision(
                allowed=False,
                action="deny",
                matched_rule="ring_breaker",
                reason=(
                    f"Circuit breaker tripped for agent '{self._config.agent_id}' "
                    f"— too many ring violations in session '{session_id}'"
                ),
            )

        # Infer the resource type from the action in context. Uses exact
        # token match (split on non-alphanumerics) to avoid false positives
        # like "set_httponly_flag" being classified as NETWORK or
        # "overwrite_protection_check" as FILESYSTEM.
        action_type = context.get("action", {}).get("type", "")
        resource_type = _infer_resource_type(action_type)

        ring_result = self._ring_enforcer.check_resource(ring, resource_type)

        # Always inject ring context so policy rules can reference it.
        constraints = self._ring_enforcer.get_constraints(ring)
        context["ring"] = {
            "level": ring.value,
            "subprocess_allowed": constraints.subprocess_allowed,
            "network_allowed": constraints.network_allowed,
            "filesystem_scope": constraints.filesystem_scope,
            "filesystem_writable": constraints.filesystem_writable,
        }

        if ring_result.allowed:
            return None

        # Find the minimum ring that allows this resource type so the breach
        # detector receives an accurate ring distance.
        from hypervisor.models import ExecutionRing
        called_ring = next(
            (
                r for r in (
                    ExecutionRing.RING_2_STANDARD,
                    ExecutionRing.RING_1_PRIVILEGED,
                    ExecutionRing.RING_0_ROOT,
                )
                if RING_CONSTRAINTS[r].allows_resource(resource_type)
            ),
            ExecutionRing.RING_1_PRIVILEGED,
        )
        self._breach_detector.record_call(
            self._config.agent_id, session_id, ring, called_ring
        )

        return PolicyDecision(
            allowed=False,
            action="deny",
            matched_rule="ring_enforcement",
            reason=(
                f"Ring {ring.value} agent cannot perform "
                f"{resource_type.value}: {ring_result.reason}"
            ),
        )

    def _handle_approval(self, decision: PolicyDecision, context: dict) -> PolicyDecision:
        """Route require_approval decisions to the approver.

        Uses the action-bound approval coordinator (ADR-0030) when both an
        ``approval_coordinator`` and an ``approval_chain_id`` are configured;
        otherwise falls back to the legacy approval-handler-only path.
        """
        if (
            self._config.approval_coordinator is not None
            and self._config.approval_chain_id is not None
        ):
            return self._handle_approval_via_coordinator(decision, context)

        handler = self._config.approval_handler or AutoRejectApproval()

        request = ApprovalRequest(
            action=context.get("action", {}).get("type", "unknown"),
            rule_name=decision.matched_rule or "",
            policy_name=decision.policy_name or "",
            agent_id=self._config.agent_id,
            context=context,
            approvers=decision.approvers,
        )

        approval = handler.request_approval(request)

        # Audit the approval decision
        if self._audit:
            self._audit.log(
                event_type="approval_decision",
                agent_did=self._config.agent_id,
                action=context.get("action", {}).get("type", "unknown"),
                outcome="approved" if approval.approved else "rejected",
                data={
                    "rule": decision.matched_rule or "",
                    "approver": approval.approver,
                    "reason": approval.reason,
                },
            )

        if approval.approved:
            return PolicyDecision(
                allowed=True,
                action="allow",
                matched_rule=decision.matched_rule,
                policy_name=decision.policy_name,
                reason=f"Approved by {approval.approver}: {approval.reason}",
            )
        else:
            return PolicyDecision(
                allowed=False,
                action="deny",
                matched_rule=decision.matched_rule,
                policy_name=decision.policy_name,
                reason=f"Approval rejected by {approval.approver}: {approval.reason}",
            )

    def _handle_approval_via_coordinator(
        self, decision: PolicyDecision, context: dict
    ) -> PolicyDecision:
        """Route require_approval through the action-bound coordinator (ADR-0030).

        The decision is bound to the exact action (digest), an approval request
        is opened against the configured chain, the configured approval handler
        supplies the approver's vote as one authenticated chain entry, and the
        request is revalidated immediately before execution. Anything short of a
        terminal allow over the same action/policy/chain version denies,
        fail-closed (including an unpermitted approver identity or an expired
        request).
        """
        coordinator = self._config.approval_coordinator
        binding = self._build_action_binding(context)

        decision_record, request = coordinator.open_request(
            binding,
            policy_rule_id=decision.matched_rule or "",
            policy_version=self._policy_version,
            chain_id=self._config.approval_chain_id,
            ttl_seconds=self._config.approval_ttl_seconds,
        )

        # The legacy handler is the synchronous source of the approver's vote;
        # its result becomes one authenticated chain entry at stage 0.
        handler = self._config.approval_handler or AutoRejectApproval()
        approval = handler.request_approval(
            ApprovalRequest(
                action=context.get("action", {}).get("type", "unknown"),
                rule_name=decision.matched_rule or "",
                policy_name=decision.policy_name or "",
                agent_id=self._config.agent_id,
                context=context,
                approvers=decision.approvers,
            )
        )

        verdict = None
        fail_reason: Optional[str] = None
        try:
            coordinator.submit_entry(
                request.approval_request_id,
                stage_index=0,
                approver_kind=ApproverKind.HUMAN,
                approver_identity=approval.approver or "unknown",
                identity_assurance="approval-handler",
                decision=(
                    EntryDecision.ALLOW if approval.approved else EntryDecision.DENY
                ),
                reason_code=approval.reason or "",
            )
        except ApprovalProtocolError as exc:
            # Unpermitted identity, expired request, etc. Fail closed.
            fail_reason = f"approval entry rejected: {exc}"
        else:
            verdict = coordinator.validate_for_execution(
                request.approval_request_id,
                current_action_digest=binding.digest(),
                current_policy_version=self._policy_version,
                current_chain_version=request.approval_chain_version,
            )

        allowed = bool(verdict and verdict.allowed)
        reason_code = verdict.reason_code if verdict is not None else fail_reason

        # Audit linkage: tie the entry to the protocol record ids and the action
        # digest (ADR-0030 section 7); reuse the AuditEntry assurance fields.
        resolution = coordinator.store.get_resolution(request.approval_request_id)
        if self._audit:
            self._audit.log(
                event_type="approval_decision",
                agent_did=self._config.agent_id,
                action=context.get("action", {}).get("type", "unknown"),
                outcome="approved" if allowed else "rejected",
                arguments_hash=binding.digest(),
                approver_did=approval.approver or None,
                policy_version=self._policy_version,
                data={
                    "rule": decision.matched_rule or "",
                    "approver": approval.approver,
                    "reason": approval.reason,
                    "reason_code": reason_code,
                    "policy_decision_id": decision_record.policy_decision_id,
                    "approval_request_id": request.approval_request_id,
                    "approval_resolution_id": (
                        resolution.approval_resolution_id if resolution else None
                    ),
                },
            )

        if allowed:
            return PolicyDecision(
                allowed=True,
                action="allow",
                matched_rule=decision.matched_rule,
                policy_name=decision.policy_name,
                reason=(
                    f"Approved by {approval.approver} "
                    f"(request {request.approval_request_id})"
                ),
            )
        return PolicyDecision(
            allowed=False,
            action="deny",
            matched_rule=decision.matched_rule,
            policy_name=decision.policy_name,
            reason=(
                f"Approval denied ({reason_code}) for request "
                f"{request.approval_request_id}"
            ),
        )

    def _build_action_binding(self, context: dict) -> ActionBinding:
        """Construct the ADR-0030 ActionBinding for the current call."""
        action = context.get("action", {})
        if isinstance(action, dict):
            action_type = action.get("type", "unknown")
            resource = action.get("resource")
        else:
            action_type = str(action)
            resource = None
        tool_name = getattr(self._fn, "__name__", None) or action_type
        subject = context.get("subject")
        subject_id = subject if isinstance(subject, str) else None
        # JSON-safe projection of the context so the action digest is stable and
        # reproducible at the execution boundary.
        parameters = {k: self._json_safe(v) for k, v in context.items()}
        return ActionBinding(
            operation="tool.invoke",
            agent_id=self._config.agent_id,
            target=ActionTarget(
                tool_name=str(tool_name),
                tool_schema_version="1",
                resource=resource if isinstance(resource, str) else None,
            ),
            parameters=parameters,
            subject_id=subject_id,
        )

    @staticmethod
    def _json_safe(value: Any) -> Any:
        """Coerce a value to JSON-canonicalizable types for the action digest."""
        if value is None or isinstance(value, (bool, int, float, str)):
            return value
        if isinstance(value, dict):
            return {
                str(k): GovernedCallable._json_safe(v) for k, v in value.items()
            }
        if isinstance(value, (list, tuple)):
            return [GovernedCallable._json_safe(v) for v in value]
        return str(value)

    def _build_context(self, args: tuple, kwargs: dict) -> dict:
        """Build policy evaluation context from function arguments."""
        context: dict[str, Any] = {}

        # If kwargs contains 'action', use it directly
        if "action" in kwargs:
            action_val = kwargs["action"]
            if isinstance(action_val, dict):
                context["action"] = action_val
            else:
                context["action"] = {"type": str(action_val)}
        elif args:
            context["action"] = {"type": str(args[0])}

        # Pass through other kwargs as context
        for key, val in kwargs.items():
            if key != "action":
                if isinstance(val, dict):
                    context[key] = val
                else:
                    context[key] = {"value": val}

        return context

    def _run_advisory(self, context: dict) -> Optional[AdvisoryDecision]:
        """Run the optional advisory check (defense-in-depth)."""
        advisory = self._config.advisory
        if not advisory:
            return None

        try:
            decision = advisory.check(context)

            # Log advisory decision
            if self._audit:
                self._audit.log(
                    event_type="advisory_check",
                    agent_did=self._config.agent_id,
                    action=context.get("action", {}).get("type", "unknown"),
                    outcome=decision.action,
                    data={
                        "classifier": decision.classifier,
                        "reason": decision.reason,
                        "confidence": decision.confidence,
                        "deterministic": False,
                    },
                )

            return decision
        except Exception as e:
            logger.warning("Advisory check failed: %s — allowing (fail-open)", e)
            return AdvisoryDecision(action="allow", reason=f"Error: {e}")

    @property
    def engine(self) -> PolicyEngine:
        """Access the underlying policy engine for advanced use."""
        return self._engine

    @property
    def audit_log(self) -> Optional[AuditLog]:
        """Access the audit log for inspection."""
        return self._audit


def govern(
    fn: Callable,
    *,
    policy: Union[str, Policy],
    agent_id: str = "*",
    audit: bool = True,
    on_deny: Optional[Callable[[PolicyDecision], Any]] = None,
    approval_handler: Optional[ApprovalHandler] = None,
    advisory: Optional[AdvisoryCheck] = None,
    conflict_strategy: str = "deny_overrides",
    ring: Optional["ExecutionRing"] = None,
    session_id: str = "",
    approval_coordinator: Optional[ApprovalCoordinator] = None,
    approval_chain_id: Optional[str] = None,
    approval_ttl_seconds: float = 300.0,
) -> GovernedCallable:
    """Wrap any callable with AGT governance — 2-line integration.

    Args:
        fn: The function, tool, or agent callable to govern.
        policy: Policy file path (supports ``extends``), inline YAML
            string, or a ``Policy`` object.
        agent_id: Agent identifier for policy evaluation. Default ``"*"``.
        audit: Enable audit logging. Default ``True``.
        on_deny: Optional callback on denial. Default: raise
            ``GovernanceDenied``.
        conflict_strategy: Conflict resolution strategy. Default
            ``"deny_overrides"`` (any deny wins).

    Returns:
        A ``GovernedCallable`` that enforces policy before execution.

    Example::

        from agentmesh.governance import govern

        def send_email(to, body):
            ...

        safe_send = govern(send_email, policy="email-policy.yaml")
        safe_send(to="user@example.com", body="Hello")  # policy-checked
    """
    config = GovernanceConfig(
        policy=policy,
        agent_id=agent_id,
        audit=audit,
        on_deny=on_deny,
        approval_handler=approval_handler,
        advisory=advisory,
        conflict_strategy=conflict_strategy,
        ring=ring,
        session_id=session_id,
        approval_coordinator=approval_coordinator,
        approval_chain_id=approval_chain_id,
        approval_ttl_seconds=approval_ttl_seconds,
    )
    return GovernedCallable(fn, config)
