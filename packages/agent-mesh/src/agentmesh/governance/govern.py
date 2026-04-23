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
import time
from dataclasses import dataclass, field
from typing import Any, Callable, Optional, Union

from .policy import Policy, PolicyDecision, PolicyEngine
from .audit import AuditLog

logger = logging.getLogger(__name__)


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
    """

    policy: Union[str, Policy]
    agent_id: str = "*"
    audit: bool = True
    audit_file: Optional[str] = None
    on_deny: Optional[Callable[[PolicyDecision], Any]] = None
    conflict_strategy: str = "deny_overrides"


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

        functools.update_wrapper(self, fn)

    def __call__(self, *args: Any, **kwargs: Any) -> Any:
        """Execute the wrapped function with governance enforcement."""
        # Build evaluation context from kwargs
        context = self._build_context(args, kwargs)

        # Evaluate policy
        start = time.monotonic()
        decision = self._engine.evaluate(self._config.agent_id, context)
        eval_ms = (time.monotonic() - start) * 1000

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

        # Allowed — execute the wrapped function
        return self._fn(*args, **kwargs)

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
    conflict_strategy: str = "deny_overrides",
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
        conflict_strategy=conflict_strategy,
    )
    return GovernedCallable(fn, config)
