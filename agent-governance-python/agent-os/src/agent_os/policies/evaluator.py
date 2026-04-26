# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""
Standalone policy evaluator for Agent-OS governance.

Evaluates declarative PolicyDocuments against an execution context dict,
returning a PolicyDecision with matched rule, action, and audit information.
"""

from __future__ import annotations

import logging
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from pydantic import BaseModel, Field

from .schema import PolicyAction, PolicyDocument, PolicyOperator, PolicyRule

logger = logging.getLogger(__name__)


class PolicyDecision(BaseModel):
    """Result of evaluating policies against an execution context."""

    allowed: bool = True
    matched_rule: str | None = None
    action: str = "allow"
    reason: str = "No rules matched; default action applied"
    audit_entry: dict[str, Any] = Field(default_factory=dict)


class PolicyEvaluator:
    """Evaluates a set of PolicyDocuments against execution contexts.

    Supports external policy backends (OPA/Rego, Cedar) alongside the
    native YAML/JSON engine. YAML rules are evaluated first; if no YAML
    rule matches, external backends are consulted in registration order.
    """

    def __init__(
        self,
        policies: list[PolicyDocument] | None = None,
        root_dir: str | Path | None = None,
    ) -> None:
        self.policies: list[PolicyDocument] = policies or []
        self.root_dir: Path | None = Path(root_dir) if root_dir else None
        self._backends: list[Any] = []

    def load_policies(self, directory: str | Path) -> None:
        """Load all YAML policy files from a directory."""
        directory = Path(directory)
        for path in sorted(directory.glob("*.yaml")):
            self.policies.append(PolicyDocument.from_yaml(path))
        for path in sorted(directory.glob("*.yml")):
            self.policies.append(PolicyDocument.from_yaml(path))

    def add_backend(self, backend: Any) -> None:
        """Register an external policy backend (OPA, Cedar, etc.).

        Backends are consulted in registration order when no YAML rule
        matches. Each backend must implement ``evaluate(context) ->
        BackendDecision`` and a ``name`` property.

        Args:
            backend: An ``ExternalPolicyBackend`` implementation such as
                ``OPABackend`` or ``CedarBackend`` from
                ``agent_os.policies.backends``.
        """
        self._backends.append(backend)

    def load_rego(
        self,
        rego_path: str | None = None,
        rego_content: str | None = None,
        package: str = "agentos",
    ) -> Any:
        """Convenience: register an OPA/Rego backend.

        Args:
            rego_path: Path to a ``.rego`` file.
            rego_content: Inline Rego policy string.
            package: Rego package name for query construction.

        Returns:
            The ``OPABackend`` instance.
        """
        from .backends import OPABackend

        backend = OPABackend(
            rego_path=rego_path, rego_content=rego_content, package=package
        )
        self.add_backend(backend)
        return backend

    def load_cedar(
        self,
        policy_path: str | None = None,
        policy_content: str | None = None,
        entities: list[dict[str, Any]] | None = None,
    ) -> Any:
        """Convenience: register a Cedar backend.

        Args:
            policy_path: Path to a ``.cedar`` policy file.
            policy_content: Inline Cedar policy string.
            entities: Cedar entities for authorization context.

        Returns:
            The ``CedarBackend`` instance.
        """
        from .backends import CedarBackend

        backend = CedarBackend(
            policy_path=policy_path,
            policy_content=policy_content,
            entities=entities,
        )
        self.add_backend(backend)
        return backend

    def evaluate(self, context: dict[str, Any]) -> PolicyDecision:
        """Evaluate all loaded policy rules against the given context.

        If ``root_dir`` is set and context contains a ``path`` key,
        folder-scoped policy discovery is used — governance.yaml files
        are loaded from the action path up to root and merged
        hierarchically. Otherwise, the flat policy list is evaluated.

        Rules are sorted by priority (descending). The first matching rule
        determines the decision. If no YAML rule matches and external
        backends are registered, they are consulted in order. If nothing
        matches, the default action from the first policy (or global allow)
        is used.
        """
        # Folder-scoped evaluation path
        if self.root_dir and "path" in context:
            return self._evaluate_scoped(context)

        # Flat evaluation (original behavior)
        return self._evaluate_flat(context)

    def _evaluate_scoped(self, context: dict[str, Any]) -> PolicyDecision:
        """Evaluate using folder-level policy discovery and merge."""
        from .discovery import discover_policies, filter_by_scope
        from .merge import merge_policies

        action_path = Path(context["path"])
        chain_paths = discover_policies(action_path, self.root_dir)

        if not chain_paths:
            # No governance files found — fall back to loaded policies
            return self._evaluate_flat(context)

        docs = [PolicyDocument.from_yaml(p) for p in chain_paths]

        # Filter by scope
        filtered = []
        for doc, path in zip(docs, chain_paths):
            if filter_by_scope(path, doc.scope, action_path, self.root_dir):
                filtered.append(doc)

        if not filtered:
            return self._evaluate_flat(context)

        merged_rules = merge_policies(filtered)
        return self._evaluate_rules(merged_rules, filtered, context)

    def _evaluate_flat(self, context: dict[str, Any]) -> PolicyDecision:
        """Flat evaluation using the loaded policy list (original behavior)."""
        try:
            all_rules: list[tuple[PolicyRule, PolicyDocument]] = []
            for doc in self.policies:
                for rule in doc.rules:
                    all_rules.append((rule, doc))

            # Sort by priority descending so highest priority is checked first
            all_rules.sort(key=lambda pair: pair[0].priority, reverse=True)

            for rule, doc in all_rules:
                if _match_condition(rule.condition, context):
                    allowed = rule.action in (PolicyAction.ALLOW, PolicyAction.AUDIT)
                    return PolicyDecision(
                        allowed=allowed,
                        matched_rule=rule.name,
                        action=rule.action.value,
                        reason=rule.message or f"Matched rule '{rule.name}'",
                        audit_entry={
                            "policy": doc.name,
                            "rule": rule.name,
                            "action": rule.action.value,
                            "context_snapshot": context,
                            "timestamp": datetime.now(timezone.utc).isoformat(),
                        },
                    )

            # No YAML rule matched — consult external backends
            for backend in self._backends:
                result = backend.evaluate(context)
                if result.error is None:
                    return PolicyDecision(
                        allowed=result.allowed,
                        matched_rule=None,
                        action=result.action,
                        reason=result.reason,
                        audit_entry={
                            "policy": f"external:{backend.name}",
                            "rule": None,
                            "action": result.action,
                            "backend": backend.name,
                            "evaluation_ms": result.evaluation_ms,
                            "context_snapshot": context,
                            "timestamp": datetime.now(timezone.utc).isoformat(),
                        },
                    )

            # No rule matched — apply defaults
            default_action = PolicyAction.ALLOW
            if self.policies:
                default_action = self.policies[0].defaults.action
            allowed = default_action in (PolicyAction.ALLOW, PolicyAction.AUDIT)
            return PolicyDecision(
                allowed=allowed,
                action=default_action.value,
                reason="No rules matched; default action applied",
                audit_entry={
                    "policy": self.policies[0].name if self.policies else None,
                    "rule": None,
                    "action": default_action.value,
                    "context_snapshot": context,
                    "timestamp": datetime.now(timezone.utc).isoformat(),
                },
            )
        except Exception:
            logger.error(
                "Policy evaluation error — denying access (fail closed)",
                exc_info=True,
            )
            return PolicyDecision(
                allowed=False,
                action="deny",
                reason="Policy evaluation error — access denied (fail closed)",
                audit_entry={
                    "policy": None,
                    "rule": None,
                    "action": "deny",
                    "context_snapshot": context,
                    "timestamp": datetime.now(timezone.utc).isoformat(),
                    "error": True,
                },
            )

    def _evaluate_rules(
        self,
        rules: list[PolicyRule],
        docs: list[PolicyDocument],
        context: dict[str, Any],
    ) -> PolicyDecision:
        """Evaluate a merged rule list from folder-scoped discovery."""
        try:
            for rule in rules:
                if _match_condition(rule.condition, context):
                    allowed = rule.action in (PolicyAction.ALLOW, PolicyAction.AUDIT)
                    return PolicyDecision(
                        allowed=allowed,
                        matched_rule=rule.name,
                        action=rule.action.value,
                        reason=rule.message or f"Matched rule '{rule.name}'",
                        audit_entry={
                            "policy": "folder-scoped",
                            "rule": rule.name,
                            "action": rule.action.value,
                            "policy_chain": [d.name for d in docs],
                            "context_snapshot": context,
                            "timestamp": datetime.now(timezone.utc).isoformat(),
                        },
                    )

            # No rule matched — consult external backends
            for backend in self._backends:
                result = backend.evaluate(context)
                if result.error is None:
                    return PolicyDecision(
                        allowed=result.allowed,
                        matched_rule=None,
                        action=result.action,
                        reason=result.reason,
                    )

            # Defaults from most specific policy
            default_action = docs[-1].defaults.action if docs else PolicyAction.ALLOW
            allowed = default_action in (PolicyAction.ALLOW, PolicyAction.AUDIT)
            return PolicyDecision(
                allowed=allowed,
                action=default_action.value,
                reason="No rules matched; default action applied",
                audit_entry={
                    "policy": "folder-scoped",
                    "policy_chain": [d.name for d in docs],
                    "context_snapshot": context,
                    "timestamp": datetime.now(timezone.utc).isoformat(),
                },
            )
        except Exception:
            logger.error("Scoped policy evaluation error — fail closed", exc_info=True)
            return PolicyDecision(
                allowed=False,
                action="deny",
                reason="Policy evaluation error — access denied (fail closed)",
            )


def _match_condition(condition: Any, context: dict[str, Any]) -> bool:
    """Check whether a single PolicyCondition matches the context."""
    ctx_value = context.get(condition.field)
    if ctx_value is None:
        return False

    op = condition.operator
    target = condition.value

    if op == PolicyOperator.EQ:
        return ctx_value == target
    if op == PolicyOperator.NE:
        return ctx_value != target
    if op == PolicyOperator.GT:
        return ctx_value > target
    if op == PolicyOperator.LT:
        return ctx_value < target
    if op == PolicyOperator.GTE:
        return ctx_value >= target
    if op == PolicyOperator.LTE:
        return ctx_value <= target
    if op == PolicyOperator.IN:
        return ctx_value in target
    if op == PolicyOperator.CONTAINS:
        return target in ctx_value
    if op == PolicyOperator.MATCHES:
        return bool(re.search(str(target), str(ctx_value)))

    return False
