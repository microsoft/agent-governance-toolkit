# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""Governance skill for OpenShell sandboxed agents.

Provides policy evaluation, trust scoring, identity verification, and
audit logging that any agent inside an OpenShell sandbox can invoke.
"""

from __future__ import annotations

import re
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Optional

import yaml


@dataclass
class PolicyDecision:
    """Result of a policy evaluation."""

    allowed: bool
    action: str
    reason: str
    policy_name: Optional[str] = None
    trust_score: float = 0.0


@dataclass
class _PolicyRule:
    """Internal representation of a loaded policy rule."""

    name: str
    field: str
    operator: str
    value: Any
    action: str  # allow / deny / escalate
    priority: int = 0
    message: str = ""


class GovernanceSkill:
    """AGT governance skill for OpenShell sandboxes.

    Loads YAML policies and evaluates agent actions against them,
    tracks per-agent trust scores, and maintains an audit log.

    Args:
        policy_dir: Directory containing YAML policy files.
        trust_threshold: Minimum trust score for action approval.
    """

    def __init__(
        self,
        policy_dir: Optional[Path] = None,
        trust_threshold: float = 0.5,
    ) -> None:
        self._rules: list[_PolicyRule] = []
        self._trust_scores: dict[str, float] = {}
        self._audit_log: list[dict] = []
        self._trust_threshold = trust_threshold

        if policy_dir:
            self.load_policies(policy_dir)

    def load_policies(self, policy_dir: Path) -> int:
        """Load all YAML policies from a directory.

        Returns:
            Number of rules loaded.
        """
        policy_dir = Path(policy_dir)
        if not policy_dir.is_dir():
            raise FileNotFoundError(f"Policy directory not found: {policy_dir}")

        self._rules.clear()
        for yaml_file in sorted(policy_dir.glob("*.yaml")):
            with open(yaml_file, encoding="utf-8") as f:
                doc = yaml.safe_load(f)
            if not doc:
                continue
            for rule_data in doc.get("rules", []):
                cond = rule_data.get("condition", {})
                self._rules.append(
                    _PolicyRule(
                        name=rule_data.get("name", yaml_file.stem),
                        field=cond.get("field", "action"),
                        operator=cond.get("operator", "equals"),
                        value=cond.get("value", ""),
                        action=rule_data.get("action", "deny"),
                        priority=rule_data.get("priority", 0),
                        message=rule_data.get("message", ""),
                    )
                )
        # Higher priority rules evaluate first
        self._rules.sort(key=lambda r: r.priority, reverse=True)
        return len(self._rules)

    def check_policy(
        self,
        action: str,
        context: Optional[dict] = None,
    ) -> PolicyDecision:
        """Evaluate an action against loaded policies.

        Args:
            action: The action string (e.g., "shell:rm -rf /tmp").
            context: Optional context dict with additional fields.

        Returns:
            PolicyDecision with allow/deny and reason.
        """
        context = context or {}
        agent_did = context.get("agent_did", "unknown")
        trust = self.get_trust_score(agent_did)

        for rule in self._rules:
            target = action if rule.field == "action" else context.get(rule.field, "")
            if self._match(rule.operator, target, rule.value):
                allowed = rule.action == "allow"
                reason = rule.message or f"{'Allowed' if allowed else 'Denied'} by rule: {rule.name}"
                decision = PolicyDecision(
                    allowed=allowed,
                    action=action,
                    reason=reason,
                    policy_name=rule.name,
                    trust_score=trust,
                )
                self.log_action(action, "allow" if allowed else "deny", agent_did, context)
                return decision

        # No rule matched — default deny
        decision = PolicyDecision(
            allowed=False,
            action=action,
            reason="No matching policy rule — default deny",
            trust_score=trust,
        )
        self.log_action(action, "deny", agent_did, context)
        return decision

    def get_trust_score(self, agent_did: str) -> float:
        """Return the trust score for an agent DID.

        Unknown agents start at 1.0 (full trust, decays on violations).
        """
        return self._trust_scores.get(agent_did, 1.0)

    def adjust_trust(self, agent_did: str, delta: float) -> float:
        """Adjust trust score by delta, clamped to [0.0, 1.0]."""
        current = self.get_trust_score(agent_did)
        new_score = max(0.0, min(1.0, current + delta))
        self._trust_scores[agent_did] = new_score
        return new_score

    def log_action(
        self,
        action: str,
        decision: str,
        agent_did: str = "unknown",
        context: Optional[dict] = None,
    ) -> dict:
        """Create an audit log entry.

        Returns:
            The created audit entry dict.
        """
        entry = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "action": action,
            "decision": decision,
            "agent_did": agent_did,
            "trust_score": self.get_trust_score(agent_did),
            "context": context or {},
        }
        self._audit_log.append(entry)
        return entry

    def get_audit_log(self, limit: int = 50) -> list[dict]:
        """Return the most recent audit log entries."""
        return self._audit_log[-limit:]

    @staticmethod
    def _match(operator: str, target: str, value: Any) -> bool:
        """Evaluate a single condition."""
        if operator == "equals":
            return target == value
        if operator == "starts_with":
            return target.startswith(str(value))
        if operator == "contains":
            return str(value) in target
        if operator == "matches":
            return bool(re.search(str(value), target))
        if operator == "in":
            return target in (value if isinstance(value, list) else [value])
        return False
