# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""
Citadel + AGT Governed Agent Example

Demonstrates an AI agent governed by both Citadel (gateway-level) and
AGT (agent-level) policies working together. Supports local mock mode
for testing without Azure dependencies.

Usage:
    python agent.py --mock      # Local mode, no Azure required
    python agent.py             # With Citadel gateway (requires env vars)
"""

from __future__ import annotations

import argparse
import hashlib
import json
import logging
import os
import sys
import time
import uuid
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Optional

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
)
logger = logging.getLogger("citadel-governed-agent")


# ---------------------------------------------------------------------------
# Policy bundle loader
# ---------------------------------------------------------------------------

@dataclass
class PolicyBundle:
    """An AGT policy bundle loaded from YAML configuration."""

    name: str = ""
    version: str = ""
    data_classification: str = "internal"
    allowed_actions: list[str] = field(default_factory=list)
    blocked_actions: list[str] = field(default_factory=list)
    rate_limits: dict[str, dict[str, int]] = field(default_factory=dict)
    requires_justification: list[str] = field(default_factory=list)
    min_trust_score: int = 0
    log_all_decisions: bool = True
    hash_chain: bool = True

    @classmethod
    def from_yaml(cls, path: str) -> PolicyBundle:
        """Load a policy bundle from a YAML file."""
        try:
            import yaml
        except ImportError:
            logger.warning("PyYAML not installed, using default policy")
            return cls(name="default", version="0.0.0")

        with open(path) as f:
            data = yaml.safe_load(f)

        policy = data.get("policy", {})
        trust = policy.get("trust", {})
        audit = policy.get("audit", {})

        return cls(
            name=policy.get("name", "unnamed"),
            version=policy.get("version", "0.0.0"),
            data_classification=policy.get("data_classification", "internal"),
            allowed_actions=policy.get("allowed_actions", []),
            blocked_actions=policy.get("blocked_actions", []),
            rate_limits=policy.get("rate_limits", {}),
            requires_justification=policy.get("requires_justification", []),
            min_trust_score=trust.get("minimum_score", 0),
            log_all_decisions=audit.get("log_all_decisions", True),
            hash_chain=audit.get("hash_chain", True),
        )


# ---------------------------------------------------------------------------
# Governance engine
# ---------------------------------------------------------------------------

@dataclass
class GovernanceDecision:
    """Result of a policy evaluation."""

    action: str
    allowed: bool
    reason: str
    policy_name: str
    trust_score: int
    decision_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    timestamp: str = field(
        default_factory=lambda: time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    )


class GovernanceEngine:
    """AGT-style policy engine that evaluates agent actions against a policy bundle."""

    def __init__(self, policy: PolicyBundle) -> None:
        self.policy = policy
        self.trust_score = 800  # Start with high trust
        self._call_counts: dict[str, list[float]] = {}
        self._hash_chain: str = hashlib.sha256(b"genesis").hexdigest()
        self._decisions: list[GovernanceDecision] = []

    def evaluate(
        self,
        action: str,
        justification: Optional[str] = None,
        context: Optional[dict[str, Any]] = None,
    ) -> GovernanceDecision:
        """Evaluate an action against the policy bundle.

        Args:
            action: The action the agent wants to perform.
            justification: Optional justification for the action.
            context: Optional context for the evaluation.

        Returns:
            A GovernanceDecision indicating whether the action is allowed.
        """
        # Check blocked actions
        if action in self.policy.blocked_actions:
            decision = GovernanceDecision(
                action=action,
                allowed=False,
                reason=f"Action '{action}' is explicitly blocked by policy",
                policy_name=self.policy.name,
                trust_score=self.trust_score,
            )
            self._record_decision(decision)
            self.trust_score = max(0, self.trust_score - 50)
            return decision

        # Check allowed actions
        if self.policy.allowed_actions and action not in self.policy.allowed_actions:
            decision = GovernanceDecision(
                action=action,
                allowed=False,
                reason=f"Action '{action}' is not in the allowed actions list",
                policy_name=self.policy.name,
                trust_score=self.trust_score,
            )
            self._record_decision(decision)
            return decision

        # Check trust score
        if self.trust_score < self.policy.min_trust_score:
            decision = GovernanceDecision(
                action=action,
                allowed=False,
                reason=(
                    f"Trust score {self.trust_score} is below minimum "
                    f"{self.policy.min_trust_score}"
                ),
                policy_name=self.policy.name,
                trust_score=self.trust_score,
            )
            self._record_decision(decision)
            return decision

        # Check justification requirement
        if action in self.policy.requires_justification and not justification:
            decision = GovernanceDecision(
                action=action,
                allowed=False,
                reason=f"Action '{action}' requires justification",
                policy_name=self.policy.name,
                trust_score=self.trust_score,
            )
            self._record_decision(decision)
            return decision

        # Check rate limits
        if action in self.policy.rate_limits:
            limit = self.policy.rate_limits[action]
            now = time.time()
            window = limit.get("window_seconds", 3600)
            max_calls = limit.get("max_calls", 100)

            timestamps = self._call_counts.get(action, [])
            timestamps = [t for t in timestamps if now - t < window]
            self._call_counts[action] = timestamps

            if len(timestamps) >= max_calls:
                decision = GovernanceDecision(
                    action=action,
                    allowed=False,
                    reason=(
                        f"Rate limit exceeded for '{action}': "
                        f"{max_calls} calls per {window}s"
                    ),
                    policy_name=self.policy.name,
                    trust_score=self.trust_score,
                )
                self._record_decision(decision)
                return decision

            timestamps.append(now)
            self._call_counts[action] = timestamps

        # Action is allowed
        decision = GovernanceDecision(
            action=action,
            allowed=True,
            reason="Policy check passed",
            policy_name=self.policy.name,
            trust_score=self.trust_score,
        )
        self._record_decision(decision)
        return decision

    def _record_decision(self, decision: GovernanceDecision) -> None:
        """Record a decision and update the hash chain."""
        if self.policy.hash_chain:
            decision_bytes = json.dumps({
                "id": decision.decision_id,
                "action": decision.action,
                "allowed": decision.allowed,
                "prev": self._hash_chain,
            }).encode()
            self._hash_chain = hashlib.sha256(decision_bytes).hexdigest()

        self._decisions.append(decision)

        level = logging.INFO if decision.allowed else logging.WARNING
        logger.log(
            level,
            "Policy %s: action=%s allowed=%s reason=%s trust=%d",
            decision.policy_name,
            decision.action,
            decision.allowed,
            decision.reason,
            decision.trust_score,
        )

    @property
    def decisions(self) -> list[GovernanceDecision]:
        """All recorded decisions."""
        return list(self._decisions)

    @property
    def current_hash(self) -> str:
        """Current hash chain value for tamper evidence."""
        return self._hash_chain


# ---------------------------------------------------------------------------
# Mock audit exporter (for local testing)
# ---------------------------------------------------------------------------

class MockCitadelExporter:
    """Mock exporter that logs events locally instead of sending to Azure."""

    def __init__(self) -> None:
        self.events: list[dict[str, Any]] = []

    def export_decision(
        self,
        decision: GovernanceDecision,
        apim_request_id: str = "",
        hash_chain: str = "",
    ) -> None:
        """Export a governance decision event."""
        event = {
            "event_type": "policy_violation" if not decision.allowed else "policy_decision",
            "timestamp": decision.timestamp,
            "agent_id": "customer-support-agent-01",
            "action": decision.action,
            "decision": "allow" if decision.allowed else "deny",
            "policy_name": decision.policy_name,
            "trust_score": decision.trust_score,
            "correlation": {
                "apim_request_id": apim_request_id,
                "agt_decision_id": decision.decision_id,
            },
            "hash_chain": hash_chain,
            "detail": decision.reason,
        }
        self.events.append(event)
        logger.info(
            "Exported to Citadel (mock): %s %s -> %s",
            event["event_type"],
            event["action"],
            event["decision"],
        )

    def flush(self) -> None:
        """Flush pending events."""
        logger.info("Flushed %d events to Citadel (mock)", len(self.events))


# ---------------------------------------------------------------------------
# Main demo
# ---------------------------------------------------------------------------

def run_demo(mock: bool = True) -> None:
    """Run the governed agent demo.

    Args:
        mock: If True, use mock gateway and exporter. If False, use real Azure.
    """
    # Load policy bundle
    policy_path = Path(__file__).parent.parent / "policies" / "agent-policy.yaml"
    if policy_path.exists():
        policy = PolicyBundle.from_yaml(str(policy_path))
        logger.info("Loaded policy bundle: %s v%s", policy.name, policy.version)
    else:
        policy = PolicyBundle(name="default", version="0.0.0")
        logger.warning("Policy file not found, using defaults")

    # Initialize governance engine
    engine = GovernanceEngine(policy)

    # Initialize gateway and exporter
    if mock:
        from citadel_config import MockGateway
        gateway = MockGateway()
        exporter = MockCitadelExporter()
        logger.info("Running in mock mode (no Azure dependencies)")
    else:
        logger.info("Running with live Citadel gateway")
        # In production, would use real CitadelAuditExporter
        exporter = MockCitadelExporter()

    print("\n" + "=" * 60)
    print("  Citadel + AGT Governed Agent Demo")
    print("=" * 60)

    # Scenario 1: Allowed action
    print("\n--- Scenario 1: Query customer database (allowed) ---")
    decision = engine.evaluate("query_customer_database")
    if decision.allowed and mock:
        result = gateway.process_request("/openai/chat", {"query": "customer lookup"})
        exporter.export_decision(
            decision,
            apim_request_id=result.get("apim_request_id", ""),
            hash_chain=engine.current_hash,
        )

    # Scenario 2: Blocked action
    print("\n--- Scenario 2: Delete customer record (blocked) ---")
    decision = engine.evaluate("delete_customer_record")
    exporter.export_decision(decision, hash_chain=engine.current_hash)

    # Scenario 3: Action requiring justification (no justification provided)
    print("\n--- Scenario 3: Send email without justification (denied) ---")
    decision = engine.evaluate("send_email")
    exporter.export_decision(decision, hash_chain=engine.current_hash)

    # Scenario 4: Action with justification (allowed)
    print("\n--- Scenario 4: Send email with justification (allowed) ---")
    decision = engine.evaluate(
        "send_email",
        justification="Customer requested order status update via email",
    )
    if decision.allowed and mock:
        result = gateway.process_request("/openai/chat", {"task": "compose email"})
        exporter.export_decision(
            decision,
            apim_request_id=result.get("apim_request_id", ""),
            hash_chain=engine.current_hash,
        )

    # Scenario 5: Unknown action (not in allowed list)
    print("\n--- Scenario 5: Execute code (not allowed) ---")
    decision = engine.evaluate("execute_code")
    exporter.export_decision(decision, hash_chain=engine.current_hash)

    # Summary
    exporter.flush()
    print("\n" + "=" * 60)
    print("  Summary")
    print("=" * 60)
    print(f"  Total decisions:     {len(engine.decisions)}")
    print(f"  Allowed:             {sum(1 for d in engine.decisions if d.allowed)}")
    print(f"  Denied:              {sum(1 for d in engine.decisions if not d.allowed)}")
    print(f"  Current trust score: {engine.trust_score}")
    print(f"  Hash chain head:     {engine.current_hash[:16]}...")
    print(f"  Events exported:     {len(exporter.events)}")
    print("=" * 60 + "\n")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Citadel + AGT Governed Agent")
    parser.add_argument(
        "--mock",
        action="store_true",
        default=True,
        help="Use mock gateway and exporter (default: True)",
    )
    args = parser.parse_args()
    run_demo(mock=args.mock)
