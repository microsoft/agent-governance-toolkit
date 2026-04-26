# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""
MCP Security Gateway — Public Preview

A governance layer that sits between MCP clients and MCP servers,
enforcing policy-based controls on all tool calls passing through.

Addresses OWASP ASI02 (Tool Misuse & Exploitation) by providing:
- Tool allow/deny list filtering
- Parameter sanitization against dangerous patterns
- Per-agent rate limiting / call budget enforcement
- Structured audit logging of every tool invocation
- Human-in-the-loop approval for sensitive tools
"""

from __future__ import annotations

import json
import logging
import re
import threading
import time
from dataclasses import dataclass
from enum import Enum
from typing import Any, Callable

from agent_os._mcp_metrics import MCPMetrics, MCPMetricsRecorder
from agent_os.credential_redactor import CredentialRedactor
from agent_os.integrations.base import GovernancePolicy, PatternType
from agent_os.mcp_protocols import (
    InMemoryAuditSink,
    InMemoryRateLimitStore,
    MCPAuditSink,
    MCPRateLimitStore,
)

logger = logging.getLogger(__name__)


# ── Built-in dangerous parameter patterns (CE defaults) ─────────────────────

_BUILTIN_DANGEROUS_PATTERNS: list[tuple[str, PatternType]] = [
    # PII / sensitive data
    (r"\b\d{3}-\d{2}-\d{4}\b", PatternType.REGEX),  # SSN
    (r"\b\d{4}[- ]?\d{4}[- ]?\d{4}[- ]?\d{4}\b", PatternType.REGEX),  # credit card
    # Shell injection
    (r";\s*(rm|del|format|mkfs)\b", PatternType.REGEX),  # destructive cmds
    (r"\$\(.*\)", PatternType.REGEX),  # command substitution
    (r"`[^`]+`", PatternType.REGEX),  # backtick execution
]


class ApprovalStatus(Enum):
    """Result of a human-approval check."""

    PENDING = "pending"
    APPROVED = "approved"
    DENIED = "denied"


@dataclass
class AuditEntry:
    """A single audit-log record for a tool call."""

    timestamp: float
    agent_id: str
    tool_name: str
    parameters: dict[str, Any]
    allowed: bool
    reason: str
    approval_status: ApprovalStatus | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "timestamp": self.timestamp,
            "agent_id": self.agent_id,
            "tool_name": self.tool_name,
            "parameters": self.parameters,
            "allowed": self.allowed,
            "reason": self.reason,
            "approval_status": self.approval_status.value if self.approval_status else None,
        }


@dataclass
class GatewayConfig:
    """Configuration returned by ``wrap_mcp_server``."""

    server_config: dict[str, Any]
    policy_name: str
    allowed_tools: list[str]
    denied_tools: list[str]
    sensitive_tools: list[str]
    rate_limit: int
    builtin_sanitization: bool


class MCPGateway:
    """Security gateway that sits between MCP clients and servers.

    Enforces governance policies on all tool calls passing through,
    providing defense against tool misuse, data exfiltration, and
    unauthorized access (OWASP ASI02). The gateway redacts persisted audit
    payloads, enforces a per-agent call budget, and fails closed whenever
    policy evaluation or approval hooks raise unexpected errors.
    """

    def __init__(
        self,
        policy: GovernancePolicy,
        *,
        denied_tools: list[str] | None = None,
        sensitive_tools: list[str] | None = None,
        approval_callback: Callable[[str, str, dict[str, Any]], ApprovalStatus] | None = None,
        enable_builtin_sanitization: bool = True,
        metrics: MCPMetricsRecorder | None = None,
        rate_limit_store: MCPRateLimitStore | None = None,
        audit_sink: MCPAuditSink | None = None,
        clock: Callable[[], float] = time.time,
    ) -> None:
        """
        Args:
            policy: Governance policy defining constraints and thresholds.
            denied_tools: Explicit deny-list — these tools are never exposed.
            sensitive_tools: Tools that require human approval before execution.
            approval_callback: Sync callback invoked for sensitive-tool approval.
                Signature: ``(agent_id, tool_name, params) -> ApprovalStatus``.
            enable_builtin_sanitization: When True, apply built-in dangerous-
                parameter patterns in addition to the policy's blocked_patterns.
            metrics: Optional metrics recorder for gateway events.
            rate_limit_store: Optional persistence backend for per-agent call
                counts.
            audit_sink: Optional sink for persisted audit records.
            clock: Clock used when recording audit timestamps.
        """
        self.policy = policy
        self.denied_tools: list[str] = denied_tools or []
        self.sensitive_tools: list[str] = sensitive_tools or []
        self.approval_callback = approval_callback
        self.enable_builtin_sanitization = enable_builtin_sanitization
        self._metrics = metrics or MCPMetrics()
        self._rate_limit_store = rate_limit_store or InMemoryRateLimitStore()
        self._audit_sink = audit_sink or InMemoryAuditSink()
        self._clock = clock

        # Per-agent call counters for rate limiting
        self._tracked_agents: set[str] = set()
        self._rate_limit_lock = threading.Lock()
        # Audit log
        self._audit_log: list[AuditEntry] = []
        # Pre-compile built-in patterns
        self._builtin_compiled: list[tuple[str, re.Pattern]] = []
        if enable_builtin_sanitization:
            for pat_str, _ in _BUILTIN_DANGEROUS_PATTERNS:
                self._builtin_compiled.append((pat_str, re.compile(pat_str, re.IGNORECASE)))

    # ── Core interception ────────────────────────────────────────────────

    def intercept_tool_call(
        self,
        agent_id: str,
        tool_name: str,
        params: dict[str, Any],
    ) -> tuple[bool, str]:
        """Evaluate a tool call against the gateway's policy stack.

        Args:
            agent_id: Agent identity attempting the tool invocation.
            tool_name: Tool being requested.
            params: Structured tool parameters to evaluate.

        Returns:
            ``(allowed, reason)`` — *allowed* is True when the call may
            proceed; *reason* explains the decision.
        """
        stage = "error"
        try:
            allowed, reason, approval, stage = self._evaluate(agent_id, tool_name, params)
        except Exception:
            # Fail closed: deny access on unexpected evaluation errors
            logger.error(
                "MCP Gateway evaluation error — failing closed | agent=%s tool=%s",
                agent_id,
                tool_name,
                exc_info=True,
            )
            allowed, reason, approval = (
                False,
                "Internal gateway error — access denied (fail closed)",
                None,
            )

        # Record audit entry
        redacted_parameters = CredentialRedactor.redact_data_structure(params)
        entry = AuditEntry(
            timestamp=self._clock(),
            agent_id=agent_id,
            tool_name=tool_name,
            parameters=redacted_parameters,
            allowed=allowed,
            reason=reason,
            approval_status=approval,
        )
        self._audit_log.append(entry)
        self._audit_sink.record(entry.to_dict())

        if self.policy.log_all_calls:
            logger.info(
                "MCP Gateway audit | agent=%s tool=%s allowed=%s reason=%s",
                agent_id,
                tool_name,
                allowed,
                reason,
            )

        self._metrics.record_decision(
            allowed=allowed,
            agent_id=agent_id,
            tool_name=tool_name,
            stage=stage,
        )
        if stage == "rate_limit":
            self._metrics.record_rate_limit_hit(agent_id=agent_id, tool_name=tool_name)

        return allowed, reason

    # ── Policy evaluation pipeline ───────────────────────────────────────

    def _evaluate(
        self,
        agent_id: str,
        tool_name: str,
        params: dict[str, Any],
    ) -> tuple[bool, str, ApprovalStatus | None, str]:
        # 1. Deny-list check
        if tool_name in self.denied_tools:
            return False, f"Tool '{tool_name}' is on the deny list", None, "deny_list"

        # 2. Allow-list check (empty list means all tools allowed)
        if self.policy.allowed_tools and tool_name not in self.policy.allowed_tools:
            return False, f"Tool '{tool_name}' is not on the allow list", None, "allow_list"

        # 3. Parameter sanitization
        param_text = json.dumps(params, default=str)

        # 3a. Policy blocked patterns
        matches = self.policy.matches_pattern(param_text)
        if matches:
            return (
                False,
                f"Parameters matched blocked pattern(s): {matches}",
                None,
                "policy_pattern",
            )

        # 3b. Built-in dangerous patterns
        if self.enable_builtin_sanitization:
            for pat_str, compiled in self._builtin_compiled:
                if compiled.search(param_text):
                    return (
                        False,
                        f"Parameters matched dangerous pattern: {pat_str}",
                        None,
                        "builtin_pattern",
                    )

        # 4. Rate limiting
        with self._rate_limit_lock:
            count = int(self._rate_limit_store.get_bucket(agent_id) or 0)
            if count >= self.policy.max_tool_calls:
                return (
                    False,
                    f"Agent '{agent_id}' exceeded call budget ({self.policy.max_tool_calls})",
                    None,
                    "rate_limit",
                )

            # Increment call counter (only on successful evaluation past this point)
            self._tracked_agents.add(agent_id)
            self._rate_limit_store.set_bucket(agent_id, count + 1)

        # 5. Human approval
        if self.policy.require_human_approval or tool_name in self.sensitive_tools:
            if self.approval_callback is not None:
                try:
                    status = self.approval_callback(agent_id, tool_name, params)
                except Exception:
                    logger.error(
                        "Approval callback error — denying access | agent=%s tool=%s",
                        agent_id,
                        tool_name,
                        exc_info=True,
                    )
                    return (
                        False,
                        "Approval callback error — access denied (fail closed)",
                        None,
                        "approval_error",
                    )
            else:
                status = ApprovalStatus.PENDING

            if status == ApprovalStatus.DENIED:
                return False, "Human approval denied", status, "approval_denied"
            if status == ApprovalStatus.PENDING:
                return False, "Awaiting human approval", status, "approval_pending"
            # APPROVED — fall through
            return True, "Approved by human reviewer", status, "approval_granted"

        return True, "Allowed by policy", None, "allowed"

    # ── Server wrapping ──────────────────────────────────────────────────

    @staticmethod
    def wrap_mcp_server(
        server_config: dict[str, Any],
        policy: GovernancePolicy,
        *,
        denied_tools: list[str] | None = None,
        sensitive_tools: list[str] | None = None,
    ) -> GatewayConfig:
        """Produce a ``GatewayConfig`` that layers governance on a server.

        Args:
            server_config: Raw MCP server configuration to wrap.
            policy: Governance policy to apply to the wrapped server.
            denied_tools: Optional explicit deny-list.
            sensitive_tools: Optional list of tools that require approval.

        This does not mutate the original *server_config*; it returns a
        new ``GatewayConfig`` object that downstream code can use to
        instantiate a governed MCP proxy.

        Returns:
            A ``GatewayConfig`` describing the governed server surface.
        """
        return GatewayConfig(
            server_config=dict(server_config),
            policy_name=policy.name,
            allowed_tools=list(policy.allowed_tools),
            denied_tools=list(denied_tools or []),
            sensitive_tools=list(sensitive_tools or []),
            rate_limit=policy.max_tool_calls,
            builtin_sanitization=True,
        )

    # ── Audit helpers ────────────────────────────────────────────────────

    @property
    def audit_log(self) -> list[AuditEntry]:
        """Return a copy of the audit log.

        Returns:
            A shallow copy of the in-memory ``AuditEntry`` list.
        """
        return list(self._audit_log)

    def get_agent_call_count(self, agent_id: str) -> int:
        """Return the number of calls made by *agent_id*.

        Args:
            agent_id: Agent identifier to inspect.

        Returns:
            The number of accepted tool calls recorded for the agent.
        """
        return int(self._rate_limit_store.get_bucket(agent_id) or 0)

    def reset_agent_budget(self, agent_id: str) -> None:
        """Reset the call counter for *agent_id*.

        Args:
            agent_id: Agent identifier whose budget should be reset.
        """
        self._tracked_agents.add(agent_id)
        self._rate_limit_store.set_bucket(agent_id, 0)

    def reset_all_budgets(self) -> None:
        """Reset call counters for every agent.

        This clears the recorded call count for each tracked agent.
        """
        for agent_id in self._tracked_agents:
            self._rate_limit_store.set_bucket(agent_id, 0)
