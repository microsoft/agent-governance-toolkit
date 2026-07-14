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
- Response scanning for prompt injection, credential/PII leaks, and exfiltration
"""

from __future__ import annotations

import json
import logging
import re
import threading
import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Callable

from agent_os._mcp_metrics import MCPMetrics, MCPMetricsRecorder
from agent_os.credential_redactor import CredentialRedactor
from agent_os.integrations._native_adapter_runtime import NativeAdapterRuntime
from agent_os.integrations.base import AdapterExecutionState
from agent_os.mcp_protocols import (
    InMemoryAuditSink,
    InMemoryRateLimitStore,
    MCPAuditSink,
    MCPRateLimitStore,
)
from agent_os.mcp_response_scanner import MCPResponseScanner

logger = logging.getLogger(__name__)


# ── Built-in dangerous parameter patterns (CE defaults) ─────────────────────

_BUILTIN_DANGEROUS_PATTERNS: list[str] = [
    # PII / sensitive data
    r"\b\d{3}-\d{2}-\d{4}\b",  # SSN
    r"\b\d{4}[- ]?\d{4}[- ]?\d{4}[- ]?\d{4}\b",  # credit card
    # Shell injection
    r";\s*(rm|del|format|mkfs)\b",  # destructive cmds
    r"\$\(.*\)",  # command substitution
    r"`[^`]+`",  # backtick execution
]


class ApprovalStatus(Enum):
    """Result of a human-approval check."""

    PENDING = "pending"
    APPROVED = "approved"
    DENIED = "denied"


class ResponsePolicy(Enum):
    """How the gateway handles threats detected in tool responses.

    - ``BLOCK``: deny the response entirely when any threat is found.
    - ``SANITIZE``: strip injection tags but still block credential/PII leaks.
    - ``LOG``: allow the response through but record all detected threats.
    """

    BLOCK = "block"
    SANITIZE = "sanitize"
    LOG = "log"


@dataclass
class MCPResponseDecision:
    """Result of scanning a tool response through the gateway."""

    allowed: bool
    reason: str
    content: str | None = None
    threats: list[dict[str, Any]] = field(default_factory=list)
    action: str = "allowed"


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
    denied_tools: list[str]
    sensitive_tools: list[str]
    rate_limit: int
    builtin_sanitization: bool


class MCPGateway:
    """Security gateway that sits between MCP clients and servers.

    Enforces native runtime decisions on all tool calls passing through,
    providing defense against tool misuse, data exfiltration, and
    unauthorized access (OWASP ASI02). The gateway redacts persisted audit
    payloads, enforces a per-agent call budget, and fails closed whenever
    policy evaluation or approval hooks raise unexpected errors.
    """

    def __init__(
        self,
        runtime: Any,
        *,
        denied_tools: list[str] | None = None,
        sensitive_tools: list[str] | None = None,
        approval_callback: Callable[[str, str, dict[str, Any]], ApprovalStatus] | None = None,
        enable_builtin_sanitization: bool = True,
        metrics: MCPMetricsRecorder | None = None,
        rate_limit_store: MCPRateLimitStore | None = None,
        audit_sink: MCPAuditSink | None = None,
        clock: Callable[[], float] = time.time,
        response_scanner: MCPResponseScanner | None = None,
        response_policy: ResponsePolicy = ResponsePolicy.BLOCK,
        rate_limit: int = 100,
    ) -> None:
        """
        Args:
            runtime: Native ACS runtime used for intervention-point evaluation.
            denied_tools: Explicit deny-list — these tools are never exposed.
            sensitive_tools: Tools that require human approval before execution.
            approval_callback: Sync callback invoked for sensitive-tool approval.
                Signature: ``(agent_id, tool_name, params) -> ApprovalStatus``.
            enable_builtin_sanitization: When True, apply built-in dangerous-
                parameter patterns before native runtime evaluation.
            metrics: Optional metrics recorder for gateway events.
            rate_limit_store: Optional persistence backend for per-agent call
                counts.
            audit_sink: Optional sink for persisted audit records.
            clock: Clock used when recording audit timestamps.
            response_scanner: Scanner for tool response content. Pass ``None``
                to disable response scanning, or omit to use the default
                ``MCPResponseScanner``.
            response_policy: How to handle threats found in tool responses.
                ``BLOCK`` denies the response, ``SANITIZE`` strips injection
                tags but blocks credential/PII leaks, ``LOG`` allows but logs.
        """
        self._runtime = NativeAdapterRuntime(runtime)
        self._rate_limit = rate_limit
        self._contexts: dict[str, AdapterExecutionState] = {}
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
            for pat_str in _BUILTIN_DANGEROUS_PATTERNS:
                self._builtin_compiled.append((pat_str, re.compile(pat_str, re.IGNORECASE)))

        # Response scanning
        self._response_scanner = response_scanner if response_scanner is not None else MCPResponseScanner()
        self._response_policy = response_policy

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

        logger.info(
            "MCP Gateway audit | agent=%s tool=%s allowed=%s reason=%s",
            agent_id, tool_name, allowed, reason,
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

    # ── Response interception ────────────────────────────────────────────

    def intercept_tool_response(
        self,
        agent_id: str,
        tool_name: str,
        response_content: str | Any,
    ) -> MCPResponseDecision:
        """Scan a tool response for threats before it reaches the LLM.

        Runs the ``MCPResponseScanner`` against the response content and
        applies the gateway's ``response_policy``:

        - **BLOCK**: deny the response if any threat is found.
        - **SANITIZE**: strip injection tags and redact credentials; block PII
          and exfiltration leaks (which cannot be safely removed).
        - **LOG**: allow the response but record all threats in the audit log.

        Args:
            agent_id: Agent identity receiving the response.
            tool_name: Tool that produced the response.
            response_content: Raw tool output (string or structured data).

        Returns:
            An ``MCPResponseDecision`` with the allow/deny verdict, the
            (possibly sanitized) content, and any detected threats.
        """
        # Normalize structured responses to string for scanning
        if not isinstance(response_content, str):
            try:
                text = json.dumps(response_content, default=str)
            except (TypeError, ValueError):
                text = str(response_content)
        else:
            text = response_content

        try:
            scan_result = self._response_scanner.scan_response(text, tool_name)
        except Exception:
            logger.error(
                "Response scanner error — failing closed | agent=%s tool=%s",
                agent_id, tool_name, exc_info=True,
            )
            decision = MCPResponseDecision(
                allowed=False,
                reason="Response scanner error — blocked (fail closed)",
                content=None,
                action="error",
            )
            self._record_response_audit(agent_id, tool_name, decision)
            return decision

        threat_dicts = [
            {"category": t.category, "description": t.description}
            for t in scan_result.threats
        ]

        if scan_result.is_safe:
            decision = MCPResponseDecision(
                allowed=True,
                reason="Response clean",
                content=text,
                threats=[],
                action="allowed",
            )
            self._record_response_audit(agent_id, tool_name, decision)
            return decision

        # Threats found: apply response_policy
        if self._response_policy == ResponsePolicy.LOG:
            decision = MCPResponseDecision(
                allowed=True,
                reason=f"Response has {len(scan_result.threats)} threat(s) — logged",
                content=text,
                threats=threat_dicts,
                action="logged",
            )
        elif self._response_policy == ResponsePolicy.SANITIZE:
            # Sanitize strips injection tags and redacts credentials. PII and
            # exfiltration URLs cannot be safely removed from prose, so they are
            # still hard-blocked. Credential leaks are no longer a hard block:
            # sanitize_response now redacts them.
            hard_block_categories = {"pii_leak", "data_exfiltration"}
            has_hard_block = any(
                t.category in hard_block_categories for t in scan_result.threats
            )
            if has_hard_block:
                categories = {t.category for t in scan_result.threats if t.category in hard_block_categories}
                decision = MCPResponseDecision(
                    allowed=False,
                    reason=f"Response blocked — {', '.join(sorted(categories))} cannot be sanitized",
                    content=None,
                    threats=threat_dicts,
                    action="blocked",
                )
            else:
                sanitized, removed = self._response_scanner.sanitize_response(text, tool_name)
                # Fail closed if sanitization errored or left a credential behind,
                # so relaxing the credential hard-block above can never leak.
                sanitize_failed = any(t.category == "error" for t in removed)
                residual_credential = CredentialRedactor.contains_credentials(sanitized)
                if sanitize_failed or residual_credential:
                    decision = MCPResponseDecision(
                        allowed=False,
                        reason="Response blocked — sanitization incomplete (fail closed)",
                        content=None,
                        threats=threat_dicts,
                        action="blocked",
                    )
                else:
                    decision = MCPResponseDecision(
                        allowed=True,
                        reason=f"Response sanitized — {len(scan_result.threats)} threat(s) stripped",
                        content=sanitized,
                        threats=threat_dicts,
                        action="sanitized",
                    )
        else:
            # BLOCK (default)
            categories = {t.category for t in scan_result.threats}
            decision = MCPResponseDecision(
                allowed=False,
                reason=f"Response blocked — {', '.join(sorted(categories))} detected",
                content=None,
                threats=threat_dicts,
                action="blocked",
            )

        self._record_response_audit(agent_id, tool_name, decision)
        return decision

    def _record_response_audit(
        self,
        agent_id: str,
        tool_name: str,
        decision: MCPResponseDecision,
    ) -> None:
        """Record a response-scan decision in the audit log.

        Threat descriptions are logged but raw response content is redacted
        to avoid persisting the sensitive data we are trying to protect.
        """
        entry = AuditEntry(
            timestamp=self._clock(),
            agent_id=agent_id,
            tool_name=tool_name,
            parameters={"direction": "response", "action": decision.action,
                        "threats": [t["category"] for t in decision.threats]},
            allowed=decision.allowed,
            reason=decision.reason,
        )
        self._audit_log.append(entry)
        self._audit_sink.record(entry.to_dict())

        logger.info(
                "MCP Gateway response audit | agent=%s tool=%s allowed=%s reason=%s",
                agent_id, tool_name, decision.allowed, decision.reason,
            )

    # ── Policy evaluation pipeline ───────────────────────────────────────

    def _context_for(self, agent_id: str) -> AdapterExecutionState:
        context = self._contexts.get(agent_id)
        if context is None:
            safe_id = "".join(c if c.isalnum() or c in "_-" else "_" for c in agent_id)
            context = AdapterExecutionState(
                agent_id=safe_id or "mcp-agent",
                session_id=f"mcp-{safe_id or 'agent'}-{int(self._clock())}",
            )
            self._contexts[agent_id] = context
        return context

    def _evaluate(
        self,
        agent_id: str,
        tool_name: str,
        params: dict[str, Any],
    ) -> tuple[bool, str, ApprovalStatus | None, str]:
        if tool_name in self.denied_tools:
            return False, f"Tool '{tool_name}' is on the deny list", None, "deny_list"

        param_text = json.dumps(params, default=str)
        if self.enable_builtin_sanitization:
            for pattern, compiled in self._builtin_compiled:
                if compiled.search(param_text):
                    return False, f"Parameters matched dangerous pattern: {pattern}", None, "builtin_pattern"

        context = self._context_for(agent_id)
        evaluation = self._runtime.evaluate_pre_tool_call(
            context,
            tool_name=tool_name,
            args=params,
            call_id=f"mcp-{context.call_count + 1}",
        )
        if not evaluation.allowed:
            return False, evaluation.reason or "Runtime denied tool call", None, "runtime"

        if tool_name in self.sensitive_tools:
            if self.approval_callback is None:
                return False, "Awaiting human approval", ApprovalStatus.PENDING, "approval_pending"
            try:
                status = self.approval_callback(agent_id, tool_name, params)
            except Exception:
                logger.error(
                    "Approval callback error — denying access | agent=%s tool=%s",
                    agent_id, tool_name, exc_info=True,
                )
                return (
                    False,
                    "Approval callback error — access denied (fail closed)",
                    None,
                    "approval_error",
                )
            if status != ApprovalStatus.APPROVED:
                reason = "Human approval denied" if status == ApprovalStatus.DENIED else "Awaiting human approval"
                return False, reason, status, "approval_denied" if status == ApprovalStatus.DENIED else "approval_pending"

        if not self._consume_budget(agent_id):
            return False, f"Agent '{agent_id}' exceeded call budget ({self._rate_limit})", None, "rate_limit"
        context.call_count += 1
        return True, "Allowed by runtime", None, "allowed"

    def _consume_budget(self, agent_id: str) -> bool:
        with self._rate_limit_lock:
            count = int(self._rate_limit_store.get_bucket(agent_id) or 0)
            if count >= self._rate_limit:
                return False
            self._tracked_agents.add(agent_id)
            self._rate_limit_store.set_bucket(agent_id, count + 1)
            return True

    # ── Server wrapping ──────────────────────────────────────────────────

    @staticmethod
    def wrap_mcp_server(
        server_config: dict[str, Any],
        *,
        denied_tools: list[str] | None = None,
        sensitive_tools: list[str] | None = None,
        rate_limit: int = 100,
    ) -> GatewayConfig:
        """Produce a ``GatewayConfig`` that layers governance on a server.

        Args:
            server_config: Raw MCP server configuration to wrap.
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
            denied_tools=list(denied_tools or []),
            sensitive_tools=list(sensitive_tools or []),
            rate_limit=rate_limit,
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
