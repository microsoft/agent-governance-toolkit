# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""
Base Agent Module - Reusable base classes for Agent OS agents.

Provides a consistent pattern for building agents that run under
the Agent OS kernel with policy governance, audit logging, and
tool integration.

Example:
    >>> from agent_os.base_agent import BaseAgent, AgentConfig
    >>>
    >>> class MyAgent(BaseAgent):
    ...     async def run(self, task: str) -> ExecutionResult:
    ...         return await self._execute("process", {"task": task})
    >>>
    >>> agent = MyAgent(AgentConfig(agent_id="my-agent", policies=["read_only"]))
    >>> result = await agent.run("hello")
"""

from __future__ import annotations

import asyncio
import copy
import json
import os
import re
import sys
import time
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Callable, Generic, TypeVar
from uuid import uuid4

from agent_os.stateless import (
    ExecutionContext,
    ExecutionResult,
    MemoryBackend,
    StateBackend,
    StatelessKernel,
)


class PolicyDecision(Enum):
    """Result of policy evaluation."""
    ALLOW = "allow"
    DENY = "deny"
    AUDIT = "audit"  # Allow but log for review
    ESCALATE = "escalate"  # Route to human reviewer
    DEFER = "defer"  # Async policy evaluation with callback


@dataclass
class EscalationRequest:
    """A request for human review of a policy decision.

    Attributes:
        action: The action that triggered escalation
        reason: Why the action was escalated
        requested_by: Agent ID that requested the escalation
        timestamp: When the escalation was created
        status: Current status (pending/approved/rejected)
    """
    action: str
    reason: str
    requested_by: str
    timestamp: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    status: str = "pending"

    def __post_init__(self) -> None:
        if self.status not in ("pending", "approved", "rejected"):
            raise ValueError(f"Invalid status: {self.status!r}")

    def approve(self) -> None:
        """Mark escalation as approved."""
        self.status = "approved"

    def reject(self) -> None:
        """Mark escalation as rejected."""
        self.status = "rejected"

    def to_dict(self) -> dict[str, Any]:
        return {
            "action": self.action,
            "reason": self.reason,
            "requested_by": self.requested_by,
            "timestamp": self.timestamp.isoformat(),
            "status": self.status,
        }


@dataclass
class AgentConfig:
    """Configuration for an agent instance.

    Attributes:
        agent_id: Unique identifier for this agent instance
        policies: List of policy names to apply (e.g., ["read_only", "no_pii"])
        metadata: Additional metadata for the agent
        state_backend: Optional custom state backend (defaults to in-memory)
        max_audit_log_size: Maximum number of audit log entries to retain
        max_metadata_size_bytes: Maximum size in bytes for metadata values
    """
    agent_id: str
    policies: list[str] = field(default_factory=list)
    metadata: dict[str, Any] = field(default_factory=dict)
    state_backend: StateBackend | None = None
    max_audit_log_size: int = 10000
    max_metadata_size_bytes: int = 1_048_576  # 1 MB

    _AGENT_ID_RE = re.compile(r"^[a-zA-Z0-9][a-zA-Z0-9-]{2,63}$")

    def __post_init__(self) -> None:
        if not self._AGENT_ID_RE.match(self.agent_id):
            raise ValueError(
                f"Invalid agent_id {self.agent_id!r}. "
                "Must be 3-64 chars, alphanumeric with dashes, "
                "starting with an alphanumeric character."
            )

    @classmethod
    def from_file(cls, path: str) -> AgentConfig:
        """Load agent configuration from a YAML or JSON file.

        Args:
            path: Path to a .yaml, .yml, or .json config file

        Returns:
            AgentConfig populated from the file

        Raises:
            FileNotFoundError: If the file does not exist
            ValueError: If the file extension is not supported
        """
        if not os.path.isfile(path):
            raise FileNotFoundError(f"Config file not found: {path}")

        ext = os.path.splitext(path)[1].lower()
        with open(path, encoding="utf-8") as fh:
            if ext in (".yaml", ".yml"):
                try:
                    import yaml
                except ImportError as exc:
                    raise ImportError(
                        "PyYAML is required for YAML config: pip install pyyaml"
                    ) from exc
                data = yaml.safe_load(fh) or {}
            elif ext == ".json":
                data = json.load(fh)
            else:
                raise ValueError(f"Unsupported config format: {ext}")

        return cls(
            agent_id=data.get("agent_id", data.get("agentId", "agent")),
            policies=data.get("policies", []),
            metadata=data.get("metadata", {}),
            max_audit_log_size=data.get("max_audit_log_size", 10000),
            max_metadata_size_bytes=data.get("max_metadata_size_bytes", 1_048_576),
        )

    def __repr__(self) -> str:
        return f"AgentConfig(agent_id={self.agent_id!r}, policies={self.policies!r})"

    def to_dict(self) -> dict[str, Any]:
        """Serialize configuration to a dictionary."""
        return {
            "agent_id": self.agent_id,
            "policies": self.policies,
            "metadata": self.metadata,
            "max_audit_log_size": self.max_audit_log_size,
            "max_metadata_size_bytes": self.max_metadata_size_bytes,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> AgentConfig:
        """Deserialize an AgentConfig from a dictionary.

        Args:
            data: Dictionary as produced by ``to_dict()``.

        Returns:
            Reconstructed AgentConfig instance.
        """
        return cls(
            agent_id=data["agent_id"],
            policies=data.get("policies", []),
            metadata=data.get("metadata", {}),
            max_audit_log_size=data.get("max_audit_log_size", 10000),
            max_metadata_size_bytes=data.get("max_metadata_size_bytes", 1_048_576),
        )


@dataclass
class AuditEntry:
    """An entry in the agent's audit log."""
    timestamp: datetime
    agent_id: str
    request_id: str
    action: str
    params: dict[str, Any]
    decision: PolicyDecision
    result_success: bool | None = None
    error: str | None = None
    execution_time_ms: float | None = None

    def __repr__(self) -> str:
        return (
            f"AuditEntry(agent_id={self.agent_id!r}, action={self.action!r}, "
            f"decision={self.decision!r})"
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "timestamp": self.timestamp.isoformat(),
            "agent_id": self.agent_id,
            "request_id": self.request_id,
            "action": self.action,
            "params_keys": list(self.params.keys()),  # Don't log full params
            "decision": self.decision.value,
            "result_success": self.result_success,
            "error": self.error,
            "execution_time_ms": self.execution_time_ms,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> AuditEntry:
        """Deserialize an AuditEntry from a dictionary.

        Args:
            data: Dictionary as produced by ``to_dict()``.

        Returns:
            Reconstructed AuditEntry instance.
        """
        return cls(
            timestamp=datetime.fromisoformat(data["timestamp"]),
            agent_id=data["agent_id"],
            request_id=data["request_id"],
            action=data["action"],
            params=dict.fromkeys(data.get("params_keys", [])),
            decision=PolicyDecision(data["decision"]),
            result_success=data.get("result_success"),
            error=data.get("error"),
            execution_time_ms=data.get("execution_time_ms"),
        )


class BaseAgent(ABC):
    """Abstract base class for Agent OS agents.

    Provides:
    - Kernel integration with policy enforcement
    - Execution context management
    - Audit logging
    - Common helper methods

    Subclasses must implement the `run` method which defines
    the agent's main task.

    Example:
        >>> class GreeterAgent(BaseAgent):
        ...     async def run(self, name: str) -> ExecutionResult:
        ...         result = await self._execute(
        ...             action="greet",
        ...             params={"name": name, "output": f"Hello, {name}!"}
        ...         )
        ...         return result
        >>>
        >>> agent = GreeterAgent(AgentConfig(agent_id="greeter"))
        >>> result = await agent.run("World")
        >>> print(result.data)  # "Hello, World!"
    """

    def __init__(
        self,
        config: AgentConfig,
        defer_timeout: float = 30.0,
    ):
        """Initialize the agent.

        Args:
            config: Agent configuration including ID, policies, and backend
            defer_timeout: Timeout in seconds for DEFER async callbacks (default 30s)
        """
        self._config = config
        self._kernel = StatelessKernel(
            backend=config.state_backend or MemoryBackend()
        )
        self._audit_log: list[AuditEntry] = []
        self._max_audit_entries = config.max_audit_log_size
        self._escalation_queue: list[EscalationRequest] = []
        self._defer_timeout = defer_timeout
        self._defer_callback: Callable[[str, dict[str, Any]], asyncio.Future[PolicyDecision]] | None = None

    @property
    def agent_id(self) -> str:
        """Get the agent's unique identifier."""
        return self._config.agent_id

    @property
    def policies(self) -> list[str]:
        """Get the agent's active policies."""
        return self._config.policies.copy()

    def _new_context(self, **extra_metadata: Any) -> ExecutionContext:
        """Create a new execution context for a request.

        Args:
            **extra_metadata: Additional metadata to include

        Returns:
            Fresh ExecutionContext with agent's default settings

        Raises:
            ValueError: If any metadata value exceeds max_metadata_size_bytes
        """
        metadata = {**self._config.metadata, **extra_metadata}
        max_size = self._config.max_metadata_size_bytes
        for key, value in metadata.items():
            size = sys.getsizeof(value)
            if size > max_size:
                raise ValueError(
                    f"Metadata key {key!r} value size ({size} bytes) "
                    f"exceeds limit ({max_size} bytes)"
                )
        metadata = copy.deepcopy(metadata)
        return ExecutionContext(
            agent_id=self._config.agent_id,
            policies=self._config.policies.copy(),
            metadata=metadata,
        )

    def set_defer_callback(
        self,
        callback: Callable[[str, dict[str, Any]], asyncio.Future[PolicyDecision]],
    ) -> None:
        """Register an async callback for DEFER policy decisions.

        Args:
            callback: Async callable receiving (action, params) and returning
                a Future that resolves to a PolicyDecision.
        """
        self._defer_callback = callback

    async def _enforce_policy(
        self,
        decision: PolicyDecision,
        action: str,
        params: dict[str, Any],
        reason: str = "",
    ) -> ExecutionResult:
        """Handle a policy decision, including ESCALATE and DEFER.

        Args:
            decision: The PolicyDecision to enforce
            action: Name of the action under evaluation
            params: Parameters for the action
            reason: Human-readable reason for the decision

        Returns:
            ExecutionResult representing the enforcement outcome
        """
        if decision == PolicyDecision.ESCALATE:
            escalation = EscalationRequest(
                action=action,
                reason=reason or f"Action '{action}' escalated for human review",
                requested_by=self._config.agent_id,
            )
            self._escalation_queue.append(escalation)
            return ExecutionResult(
                success=False,
                data=escalation.to_dict(),
                error=None,
                signal="ESCALATE",
                metadata={"pending_review": True},
            )

        if decision == PolicyDecision.DEFER:
            if self._defer_callback is None:
                return ExecutionResult(
                    success=False,
                    data=None,
                    error="DEFER requested but no callback registered",
                    signal="DEFER",
                )
            try:
                future = self._defer_callback(action, params)
                resolved = await asyncio.wait_for(
                    future, timeout=self._defer_timeout
                )
                if resolved == PolicyDecision.ALLOW:
                    return ExecutionResult(success=True, data=None)
                return ExecutionResult(
                    success=False,
                    data=None,
                    error=f"Deferred evaluation resolved to {resolved.value}",
                    signal=resolved.value.upper(),
                )
            except asyncio.TimeoutError:
                return ExecutionResult(
                    success=False,
                    data=None,
                    error=(
                        f"DEFER timeout after {self._defer_timeout}s "
                        f"for action '{action}'"
                    ),
                    signal="DEFER_TIMEOUT",
                )

        if decision == PolicyDecision.DENY:
            return ExecutionResult(
                success=False,
                data=None,
                error=reason or f"Action '{action}' denied by policy",
                signal="SIGKILL",
            )

        # ALLOW / AUDIT — no blocking
        return ExecutionResult(success=True, data=None)

    async def _execute(
        self,
        action: str,
        params: dict[str, Any],
        context: ExecutionContext | None = None,
    ) -> ExecutionResult:
        """Execute an action through the kernel with policy checks.

        This is the primary method for agents to perform actions.
        All actions are:
        1. Checked against configured policies
        2. Logged for audit
        3. Executed through the kernel

        Args:
            action: Name of the action to execute
            params: Parameters for the action
            context: Optional custom context (uses default if None)

        Returns:
            ExecutionResult with success status, data, and any errors
        """
        ctx = context or self._new_context()
        request_id = str(uuid4())[:16]

        # Create audit entry
        audit = AuditEntry(
            timestamp=datetime.now(timezone.utc),
            agent_id=self._config.agent_id,
            request_id=request_id,
            action=action,
            params=params,
            decision=PolicyDecision.ALLOW,  # Will be updated
        )

        # Execute through kernel with timing
        t0 = time.monotonic()
        result = await self._kernel.execute(action, params, ctx)
        elapsed_ms = (time.monotonic() - t0) * 1000.0

        # Update audit entry with result
        if result.signal == "SIGKILL":
            audit.decision = PolicyDecision.DENY
        elif result.signal == "ESCALATE":
            audit.decision = PolicyDecision.ESCALATE
        elif result.signal in ("DEFER", "DEFER_TIMEOUT"):
            audit.decision = PolicyDecision.DEFER
        audit.result_success = result.success
        audit.error = result.error
        audit.execution_time_ms = elapsed_ms

        self._audit_log.append(audit)
        if len(self._audit_log) > self._max_audit_entries:
            self._audit_log = self._audit_log[-self._max_audit_entries:]

        return result

    def get_audit_log(self) -> list[dict[str, Any]]:
        """Get the agent's audit log.

        Returns:
            List of audit entries as dictionaries
        """
        return [entry.to_dict() for entry in self._audit_log]

    def clear_audit_log(self) -> None:
        """Clear the agent's audit log."""
        self._audit_log.clear()

    def get_execution_stats(self) -> dict[str, Any]:
        """Return execution time statistics from audit log entries.

        Returns:
            Dictionary with avg, min, max, p99 execution times in milliseconds,
            and the total count of timed entries.
        """
        times = [
            e.execution_time_ms
            for e in self._audit_log
            if e.execution_time_ms is not None
        ]
        if not times:
            return {"count": 0, "avg_ms": 0.0, "min_ms": 0.0, "max_ms": 0.0, "p99_ms": 0.0}
        times_sorted = sorted(times)
        count = len(times_sorted)
        p99_idx = min(int(count * 0.99), count - 1)
        return {
            "count": count,
            "avg_ms": sum(times_sorted) / count,
            "min_ms": times_sorted[0],
            "max_ms": times_sorted[-1],
            "p99_ms": times_sorted[p99_idx],
        }

    def query_audit_log(
        self,
        action: str | None = None,
        decision: str | None = None,
        since: datetime | None = None,
        limit: int | None = None,
        offset: int = 0,
    ) -> list[dict[str, Any]]:
        """Query audit log with optional filters.

        Args:
            action: Filter by action name (exact match).
            decision: Filter by decision value (e.g. "allow", "deny").
            since: Only include entries at or after this timestamp.
            limit: Maximum number of entries to return.
            offset: Number of matching entries to skip (for pagination).

        Returns:
            List of matching audit entries as dictionaries.
        """
        results: list[AuditEntry] = self._audit_log
        if action is not None:
            results = [e for e in results if e.action == action]
        if decision is not None:
            results = [e for e in results if e.decision.value == decision]
        if since is not None:
            results = [e for e in results if e.timestamp >= since]
        results = results[offset:]
        if limit is not None:
            results = results[:limit]
        return [e.to_dict() for e in results]

    def get_escalation_queue(self) -> list[EscalationRequest]:
        """Get pending escalation requests."""
        return [e for e in self._escalation_queue if e.status == "pending"]

    @abstractmethod
    async def run(self, *args, **kwargs) -> ExecutionResult:
        """Run the agent's main task.

        Subclasses must implement this method to define the agent's
        primary functionality.

        Returns:
            ExecutionResult with the outcome of the task
        """
        pass


class ToolUsingAgent(BaseAgent):
    """Base class for agents that use registered tools from ATR.

    Extends BaseAgent with tool discovery and execution capabilities.
    Tools are executed through the kernel for policy enforcement.

    Example:
        >>> class AnalysisAgent(ToolUsingAgent):
        ...     async def run(self, data: str) -> ExecutionResult:
        ...         # Use registered tools
        ...         parsed = await self._use_tool("json_parser", {"text": data})
        ...         return parsed
    """

    def __init__(self, config: AgentConfig, tools: list[str] | None = None):
        """Initialize the tool-using agent.

        Args:
            config: Agent configuration
            tools: Optional list of tool names this agent is allowed to use
        """
        super().__init__(config)
        self._allowed_tools = set(tools) if tools else None

    async def _use_tool(
        self,
        tool_name: str,
        params: dict[str, Any],
    ) -> ExecutionResult:
        """Use a registered tool through the kernel.

        Args:
            tool_name: Name of the tool to use
            params: Parameters to pass to the tool

        Returns:
            ExecutionResult from tool execution
        """
        # Check tool allowlist if configured
        if self._allowed_tools and tool_name not in self._allowed_tools:
            return ExecutionResult(
                success=False,
                data=None,
                error=f"Tool '{tool_name}' not in allowed tools list",
            )

        # Execute through kernel
        return await self._execute(
            action=f"tool:{tool_name}",
            params=params,
        )

    def list_allowed_tools(self) -> list[str] | None:
        """Get list of allowed tools, or None if all tools allowed."""
        return list(self._allowed_tools) if self._allowed_tools else None


# Type variable for generic agent results
T = TypeVar("T")


@dataclass
class TypedResult(Generic[T]):
    """A typed wrapper for execution results.

    Useful when you want type hints on the result data.
    """
    success: bool
    data: T | None = None
    error: str | None = None

    @classmethod
    def from_execution_result(
        cls,
        result: ExecutionResult,
        transform: Callable[[Any], T] | None = None,
    ) -> TypedResult[T]:
        """Create from an ExecutionResult with optional transformation."""
        data = None
        if result.success and result.data is not None:
            data = transform(result.data) if transform else result.data
        return cls(
            success=result.success,
            data=data,
            error=result.error,
        )
