# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""Trust-gated tools for LangChain."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any

from langchain_core.tools import BaseTool

from langchain_agentmesh.identity import CMVKIdentity


@dataclass
class ToolExecutionResult:
    """Result of a tool execution with trust context."""

    success: bool
    result: Any = None
    error: str = ""
    trust_verified: bool = False
    execution_time_ms: float = 0.0
    timestamp: datetime = field(default_factory=lambda: datetime.now(UTC))


class TrustGatedTool:
    """Wraps a LangChain tool with trust requirements."""

    def __init__(
        self,
        tool: BaseTool,
        required_capabilities: list[str] | None = None,
        min_trust_score: float = 0.5,
        allow_untrusted: bool = False,
    ):
        self.tool = tool
        self.required_capabilities = required_capabilities or []
        self.min_trust_score = min_trust_score
        self.allow_untrusted = allow_untrusted

    @property
    def name(self) -> str:
        return self.tool.name

    @property
    def description(self) -> str:
        return self.tool.description

    def check_trust(self, identity: CMVKIdentity, trust_score: float = 0.5) -> bool:
        """Check if identity meets trust requirements."""
        # Check capabilities
        for cap in self.required_capabilities:
            if not identity.has_capability(cap):
                return False

        # Check trust score
        if trust_score < self.min_trust_score:
            return False

        return True

    def invoke(
        self,
        input_data: str | dict[str, Any],
        identity: CMVKIdentity | None = None,
        trust_score: float = 0.5,
    ) -> ToolExecutionResult:
        """Invoke the tool with trust verification."""
        import time

        start = time.time()

        # Verify trust if identity provided
        trust_verified = False
        if identity:
            trust_verified = self.check_trust(identity, trust_score)
            if not trust_verified and not self.allow_untrusted:
                return ToolExecutionResult(
                    success=False,
                    error=f"Trust verification failed for {self.name}",
                    trust_verified=False,
                    execution_time_ms=(time.time() - start) * 1000,
                )
        elif not self.allow_untrusted:
            return ToolExecutionResult(
                success=False,
                error=f"Identity required for {self.name}",
                trust_verified=False,
                execution_time_ms=(time.time() - start) * 1000,
            )

        # Execute the tool
        try:
            result = self.tool.invoke(input_data)
            return ToolExecutionResult(
                success=True,
                result=result,
                trust_verified=trust_verified,
                execution_time_ms=(time.time() - start) * 1000,
            )
        except Exception as e:
            return ToolExecutionResult(
                success=False,
                error=str(e),
                trust_verified=trust_verified,
                execution_time_ms=(time.time() - start) * 1000,
            )


class TrustedToolExecutor:
    """Executor that manages trust verification for multiple tools."""

    def __init__(
        self,
        tools: list[TrustGatedTool],
        identity: CMVKIdentity,
        default_trust_score: float = 0.7,
    ):
        self.tools = {t.name: t for t in tools}
        self.identity = identity
        self.default_trust_score = default_trust_score
        self._execution_log: list[dict[str, Any]] = []

    def execute(
        self,
        tool_name: str,
        input_data: str | dict[str, Any],
        trust_score: float | None = None,
    ) -> ToolExecutionResult:
        """Execute a tool by name with trust verification."""
        if tool_name not in self.tools:
            return ToolExecutionResult(
                success=False,
                error=f"Tool not found: {tool_name}",
            )

        tool = self.tools[tool_name]
        score = trust_score if trust_score is not None else self.default_trust_score

        result = tool.invoke(input_data, self.identity, score)

        # Log execution
        self._execution_log.append(
            {
                "tool": tool_name,
                "success": result.success,
                "trust_verified": result.trust_verified,
                "execution_time_ms": result.execution_time_ms,
                "timestamp": result.timestamp.isoformat(),
            }
        )

        return result

    def get_execution_log(self) -> list[dict[str, Any]]:
        """Get the execution log."""
        return self._execution_log.copy()

    def get_available_tools(self) -> list[str]:
        """Get list of available tool names."""
        return list(self.tools.keys())
