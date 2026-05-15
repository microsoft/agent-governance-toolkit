# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""
Agent Shield Integration for Agent-OS
======================================

Integrates Microsoft Agent Shield as the guardrails engine for AGT,
delegating 5-stage per-call validation (input, state, tool execution,
post-tool, output) to Agent Shield while AGT retains ownership of
identity, trust scoring, audit, and lifecycle governance.

Agent Shield provides rich, stateful, per-turn gating with typed
variables, human-in-the-loop resolvers, LLM judges, and composable
YAML policies. AGT provides the enterprise governance envelope.

Together, they form a defense-in-depth stack: Agent Shield gates
individual actions with fine-grained declarative rules, and AGT
governs the agent's identity, trust posture, and compliance.

Usage with Agent Shield SDK installed::

    from agent_os.integrations.agentshield_adapter import AgentShieldKernel

    kernel = AgentShieldKernel.from_yaml("policies/.guardrails.yaml")

    # Validate input (Stage 1)
    result = kernel.validate_input("Hello, process this order")
    assert result.allowed

    # Validate a tool call (Stage 2 state + Stage 3 execution)
    result = kernel.validate_tool_call("send_email", {"to": "user@example.com"})
    if not result.allowed:
        print(f"Blocked: {result.reason}")

    # Validate output (Stage 5)
    result = kernel.validate_output("Order processed successfully")

Usage without Agent Shield SDK (mock mode for testing)::

    kernel = AgentShieldKernel.mock()
    result = kernel.validate_tool_call("any_tool", {})
    assert result.allowed  # Mock always allows

Integration with AGT trust scoring::

    kernel = AgentShieldKernel.from_yaml(
        "policies/.guardrails.yaml",
        trust_score_variable="agt_trust_score",
    )

    # AGT trust score is injected as an Agent Shield variable,
    # enabling guard_policies to gate on trust level:
    #
    #   evaluate_when:
    #     - expression: "agt_trust_score >= 500"
    #       reason: "Agent trust score too low for this action"
    kernel.set_trust_score(750)
"""

from __future__ import annotations

import logging
import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Protocol, runtime_checkable

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Graceful import of Agent Shield SDK
# ---------------------------------------------------------------------------

try:
    from agent_shield import RuntimeBuilder as _RuntimeBuilder  # type: ignore[import-untyped]

    _HAS_AGENT_SHIELD = True
except ImportError:
    _RuntimeBuilder = None
    _HAS_AGENT_SHIELD = False


# ---------------------------------------------------------------------------
# Enums and result types
# ---------------------------------------------------------------------------


class ValidationStage(str, Enum):
    """The five Agent Shield validation stages."""

    INPUT = "input"
    STATE = "state"
    TOOL_EXECUTION = "tool_execution"
    POST_TOOL = "post_tool"
    OUTPUT = "output"


class ShieldAction(str, Enum):
    """Actions taken by Agent Shield on a policy hit."""

    ALLOW = "allow"
    BLOCK = "block"
    WARN = "warn"
    REDACT = "redact"


@dataclass
class ShieldVerdict:
    """Result of an Agent Shield validation stage.

    Attributes:
        allowed: Whether the action was permitted.
        stage: Which validation stage produced this verdict.
        action: The enforcement action taken (allow, block, warn, redact).
        reason: Human-readable explanation of the decision.
        policy_name: Name of the guard policy that triggered (if any).
        modified_value: The value after any redact/append/prepend transforms.
        variables: Agent Shield variables after evaluation.
        elapsed_ms: Time taken for the validation in milliseconds.
        metadata: Additional metadata from the Agent Shield runtime.
    """

    allowed: bool
    stage: ValidationStage
    action: ShieldAction = ShieldAction.ALLOW
    reason: str = ""
    policy_name: str = ""
    modified_value: str | None = None
    variables: dict[str, Any] = field(default_factory=dict)
    elapsed_ms: float = 0.0
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        """Serialize this verdict to a dictionary for audit logging.

        Returns:
            Dict with all verdict fields suitable for JSON serialization.
        """
        d: dict[str, Any] = {
            "allowed": self.allowed,
            "stage": self.stage.value,
            "action": self.action.value,
        }
        if self.reason:
            d["reason"] = self.reason
        if self.policy_name:
            d["policy_name"] = self.policy_name
        if self.modified_value is not None:
            d["modified_value"] = self.modified_value
        if self.elapsed_ms:
            d["elapsed_ms"] = round(self.elapsed_ms, 3)
        return d


@dataclass
class ToolCallVerdict:
    """Combined result of Stage 2 (state) and Stage 3 (tool execution) validation.

    Attributes:
        allowed: Whether the tool call was permitted (both stages must pass).
        state_verdict: Result of state validation (Stage 2).
        execution_verdict: Result of tool execution validation (Stage 3).
        tool_name: Name of the tool being called.
        parameters: Tool parameters (may be modified by Stage 3 transforms).
    """

    allowed: bool
    state_verdict: ShieldVerdict
    execution_verdict: ShieldVerdict
    tool_name: str
    parameters: dict[str, Any]

    @property
    def reason(self) -> str:
        """Return the reason from whichever stage blocked the call."""
        if not self.state_verdict.allowed:
            return self.state_verdict.reason
        if not self.execution_verdict.allowed:
            return self.execution_verdict.reason
        return ""

    def to_dict(self) -> dict[str, Any]:
        """Serialize to a dictionary for audit logging."""
        return {
            "allowed": self.allowed,
            "tool_name": self.tool_name,
            "state_verdict": self.state_verdict.to_dict(),
            "execution_verdict": self.execution_verdict.to_dict(),
        }


# ---------------------------------------------------------------------------
# Session protocol for Agent Shield SDK compatibility
# ---------------------------------------------------------------------------


@runtime_checkable
class AgentShieldSessionProtocol(Protocol):
    """Protocol matching the Agent Shield Session interface."""

    def begin_turn(self) -> None: ...
    def end_turn(self) -> None: ...
    def validate_input(self, text: str) -> Any: ...
    def validate_tool_call(self, tool_name: str, params: Any) -> Any: ...
    def validate_tool_result(self, tool_name: str, result: Any) -> Any: ...
    def validate_output(self, text: str) -> Any: ...
    def set_variable(self, name: str, value: Any) -> None: ...


# ---------------------------------------------------------------------------
# Mock session for testing without Agent Shield SDK
# ---------------------------------------------------------------------------


class _MockSession:
    """Mock Agent Shield session for testing without the real SDK.

    Permits all validations unconditionally, returning ``_MockVerdict``
    objects that evaluate to ``True``.  Used when the real Agent Shield
    runtime is unavailable or when ``AgentShieldKernel`` is instantiated
    via ``AgentShieldKernel.mock()``.

    This class satisfies ``AgentShieldSessionProtocol`` so it can be
    used as a drop-in replacement for a real SDK session during unit
    tests, local development, and CI environments where the Agent
    Shield SDK is not installed.

    Attributes:
        _variables: In-memory store for session variables (e.g. trust
            score) set via ``set_variable``.
        _turn_active: Whether a conversation turn is currently open.
    """

    def __init__(self) -> None:
        self._variables: dict[str, Any] = {}
        self._turn_active = False

    def begin_turn(self) -> None:
        """Mark the start of a conversation turn."""
        self._turn_active = True

    def end_turn(self) -> None:
        """Mark the end of a conversation turn."""
        self._turn_active = False

    def validate_input(self, text: str) -> _MockVerdict:
        """Always allow input text."""
        return _MockVerdict(allowed=True)

    def validate_tool_call(self, tool_name: str, params: Any) -> _MockVerdict:
        """Always allow tool calls."""
        return _MockVerdict(allowed=True)

    def validate_tool_result(self, tool_name: str, result: Any) -> _MockVerdict:
        """Always allow tool results."""
        return _MockVerdict(allowed=True)

    def validate_output(self, text: str) -> _MockVerdict:
        """Always allow output text, passing it through unchanged."""
        return _MockVerdict(allowed=True, response=text)

    def set_variable(self, name: str, value: Any) -> None:
        """Store a session variable (e.g. AGT trust score)."""
        self._variables[name] = value


@dataclass
class _MockVerdict:
    """Mock verdict that mirrors Agent Shield's verdict structure.

    Provides the minimal attribute surface that ``_translate_verdict``
    reads from an SDK verdict: ``allowed``, ``reason``, ``policy_name``,
    and ``response``.  Truthiness delegates to ``allowed`` so the
    ``bool(sdk_result)`` check in ``_translate_verdict`` works correctly.
    """

    allowed: bool = True
    reason: str | None = None
    response: str | None = None
    policy_name: str | None = None

    def __bool__(self) -> bool:
        return self.allowed


# ---------------------------------------------------------------------------
# Mock runtime
# ---------------------------------------------------------------------------


class _MockRuntime:
    """Mock Agent Shield runtime that produces ``_MockSession`` instances.

    Acts as a stand-in for the real ``agent_shield.RuntimeBuilder`` when
    the SDK is not installed.  Every call to ``new_session`` returns a
    fresh ``_MockSession`` that unconditionally allows all validations.
    """

    def new_session(self, **kwargs: Any) -> _MockSession:
        return _MockSession()


# ---------------------------------------------------------------------------
# AgentShieldKernel
# ---------------------------------------------------------------------------


class AgentShieldKernel:
    """
    AGT governance kernel backed by Agent Shield's 5-stage validation.

    Wraps the Agent Shield runtime to provide guardrails validation
    while integrating with AGT's trust scoring, audit logging, and
    policy enforcement systems.

    The kernel manages Agent Shield sessions (one per conversation)
    and translates verdicts into AGT-compatible result types.
    """

    def __init__(
        self,
        runtime: Any,
        *,
        trust_score_variable: str = "agt_trust_score",
        agent_id_variable: str = "agt_agent_id",
        on_violation: Any | None = None,
        fail_closed: bool = True,
    ):
        """Initialize the Agent Shield kernel.

        Args:
            runtime: An Agent Shield Runtime instance (or mock).
            trust_score_variable: Name of the Agent Shield variable
                that receives AGT trust scores. Guard policies can
                reference this variable in expressions.
            agent_id_variable: Name of the Agent Shield variable
                that receives the AGT agent identity.
            on_violation: Optional callback invoked when a stage blocks.
                Signature: ``(verdict: ShieldVerdict) -> None``.
            fail_closed: If True, errors in Agent Shield evaluation
                result in a block. If False, errors result in allow.
        """
        self._runtime = runtime
        self._trust_score_variable = trust_score_variable
        self._agent_id_variable = agent_id_variable
        self._on_violation = on_violation or self._default_violation_handler
        self._fail_closed = fail_closed
        self._session: Any | None = None
        self._session_id: str = ""
        self._history: list[ShieldVerdict] = []
        self._turn_active = False
        self._trust_score: int | None = None
        self._agent_id: str | None = None

    @classmethod
    def from_yaml(
        cls,
        yaml_path: str,
        *,
        trust_score_variable: str = "agt_trust_score",
        fail_closed: bool = True,
        **kwargs: Any,
    ) -> AgentShieldKernel:
        """Create a kernel from a .guardrails.yaml file.

        Args:
            yaml_path: Path to the Agent Shield guardrails YAML file.
            trust_score_variable: Agent Shield variable name for trust scores.
            fail_closed: Block on evaluation errors if True.
            **kwargs: Additional arguments passed to RuntimeBuilder.

        Returns:
            An initialized AgentShieldKernel.

        Raises:
            ImportError: If the agent-shield package is not installed.
        """
        if not _HAS_AGENT_SHIELD:
            raise ImportError(
                "agent-shield package is required for AgentShieldKernel. "
                "Install it with: pip install agent-shield"
            )
        runtime = _RuntimeBuilder.from_yaml(yaml_path).build()
        return cls(
            runtime,
            trust_score_variable=trust_score_variable,
            fail_closed=fail_closed,
            **kwargs,
        )

    @classmethod
    def mock(cls, **kwargs: Any) -> AgentShieldKernel:
        """Create a mock kernel for testing without Agent Shield SDK.

        All validations will return allowed=True. Useful for unit tests
        and development environments.

        Returns:
            An AgentShieldKernel backed by a mock runtime.
        """
        return cls(_MockRuntime(), **kwargs)

    def _default_violation_handler(self, verdict: ShieldVerdict) -> None:
        """Log a warning when Agent Shield blocks an action."""
        logger.warning(
            "Agent Shield blocked at stage %s: %s (policy: %s)",
            verdict.stage.value,
            verdict.reason,
            verdict.policy_name or "unknown",
        )

    # ------------------------------------------------------------------
    # Session management
    # ------------------------------------------------------------------

    def start_session(
        self,
        session_id: str = "default",
        correlation_id: str = "",
    ) -> None:
        """Start a new Agent Shield session.

        Creates a new session on the Agent Shield runtime. Each session
        maintains its own variable state and turn history.

        Args:
            session_id: Unique identifier for this conversation.
            correlation_id: Correlation ID for distributed tracing.
        """
        self._session_id = session_id
        try:
            self._session = self._runtime.new_session(
                session_id=session_id,
                correlation_id=correlation_id,
            )
        except TypeError:
            # Mock runtime may not accept kwargs
            self._session = self._runtime.new_session()

        # Inject AGT context variables
        if self._trust_score is not None:
            self._session.set_variable(
                self._trust_score_variable, self._trust_score
            )
        if self._agent_id is not None:
            self._session.set_variable(
                self._agent_id_variable, self._agent_id
            )

        logger.debug("Agent Shield session started: %s", session_id)

    def end_session(self) -> None:
        """End the current Agent Shield session."""
        if self._turn_active:
            self.end_turn()
        self._session = None
        self._session_id = ""

    def begin_turn(self) -> None:
        """Begin a new turn within the current session."""
        self._ensure_session()
        self._session.begin_turn()
        self._turn_active = True

    def end_turn(self) -> None:
        """End the current turn within the session."""
        if self._session and self._turn_active:
            self._session.end_turn()
            self._turn_active = False

    def _ensure_session(self) -> None:
        """Create a session if one doesn't exist."""
        if self._session is None:
            self.start_session()

    def _ensure_turn(self) -> None:
        """Begin a turn if one isn't active."""
        self._ensure_session()
        if not self._turn_active:
            self.begin_turn()

    # ------------------------------------------------------------------
    # Trust score integration
    # ------------------------------------------------------------------

    def set_trust_score(self, score: int) -> None:
        """Inject the AGT trust score into Agent Shield as a variable.

        Guard policies in the .guardrails.yaml can reference this score::

            evaluate_when:
              - expression: "agt_trust_score >= 500"
                reason: "Agent trust score too low for this action"

        Args:
            score: AGT trust score (0-1000).
        """
        self._trust_score = score
        if self._session:
            self._session.set_variable(self._trust_score_variable, score)

    def set_agent_id(self, agent_id: str) -> None:
        """Inject the AGT agent identity into Agent Shield.

        Args:
            agent_id: AGT agent identifier (DID or SPIFFE ID).
        """
        self._agent_id = agent_id
        if self._session:
            self._session.set_variable(self._agent_id_variable, agent_id)

    # ------------------------------------------------------------------
    # Stage 1: Input validation
    # ------------------------------------------------------------------

    def validate_input(self, text: str) -> ShieldVerdict:
        """Validate agent input through Agent Shield Stage 1.

        Stage 1 screens the raw user message for jailbreak attempts,
        prompt injection, and content moderation violations.

        Args:
            text: The raw user input to validate.

        Returns:
            ShieldVerdict indicating whether the input is allowed.
        """
        self._ensure_turn()
        start = time.monotonic()
        try:
            result = self._session.validate_input(text)
            elapsed = (time.monotonic() - start) * 1000
            verdict = self._translate_verdict(
                result, ValidationStage.INPUT, elapsed
            )
        except Exception as e:
            elapsed = (time.monotonic() - start) * 1000
            verdict = self._error_verdict(
                ValidationStage.INPUT, str(e), elapsed
            )

        self._record(verdict)
        return verdict

    # ------------------------------------------------------------------
    # Stage 2+3: Tool call validation (state + execution)
    # ------------------------------------------------------------------

    def validate_tool_call(
        self,
        tool_name: str,
        parameters: dict[str, Any] | None = None,
    ) -> ToolCallVerdict:
        """Validate a tool call through Agent Shield Stages 2 and 3.

        Stage 2 (state validation) checks whether the tool call is
        allowed given the current session state and variables.

        Stage 3 (tool execution) validates the specific parameters,
        applies transforms (redact, append, prepend), and runs any
        LLM-judge validators.

        Args:
            tool_name: Name of the tool being called.
            parameters: Tool call parameters.

        Returns:
            ToolCallVerdict with verdicts from both stages.
        """
        self._ensure_turn()
        params = dict(parameters or {})

        # Stage 2: State validation
        start = time.monotonic()
        try:
            state_result = self._session.validate_tool_call(tool_name, params)
            elapsed = (time.monotonic() - start) * 1000
            state_verdict = self._translate_verdict(
                state_result, ValidationStage.STATE, elapsed
            )
        except Exception as e:
            elapsed = (time.monotonic() - start) * 1000
            state_verdict = self._error_verdict(
                ValidationStage.STATE, str(e), elapsed
            )

        self._record(state_verdict)

        # Stage 3: Tool execution validation (only if state passed)
        if state_verdict.allowed:
            start = time.monotonic()
            try:
                # Agent Shield SDK combines state+execution in validate_tool_call
                # The execution verdict is embedded in the same result
                exec_verdict = ShieldVerdict(
                    allowed=True,
                    stage=ValidationStage.TOOL_EXECUTION,
                    action=ShieldAction.ALLOW,
                    elapsed_ms=(time.monotonic() - start) * 1000,
                )
                # If the SDK modified parameters (redaction), capture that
                if hasattr(state_result, "params"):
                    params = state_result.params
            except Exception as e:
                elapsed = (time.monotonic() - start) * 1000
                exec_verdict = self._error_verdict(
                    ValidationStage.TOOL_EXECUTION, str(e), elapsed
                )
        else:
            exec_verdict = ShieldVerdict(
                allowed=False,
                stage=ValidationStage.TOOL_EXECUTION,
                action=ShieldAction.BLOCK,
                reason="Skipped: state validation failed",
            )

        self._record(exec_verdict)

        return ToolCallVerdict(
            allowed=state_verdict.allowed and exec_verdict.allowed,
            state_verdict=state_verdict,
            execution_verdict=exec_verdict,
            tool_name=tool_name,
            parameters=params,
        )

    # ------------------------------------------------------------------
    # Stage 4: Post-tool validation
    # ------------------------------------------------------------------

    def validate_tool_result(
        self,
        tool_name: str,
        result: Any,
    ) -> ShieldVerdict:
        """Validate a tool result through Agent Shield Stage 4.

        Stage 4 screens the raw tool output for leaked secrets,
        blocked content, and applies redaction transforms.

        Args:
            tool_name: Name of the tool that produced the result.
            result: The raw tool output to validate.

        Returns:
            ShieldVerdict indicating whether the result is safe.
        """
        self._ensure_turn()
        start = time.monotonic()
        try:
            sdk_result = self._session.validate_tool_result(tool_name, result)
            elapsed = (time.monotonic() - start) * 1000
            verdict = self._translate_verdict(
                sdk_result, ValidationStage.POST_TOOL, elapsed
            )
        except Exception as e:
            elapsed = (time.monotonic() - start) * 1000
            verdict = self._error_verdict(
                ValidationStage.POST_TOOL, str(e), elapsed
            )

        self._record(verdict)
        return verdict

    # ------------------------------------------------------------------
    # Stage 5: Output validation
    # ------------------------------------------------------------------

    def validate_output(self, text: str) -> ShieldVerdict:
        """Validate agent output through Agent Shield Stage 5.

        Stage 5 enforces output policies: PII redaction, compliance
        disclaimers, content policy enforcement.

        Args:
            text: The agent's response text to validate.

        Returns:
            ShieldVerdict. Check modified_value for any redacted output.
        """
        self._ensure_turn()
        start = time.monotonic()
        try:
            result = self._session.validate_output(text)
            elapsed = (time.monotonic() - start) * 1000
            verdict = self._translate_verdict(
                result, ValidationStage.OUTPUT, elapsed
            )
            # Capture modified output text (after redaction/append/prepend)
            if hasattr(result, "response") and result.response != text:
                verdict.modified_value = result.response
        except Exception as e:
            elapsed = (time.monotonic() - start) * 1000
            verdict = self._error_verdict(
                ValidationStage.OUTPUT, str(e), elapsed
            )

        self._record(verdict)
        return verdict

    # ------------------------------------------------------------------
    # Verdict translation
    # ------------------------------------------------------------------

    def _translate_verdict(
        self,
        sdk_result: Any,
        stage: ValidationStage,
        elapsed_ms: float,
    ) -> ShieldVerdict:
        """Translate an Agent Shield SDK verdict to AGT ``ShieldVerdict``.

        Maps the SDK's boolean-truthy result and optional ``reason`` /
        ``policy_name`` attributes to the standardised AGT verdict type.
        A ``None`` result is treated as a denial (fail-closed).

        When the policy denies the request the returned verdict carries
        ``metadata["source"] == "policy_denial"`` so callers can
        distinguish intentional policy blocks from SDK errors (which
        carry ``metadata["source"] == "sdk_error"``).

        Args:
            sdk_result: The raw verdict object returned by the Agent
                Shield SDK session method (or ``None``).
            stage: The validation stage that produced this verdict.
            elapsed_ms: Wall-clock time for the SDK call.

        Returns:
            A ``ShieldVerdict`` with ``source`` metadata on denials.
        """
        allowed = bool(sdk_result) if sdk_result is not None else False
        reason = getattr(sdk_result, "reason", None) or ""
        policy_name = getattr(sdk_result, "policy_name", None) or ""

        if allowed:
            action = ShieldAction.ALLOW
        else:
            action = ShieldAction.BLOCK

        metadata: dict[str, Any] = {}
        if not allowed:
            metadata["source"] = "policy_denial"

        return ShieldVerdict(
            allowed=allowed,
            stage=stage,
            action=action,
            reason=str(reason),
            policy_name=str(policy_name),
            elapsed_ms=elapsed_ms,
            metadata=metadata,
        )

    def _error_verdict(
        self,
        stage: ValidationStage,
        error: str,
        elapsed_ms: float,
    ) -> ShieldVerdict:
        """Create a verdict for an Agent Shield SDK or runtime error.

        Distinct from a policy denial: the returned verdict carries
        ``metadata["source"] == "sdk_error"`` (plus the raw error
        string in ``metadata["error"]``) so callers can programmatically
        distinguish infrastructure failures from intentional policy
        blocks (which carry ``metadata["source"] == "policy_denial"``).

        The ``fail_closed`` flag controls the outcome:

        * ``True``  → BLOCK (denied, safe default).
        * ``False`` → WARN  (allowed, but logged as degraded).

        Args:
            stage: The validation stage where the error occurred.
            error: Human-readable error description.
            elapsed_ms: Wall-clock time before the error was caught.

        Returns:
            A ``ShieldVerdict`` with ``source`` and ``error`` metadata.
        """
        allowed = not self._fail_closed
        action = ShieldAction.BLOCK if self._fail_closed else ShieldAction.WARN
        logger.error(
            "Agent Shield error at stage %s: %s (fail_closed=%s)",
            stage.value,
            error,
            self._fail_closed,
        )
        return ShieldVerdict(
            allowed=allowed,
            stage=stage,
            action=action,
            reason=f"Agent Shield error: {error}",
            elapsed_ms=elapsed_ms,
            metadata={"source": "sdk_error", "error": error},
        )

    def _record(self, verdict: ShieldVerdict) -> None:
        """Record a verdict in history and invoke violation handler."""
        self._history.append(verdict)
        if not verdict.allowed and self._on_violation:
            self._on_violation(verdict)

    # ------------------------------------------------------------------
    # Observability
    # ------------------------------------------------------------------

    def get_history(self) -> list[ShieldVerdict]:
        """Return all validation verdicts from this kernel's lifetime.

        Returns:
            List of ShieldVerdict objects in chronological order.
        """
        return list(self._history)

    def get_stats(self) -> dict[str, Any]:
        """Return Agent Shield validation statistics.

        Returns:
            Dict with total validations, pass/fail counts, and per-stage
            breakdown.
        """
        total = len(self._history)
        passed = sum(1 for v in self._history if v.allowed)
        by_stage: dict[str, dict[str, int]] = {}
        for v in self._history:
            stage = v.stage.value
            if stage not in by_stage:
                by_stage[stage] = {"total": 0, "passed": 0, "blocked": 0}
            by_stage[stage]["total"] += 1
            if v.allowed:
                by_stage[stage]["passed"] += 1
            else:
                by_stage[stage]["blocked"] += 1

        return {
            "total_validations": total,
            "passed": passed,
            "blocked": total - passed,
            "pass_rate": passed / total if total > 0 else 1.0,
            "by_stage": by_stage,
            "session_id": self._session_id,
            "agent_shield_available": _HAS_AGENT_SHIELD,
        }

    def reset(self) -> None:
        """Clear validation history."""
        self._history.clear()


__all__ = [
    "AgentShieldKernel",
    "ShieldVerdict",
    "ToolCallVerdict",
    "ValidationStage",
    "ShieldAction",
]
