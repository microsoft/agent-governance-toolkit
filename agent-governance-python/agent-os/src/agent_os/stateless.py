# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""Stateless Kernel — June 2026 MCP-compliant design.

This module implements a fully stateless execution kernel that complies with
the Model Context Protocol (MCP) specification targeted for June 2026. The
stateless architecture enables horizontal scaling: any kernel instance can
handle any request because no session state is stored in-process.

Architecture overview:
    ┌──────────────┐     ┌────────────────┐     ┌──────────────┐
    │  Client /    │────▶│ StatelessKernel │────▶│ StateBackend │
    │  MCP Host    │◀────│  (any instance) │◀────│ (Redis, etc) │
    └──────────────┘     └────────────────┘     └──────────────┘

Key design principles:
    - **No session state in kernel**: Every request carries its own
      ``ExecutionContext`` with agent identity, policy list, and history.
    - **All context passed per request**: The kernel never looks up prior
      requests; the caller is responsible for threading context.
    - **Pluggable state backends**: State that must persist (e.g. agent
      working memory) is stored in an external backend implementing the
      ``StateBackend`` protocol. Built-in backends:

      - ``MemoryBackend``: In-memory dict with TTL support (dev/test only).
      - ``RedisBackend``: Production-grade backend with connection pooling,
        configurable timeouts, and optional ``RedisConfig``.

    - **Horizontally scalable**: Because kernels are stateless, you can
      run N replicas behind a load balancer with no sticky sessions.

State serialization format:
    All state values are serialized as JSON via ``json.dumps`` / ``json.loads``.
    Keys are prefixed with a configurable namespace (default ``"agent-os:"``)
    to avoid collisions in shared Redis instances. A ``SerializationError``
    is raised if a value cannot be round-tripped through JSON.

Resilience:
    Backend calls are wrapped in a circuit breaker (see ``CircuitBreaker``)
    that opens after repeated failures, preventing cascade failures when
    the backend is unavailable.

Observability:
    When OpenTelemetry is installed, the kernel emits spans for every
    ``execute()`` call and backend operation, annotated with action name,
    agent ID, and backend type.

Example:
    >>> from agent_os.stateless import StatelessKernel, ExecutionContext
    >>> kernel = StatelessKernel()
    >>> ctx = ExecutionContext(agent_id="a1", policies=["read_only"])
    >>> result = await kernel.execute("database_query", {"query": "SELECT 1"}, ctx)
    >>> assert result.success
"""

from __future__ import annotations

import hashlib
import json
import logging
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Protocol

from agent_os.circuit_breaker import CircuitBreaker, CircuitBreakerConfig, CircuitBreakerOpen
from agent_os.exceptions import SerializationError

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Optional OpenTelemetry support
# Design decision: OTel is opt-in to avoid adding a hard dependency.
# When present, every kernel.execute() and backend call emits a trace span
# so operators can correlate latency across services.
# ---------------------------------------------------------------------------
try:
    from opentelemetry import context as _otel_context
    from opentelemetry import trace as _otel_trace

    _HAS_OTEL = True
except ImportError:  # pragma: no cover
    _otel_trace = None  # type: ignore[assignment]
    _otel_context = None  # type: ignore[assignment]
    _HAS_OTEL = False


# =============================================================================
# State Backend Protocol
# Design decision: Using typing.Protocol (structural subtyping) instead of
# an ABC so that any object with get/set/delete methods satisfies the
# contract without explicit inheritance.  This makes it easy to adapt
# third-party clients (e.g. DynamoDB, Cosmos DB) as backends.
# =============================================================================

class StateBackend(Protocol):
    """Protocol for external state storage.

    Any object implementing ``get``, ``set``, and ``delete`` as async
    methods satisfies this protocol via structural subtyping — no
    explicit inheritance required.

    All values are JSON-serializable dictionaries. Keys are plain strings
    (the backend may add its own prefix for namespacing).

    Args:
        key: A unique string identifying the state entry.
        value: A JSON-serializable dictionary to store.
        ttl: Optional time-to-live in seconds. After expiry the entry
            should be treated as deleted.
    """

    async def get(self, key: str) -> dict[str, Any] | None:
        """Get state by key."""
        ...

    async def set(self, key: str, value: dict[str, Any], ttl: int | None = None) -> None:
        """Set state with optional TTL."""
        ...

    async def delete(self, key: str) -> None:
        """Delete state."""
        ...


class MemoryBackend:
    """In-memory state backend for testing and development.

    Stores state as ``{key: (value_dict, expires_at)}`` tuples in a plain
    Python dictionary. TTL expiry is checked lazily on ``get()``; expired
    entries are removed on access rather than via a background sweep.

    Warning:
        Not suitable for production. State is lost on process restart and
        is not shared across kernel replicas. Use ``RedisBackend`` for
        production deployments.
    """

    def __init__(self) -> None:
        # Store maps key -> (value_dict, optional_expiry_monotonic_time).
        # Using monotonic clock for TTL avoids issues with wall-clock jumps.
        self._store: dict[str, tuple[dict[str, Any], float | None]] = {}
        self._debug = False

    async def get(self, key: str) -> dict[str, Any] | None:
        entry = self._store.get(key)
        if entry is None:
            return None
        value, expires_at = entry
        if expires_at is not None and time.monotonic() >= expires_at:
            del self._store[key]
            return None
        return value

    async def set(self, key: str, value: dict[str, Any], ttl: int | None = None) -> None:
        expires_at = (time.monotonic() + ttl) if ttl is not None else None
        self._store[key] = (value, expires_at)

    async def delete(self, key: str) -> None:
        self._store.pop(key, None)


@dataclass
class RedisConfig:
    """Configuration for Redis connection pooling and timeouts.

    Args:
        host: Redis server hostname.
        port: Redis server port.
        db: Redis database number.
        password: Optional authentication password.
        pool_size: Maximum number of connections in the pool.
        connect_timeout: Timeout in seconds for establishing a connection.
        read_timeout: Timeout in seconds for reading a response.
        retry_on_timeout: Whether to retry commands that time out.
    """

    host: str = "localhost"
    port: int = 6379
    db: int = 0
    password: str | None = None
    pool_size: int = 10
    connect_timeout: float = 5.0
    read_timeout: float = 10.0
    retry_on_timeout: bool = True

    def to_url(self) -> str:
        """Build a Redis URL from host/port/db."""
        auth = f":{self.password}@" if self.password else ""
        return f"redis://{auth}{self.host}:{self.port}/{self.db}"


class RedisBackend:
    """Redis state backend (for production).

    Supports connection pooling and configurable timeouts via ``RedisConfig``.
    When no config is provided the legacy ``url`` parameter is used with
    default timeout/pool behaviour for backward compatibility.
    """

    def __init__(
        self,
        url: str = "redis://localhost:6379",
        key_prefix: str = "agent-os:",
        config: RedisConfig | None = None,
    ):
        if not isinstance(key_prefix, str):
            raise TypeError(f"key_prefix must be str, got {type(key_prefix).__name__}")
        self._config = config
        self.url = config.to_url() if config else url
        self._client = None
        self._pool = None
        self._prefix = key_prefix

    async def _get_client(self):
        if self._client is None:
            import redis.asyncio as aioredis

            if self._config is not None:
                self._pool = aioredis.ConnectionPool.from_url(
                    self.url,
                    max_connections=self._config.pool_size,
                    socket_connect_timeout=self._config.connect_timeout,
                    socket_timeout=self._config.read_timeout,
                    retry_on_timeout=self._config.retry_on_timeout,
                )
                self._client = aioredis.Redis(connection_pool=self._pool)
            else:
                self._client = aioredis.from_url(self.url)
        return self._client

    async def get(self, key: str) -> dict[str, Any] | None:
        client = await self._get_client()
        data = await client.get(f"{self._prefix}{key}")
        if not data:
            return None
        try:
            return json.loads(data)
        except (json.JSONDecodeError, TypeError) as exc:
            logger.error(
                "Deserialization failed: key=%s error=%s",
                key,
                str(exc),
            )
            raise SerializationError(
                f"Failed to deserialize state for key '{key}': {exc}",
                details={"key": key, "original_error": str(exc)},
            ) from exc

    async def set(self, key: str, value: dict[str, Any], ttl: int | None = None) -> None:
        client = await self._get_client()
        try:
            serialized = json.dumps(value)
        except (TypeError, ValueError) as exc:
            logger.error(
                "Serialization failed: key=%s value_type=%s error=%s",
                key,
                type(value).__name__,
                str(exc),
            )
            raise SerializationError(
                f"Failed to serialize state for key '{key}': {exc}",
                details={
                    "key": key,
                    "value_type": type(value).__name__,
                    "original_error": str(exc),
                },
            ) from exc
        await client.set(f"{self._prefix}{key}", serialized, ex=ttl)

    async def delete(self, key: str) -> None:
        client = await self._get_client()
        await client.delete(f"{self._prefix}{key}")


# =============================================================================
# Stateless Request/Response Types
# Design decision: Using dataclasses (not Pydantic) for request/response
# types to keep the core kernel dependency-free. Pydantic is used in the
# integrations layer where richer validation is needed.
# =============================================================================

@dataclass
class ExecutionContext:
    """Complete context for a stateless execution request.

    All state needed for a request is passed here — the kernel never
    maintains session state internally. Callers are responsible for
    threading the ``updated_context`` from one ``ExecutionResult`` into
    the next request to maintain conversational continuity.

    Args:
        agent_id: Unique identifier of the requesting agent.
        policies: List of policy names to enforce (e.g. ``["read_only"]``).
            Policy definitions are resolved from ``StatelessKernel.policies``.
        history: Chronological list of previous actions in this session,
            each a dict with ``action``, ``timestamp``, and ``success`` keys.
        state_ref: Optional key referencing externalized state in the
            backend. When present, the kernel loads this state before
            execution and persists updates afterward.
        metadata: Arbitrary metadata passed through to the result.
    """
    agent_id: str
    policies: list[str] = field(default_factory=list)
    history: list[dict[str, Any]] = field(default_factory=list)
    state_ref: str | None = None  # Reference to external state
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "agent_id": self.agent_id,
            "policies": self.policies,
            "history": self.history,
            "state_ref": self.state_ref,
            "metadata": self.metadata
        }


@dataclass
class ExecutionRequest:
    """Internal representation of a stateless execution request.

    Created by ``StatelessKernel.execute()`` from the caller-supplied
    action, params, and context. The ``request_id`` is auto-generated as
    a truncated SHA-256 hash to enable correlation in logs without
    requiring the caller to supply an ID.
    """
    action: str
    params: dict[str, Any]
    context: ExecutionContext
    request_id: str | None = None

    def __post_init__(self):
        if self.request_id is None:
            self.request_id = hashlib.sha256(
                f"{self.context.agent_id}:{self.action}:{datetime.now(timezone.utc).isoformat()}".encode()
            ).hexdigest()[:16]


@dataclass
class ExecutionResult:
    """Result of a stateless kernel execution.

    Attributes:
        success: ``True`` if the action completed without policy violation
            or execution error.
        data: The action's return value (arbitrary type). ``None`` on
            failure.
        error: Human-readable error message when ``success`` is ``False``.
        signal: Kernel signal emitted on failure — ``"SIGKILL"`` for policy
            violations, ``"SIGTERM"`` for execution errors.
        updated_context: A new ``ExecutionContext`` reflecting the latest
            history and state reference. Callers should use this as the
            context for subsequent requests.
        metadata: Request metadata including ``request_id`` and timestamp.
    """
    success: bool
    data: Any
    error: str | None = None
    signal: str | None = None
    updated_context: ExecutionContext | None = None
    metadata: dict[str, Any] = field(default_factory=dict)


# =============================================================================
# Stateless Kernel
# Design decision: The kernel is intentionally thin — it delegates policy
# checking, state persistence, and action execution to composable
# components.  This keeps the kernel testable and allows swapping backends
# or policy engines without changing core logic.
# =============================================================================

class StatelessKernel:
    """
    Stateless kernel for MCP June 2026 compliance.

    Design principles:
    - Every request is self-contained
    - State stored in external backend
    - Kernel can run on any instance (horizontal scaling)
    - No agent registration required

    Usage:
        kernel = StatelessKernel(backend=RedisBackend())

        result = await kernel.execute(
            action="database_query",
            params={"query": "SELECT * FROM users"},
            context=ExecutionContext(
                agent_id="analyst-001",
                policies=["read_only", "no_pii"]
            )
        )
    """

    # Default policy rules
    DEFAULT_POLICIES = {
        "read_only": {
            "blocked_actions": ["file_write", "database_write", "send_email"],
            "constraints": {"database_query": {"mode": "read"}}
        },
        "no_pii": {
            "blocked_patterns": ["ssn", "social_security", "credit_card", "password"]
        },
        "strict": {
            "require_approval": ["send_email", "file_write", "code_execution"]
        }
    }

    def __init__(
        self,
        backend: StateBackend | None = None,
        policies: dict[str, Any] | None = None,
        enable_tracing: bool = False,
        circuit_breaker_config: CircuitBreakerConfig | None = None,
    ):
        self.backend = backend or MemoryBackend()
        self.policies = {**self.DEFAULT_POLICIES, **(policies or {})}
        self.enable_tracing = enable_tracing and _HAS_OTEL
        self._tracer = (
            _otel_trace.get_tracer("agent_os.stateless") if self.enable_tracing else None
        )
        self._backend_type = type(self.backend).__name__
        self.circuit_breaker = CircuitBreaker(circuit_breaker_config)

    async def execute(
        self,
        action: str,
        params: dict[str, Any],
        context: ExecutionContext
    ) -> ExecutionResult:
        """
        Execute an action statelessly with full policy governance.

        This is the main entry point. Every request is self-contained:
        policies are checked, the action is executed, state is updated
        externally, and an updated context is returned.

        Args:
            action: Action to execute (e.g., "database_query", "file_write", "chat")
            params: Action parameters (passed to handler and checked against policies)
            context: Complete execution context including agent_id, policies, and history

        Returns:
            ExecutionResult with:
            - success=True, data=result, updated_context (on success)
            - success=False, error=reason, signal="SIGKILL" (on policy violation)
            - success=False, error=str(e), signal="SIGTERM" (on execution error)

        Example:
            >>> result = await kernel.execute(
            ...     action="database_query",
            ...     params={"query": "SELECT * FROM users"},
            ...     context=ExecutionContext(agent_id="a1", policies=["read_only"])
            ... )
            >>> if result.success:
            ...     print(result.data)
            ... else:
            ...     print(f"Blocked: {result.error}")
        """
        request = ExecutionRequest(action=action, params=params, context=context)

        span_ctx = self._start_span("kernel.execute", {
            "operation": "execute",
            "action": action,
            "agent_id": context.agent_id,
            "backend_type": self._backend_type,
        })
        try:
            return await self._execute_inner(request, action, params, context)
        finally:
            self._end_span(span_ctx)

    async def _execute_inner(
        self,
        request: ExecutionRequest,
        action: str,
        params: dict[str, Any],
        context: ExecutionContext,
    ) -> ExecutionResult:
        """Core execute logic, called inside an optional tracing span."""
        # 1. Load external state if referenced
        external_state: dict[str, Any] = {}
        if context.state_ref:
            external_state = await self._backend_get(context.state_ref) or {}

        # 2. Check policies
        policy_result = self._check_policies(action, params, context.policies)
        if not policy_result["allowed"]:
            return ExecutionResult(
                success=False,
                data=None,
                error=policy_result["reason"],
                signal="SIGKILL",
                metadata={
                    "request_id": request.request_id,
                    "violation": policy_result["reason"],
                    "timestamp": datetime.now(timezone.utc).isoformat()
                }
            )

        # 3. Execute action
        try:
            result = await self._execute_action(action, params, external_state)
        except Exception as e:
            return ExecutionResult(
                success=False,
                data=None,
                error=str(e),
                signal="SIGTERM",
                metadata={"request_id": request.request_id}
            )

        # 4. Update external state if needed
        new_state_ref = context.state_ref
        if result.get("state_update"):
            new_state = {**external_state, **result["state_update"]}
            new_state_ref = new_state_ref or f"state:{context.agent_id}"
            await self._backend_set(new_state_ref, new_state)

        # 5. Build updated context
        updated_context = ExecutionContext(
            agent_id=context.agent_id,
            policies=context.policies,
            history=context.history + [{
                "action": action,
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "success": True
            }],
            state_ref=new_state_ref,
            metadata=context.metadata
        )

        return ExecutionResult(
            success=True,
            data=result.get("data"),
            updated_context=updated_context,
            metadata={
                "request_id": request.request_id,
                "timestamp": datetime.now(timezone.utc).isoformat()
            }
        )

    def _check_policies(
        self,
        action: str,
        params: dict[str, Any],
        policy_names: list[str]
    ) -> dict[str, Any]:
        """Check if action is allowed under policies.

        Args:
            action: The action being attempted (e.g., "database_query", "file_write")
            params: Parameters for the action
            policy_names: List of policy names to check against

        Returns:
            Dict with 'allowed' (bool) and 'reason' (str) keys.
            When blocked, includes 'suggestion' with actionable fix.
        """
        for policy_name in policy_names:
            policy = self.policies.get(policy_name)
            if not policy:
                continue

            # Check blocked actions
            if action in policy.get("blocked_actions", []):
                allowed_actions = [a for a in ["read", "query", "list"]
                                   if a not in policy.get("blocked_actions", [])]
                suggestion = (f"Try a read-only action instead (e.g., {', '.join(allowed_actions[:3])})"
                              if allowed_actions else "Request policy exception from administrator")
                return {
                    "allowed": False,
                    "reason": f"Action '{action}' blocked by '{policy_name}' policy. {suggestion}."
                }

            # Check blocked patterns in params
            params_str = json.dumps(params).lower()
            for pattern in policy.get("blocked_patterns", []):
                if pattern.lower() in params_str:
                    return {
                        "allowed": False,
                        "reason": (
                            f"Content blocked: '{pattern}' detected in request parameters. "
                            f"Policy '{policy_name}' prohibits this pattern. "
                            f"Remove the sensitive content and retry."
                        )
                    }

            # Check requires approval
            if action in policy.get("require_approval", []):
                if not params.get("approved"):
                    return {
                        "allowed": False,
                        "reason": (
                            f"Action '{action}' requires approval. "
                            f"Add approved=True to params after getting authorization, "
                            f"or use a non-restricted action instead."
                        )
                    }

        return {"allowed": True, "reason": None}

    async def _execute_action(
        self,
        action: str,
        params: dict[str, Any],
        state: dict[str, Any]
    ) -> dict[str, Any]:
        """Execute action (stub - real impl dispatches to handlers)."""
        return {
            "data": {
                "status": "executed",
                "action": action,
                "result": f"Action '{action}' executed successfully"
            }
        }

    # -----------------------------------------------------------------
    # Backend wrappers (circuit breaker + tracing)
    # Design decision: All backend calls go through the circuit breaker
    # to prevent cascading failures when the backend (e.g. Redis) is
    # down.  The breaker opens after repeated failures and returns
    # CircuitBreakerOpen without hitting the backend, giving it time
    # to recover.
    # -----------------------------------------------------------------

    async def _backend_get(self, key: str) -> dict[str, Any] | None:
        """Get from backend through circuit breaker with tracing."""
        span_ctx = self._start_span("kernel.backend.get", {
            "operation": "get",
            "key": key,
            "backend_type": self._backend_type,
        })
        try:
            return await self.circuit_breaker.call(self.backend.get, key)
        except CircuitBreakerOpen:
            raise
        finally:
            self._end_span(span_ctx)

    async def _backend_set(
        self, key: str, value: dict[str, Any], ttl: int | None = None
    ) -> None:
        """Set in backend through circuit breaker with tracing."""
        span_ctx = self._start_span("kernel.backend.set", {
            "operation": "set",
            "key": key,
            "backend_type": self._backend_type,
        })
        try:
            await self.circuit_breaker.call(self.backend.set, key, value, ttl)
        except CircuitBreakerOpen:
            raise
        finally:
            self._end_span(span_ctx)

    async def _backend_delete(self, key: str) -> None:
        """Delete from backend through circuit breaker with tracing."""
        span_ctx = self._start_span("kernel.backend.delete", {
            "operation": "delete",
            "key": key,
            "backend_type": self._backend_type,
        })
        try:
            await self.circuit_breaker.call(self.backend.delete, key)
        except CircuitBreakerOpen:
            raise
        finally:
            self._end_span(span_ctx)

    # -----------------------------------------------------------------
    # OpenTelemetry helpers
    # -----------------------------------------------------------------

    def _start_span(
        self, name: str, attributes: dict[str, str]
    ) -> Any | None:
        """Start an OTel span if tracing is enabled. Returns a context token."""
        if not self._tracer:
            return None
        span = self._tracer.start_span(name, attributes=attributes)
        ctx = _otel_trace.set_span_in_context(span)
        token = _otel_context.attach(ctx)
        return (span, token)

    @staticmethod
    def _end_span(span_ctx: Any | None) -> None:
        """End the OTel span if present."""
        if span_ctx is None:
            return
        span, token = span_ctx
        span.end()
        _otel_context.detach(token)


# =============================================================================
# Helper Functions
# =============================================================================

async def stateless_execute(
    action: str,
    params: dict,
    agent_id: str,
    policies: list[str] | None = None,
    history: list[dict] | None = None,
    backend: StateBackend | None = None
) -> ExecutionResult:
    """Convenience function for one-shot stateless execution.

    Creates an ephemeral ``StatelessKernel`` and ``ExecutionContext``,
    executes the action, and returns the result. Useful for simple
    scripts and tests where managing a kernel instance is unnecessary.

    Args:
        action: Action to execute (e.g. ``"database_query"``).
        params: Action parameters.
        agent_id: Identifier of the requesting agent.
        policies: Policy names to enforce. Defaults to ``[]``.
        history: Prior action history. Defaults to ``[]``.
        backend: Optional ``StateBackend``. Defaults to ``MemoryBackend``.

    Returns:
        An ``ExecutionResult`` with the outcome of the action.

    Example:
        >>> result = await stateless_execute(
        ...     action="database_query",
        ...     params={"query": "SELECT * FROM users"},
        ...     agent_id="analyst-001",
        ...     policies=["read_only"],
        ... )
        >>> print(result.success)
        True
    """
    kernel = StatelessKernel(backend=backend)
    context = ExecutionContext(
        agent_id=agent_id,
        policies=policies or [],
        history=history or []
    )
    return await kernel.execute(action, params, context)
