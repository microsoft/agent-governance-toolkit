# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""LangGraph integration backed by a required native ACS runtime.

Nodes and tool calls are mediated before execution. Checkpoint fingerprinting
detects stale authorization state on resume.
"""

from __future__ import annotations

import hashlib
import inspect
import json
import logging
import time
from datetime import datetime
from typing import Any, Optional

from ._native_adapter_runtime import NativeAdapterRuntime
from .base import (
    BaseIntegration,
    AdapterExecutionState,
    GovernanceEventType,
    PolicyViolationError,
)

logger = logging.getLogger("agent_os.langgraph")

# ── Graceful LangGraph import ──────────────────────────────────────────
try:
    from langgraph.graph import StateGraph  # type: ignore[import-untyped]
    from langgraph.graph.state import CompiledStateGraph as CompiledGraph  # type: ignore[import-untyped]
    _HAS_LANGGRAPH = True
except ImportError:
    StateGraph = None  # type: ignore[assignment,misc]
    CompiledGraph = None  # type: ignore[assignment,misc]
    _HAS_LANGGRAPH = False

# Sentinel attribute name written onto wrapped node callables
_GOVERNED_SENTINEL = "_agt_governed"

# Fingerprint schema version — bump when the fingerprint payload structure changes
_FINGERPRINT_SCHEMA_VERSION = "1"


def _require_langgraph() -> None:
    """Raise a clear ImportError when langgraph is not installed."""
    if not _HAS_LANGGRAPH:
        raise ImportError(
            "The 'langgraph' package is required for LangGraphKernel. "
            "Install it with: pip install 'agent-os-kernel[langgraph]'"
        )


# ══════════════════════════════════════════════════════════════════════
# GovernedGraph
# ══════════════════════════════════════════════════════════════════════

class GovernedGraph:
    """A StateGraph wrapped with AGT governance hooks.

    Do not instantiate directly — use :meth:`LangGraphKernel.wrap_graph`.
    """

    def __init__(
        self,
        graph: Any,
        kernel: "LangGraphKernel",
        ctx: AdapterExecutionState,
    ) -> None:
        self._graph = graph
        self._kernel = kernel
        self._ctx = ctx

    def compile(self, **kwargs: Any) -> Any:
        """Compile the governed graph, wrapping the checkpointer if provided."""
        checkpointer = kwargs.get("checkpointer")
        if checkpointer is not None:
            kwargs["checkpointer"] = _GovernedCheckpointer(
                checkpointer, self._kernel, self._ctx
            )
        return self._graph.compile(**kwargs)

    def __getattr__(self, name: str) -> Any:
        return getattr(self._graph, name)


# ══════════════════════════════════════════════════════════════════════
# _GovernedCheckpointer
# ══════════════════════════════════════════════════════════════════════

class _GovernedCheckpointer:
    """Wraps a LangGraph Checkpointer to add stale-auth fingerprinting.

    Stores the authorization fingerprint in checkpoint metadata on save.
    Validates the fingerprint against the current policy on resume (get).
    """

    def __init__(
        self,
        checkpointer: Any,
        kernel: "LangGraphKernel",
        ctx: AdapterExecutionState,
    ) -> None:
        self._cp = checkpointer
        self._kernel = kernel
        self._ctx = ctx

    # ── Sync interface ────────────────────────────────────────────────

    def put(self, config: Any, checkpoint: Any, metadata: Any, new_versions: Any) -> Any:
        """Intercept checkpoint saves — inject authorization fingerprint."""
        metadata = self._kernel._inject_fingerprint(metadata, self._ctx)
        return self._cp.put(config, checkpoint, metadata, new_versions)

    def get(self, config: Any) -> Any:
        """Intercept checkpoint reads — validate fingerprint before resume."""
        result = self._cp.get(config)
        if result is not None:
            self._kernel._validate_fingerprint(result, self._ctx)
        return result

    def get_tuple(self, config: Any) -> Any:
        result = self._cp.get_tuple(config)
        if result is not None:
            metadata = getattr(result, "metadata", {}) or {}
            self._kernel._validate_checkpoint_metadata(metadata, self._ctx)
        return result

    # ── Async interface ───────────────────────────────────────────────

    async def aput(self, config: Any, checkpoint: Any, metadata: Any, new_versions: Any) -> Any:
        """Async checkpoint save — inject authorization fingerprint."""
        metadata = self._kernel._inject_fingerprint(metadata, self._ctx)
        return await self._cp.aput(config, checkpoint, metadata, new_versions)

    async def aget(self, config: Any) -> Any:
        """Async checkpoint read — validate fingerprint before resume."""
        result = await self._cp.aget(config)
        if result is not None:
            self._kernel._validate_fingerprint(result, self._ctx)
        return result

    async def aget_tuple(self, config: Any) -> Any:
        result = await self._cp.aget_tuple(config)
        if result is not None:
            metadata = getattr(result, "metadata", {}) or {}
            self._kernel._validate_checkpoint_metadata(metadata, self._ctx)
        return result

    def __getattr__(self, name: str) -> Any:
        return getattr(self._cp, name)


# ══════════════════════════════════════════════════════════════════════
# LangGraphKernel
# ══════════════════════════════════════════════════════════════════════

class LangGraphKernel(BaseIntegration):
    """Govern LangGraph nodes, tools, transitions, and checkpoints."""

    def __init__(
        self,
        audit_only_stale_auth: bool = False,
        *,
        runtime: Any,
    ) -> None:
        _require_langgraph()
        super().__init__(runtime=runtime)
        self._adapter_runtime = NativeAdapterRuntime(runtime)
        self.audit_only_stale_auth = audit_only_stale_auth
        self._tool_callables: dict[str, Any] = {}
        self._start_time = time.monotonic()
        self._last_error: Optional[str] = None
        self._node_execution_log: list[dict[str, Any]] = []
        self._transition_log: list[dict[str, Any]] = []

    # ── Public API ────────────────────────────────────────────────────

    def wrap_graph(self, graph: Any) -> GovernedGraph:
        """Wrap a LangGraph StateGraph with governance hooks.

        Must be called **after** ``add_node()`` and **before** ``compile()``.

        Args:
            graph: A :class:`~langgraph.graph.StateGraph` instance.

        Returns:
            A :class:`GovernedGraph` whose ``compile()`` method injects
            the governed checkpointer automatically.

        Raises:
            ImportError: If ``langgraph`` is not installed.
            TypeError: If a ``CompiledGraph`` is passed in (too late to hook).
        """
        _require_langgraph()
        if CompiledGraph is not None and isinstance(graph, CompiledGraph):
            raise TypeError(
                "wrap_graph() must be called on a StateGraph before compile(), "
                "not on a CompiledGraph. Pass the graph before calling .compile()."
            )

        agent_id = f"langgraph-{id(graph)}"
        ctx = self.create_context(agent_id)

        self._wrap_nodes(graph, ctx)
        logger.info("LangGraphKernel: wrapped graph %s", agent_id)
        return GovernedGraph(graph, self, ctx)

    def wrap(self, agent: Any) -> Any:
        """Alias for :meth:`wrap_graph` to satisfy ``BaseIntegration`` contract."""
        return self.wrap_graph(agent)

    def unwrap(self, governed: Any) -> Any:
        """Return the original StateGraph from a :class:`GovernedGraph`."""
        if isinstance(governed, GovernedGraph):
            return governed._graph
        return governed

    def register_tool(self, tool_name: str, fn: Any) -> None:
        """Register a tool callable for content-hash fingerprinting.

        Call this for any tool function that participates in governance so
        that its source hash can be included in the authorization fingerprint.

        Args:
            tool_name: The tool name as it appears in ``allowed_tools``.
            fn: The callable implementing the tool.
        """
        self._tool_callables[tool_name] = fn

    # ── Hook implementations ──────────────────────────────────────────

    def before_node_execution(
        self,
        node_name: str,
        state: dict[str, Any],
        config: dict[str, Any],
        ctx: AdapterExecutionState,
    ) -> None:
        """Policy gate before a graph node runs.

        Raises:
            PolicyViolationError: If the node is blocked by policy.
        """
        logger.debug("before_node_execution: node=%s", node_name)

        evaluation = self._adapter_runtime.evaluate_input(ctx, body=state)
        if not evaluation.allowed:
            raise evaluation.to_policy_violation(PolicyViolationError)

        # ── 3. Audit record ──────────────────────────────────────────
        record = {
            "node_name": node_name,
            "timestamp": datetime.now().isoformat(),
            "agent_id": ctx.agent_id,
        }
        self._node_execution_log.append(record)
        self.emit(GovernanceEventType.POLICY_CHECK, {
            **record, "phase": "before_node_execution",
        })
        logger.info("before_node_execution ALLOW: node=%s", node_name)

    def before_tool_call(
        self,
        tool_name: str,
        tool_input: dict[str, Any],
        ctx: AdapterExecutionState,
    ) -> None:
        """Tool-level governance gate.

        Raises:
            PolicyViolationError: If the tool call is blocked by policy.
        """
        logger.debug("before_tool_call: tool=%s", tool_name)

        evaluation = self._adapter_runtime.evaluate_pre_tool_call(
            ctx,
            tool_name=tool_name,
            args=tool_input,
            call_id=f"langgraph-{ctx.call_count + 1}",
        )
        if not evaluation.allowed:
            raise evaluation.to_policy_violation(PolicyViolationError)
        ctx.call_count += 1

        ctx.tool_calls.append({
            "tool_name": tool_name,
            "timestamp": datetime.now().isoformat(),
        })
        logger.info("before_tool_call ALLOW: tool=%s count=%d", tool_name, ctx.call_count)

    def on_state_transition(
        self,
        from_node: str,
        to_node: str,
        state: dict[str, Any],
        ctx: AdapterExecutionState,
    ) -> None:
        """Audit-only hook for graph edge traversals.

        Does not block by default. Records every node->node transition
        for the governance audit trail.
        """
        record = {
            "from_node": from_node,
            "to_node": to_node,
            "timestamp": datetime.now().isoformat(),
            "agent_id": ctx.agent_id,
        }
        self._transition_log.append(record)
        self.emit(GovernanceEventType.CHECKPOINT_CREATED, {
            **record, "phase": "state_transition",
        })
        logger.debug("on_state_transition: %s -> %s", from_node, to_node)

    # ── Fingerprint helpers ───────────────────────────────────────────

    def _compute_authorization_fingerprint(self, ctx: AdapterExecutionState) -> str:
        """SHA-256 of the enforcement-relevant authorization surface.

        Covers:
        - All enforcement-relevant policy fields (via to_dict())
        - Tool content hashes where source is available
        - Cedar/OPA evaluator revision when configured
        - Schema version field for future-proofing
        """
        # 1. Native manifest surface
        manifest = self._adapter_runtime.runtime.manifest
        policy_data = manifest.to_document() if manifest is not None else {}
        governed_tools = list(manifest.tools) if manifest is not None else []

        # 2. Tool content hashes (source SHA-256 for registered callables)
        tool_hashes: dict[str, str] = {}
        for tool_name in governed_tools:
            fn = self._tool_callables.get(tool_name)
            if fn is not None:
                try:
                    src = inspect.getsource(fn).encode()
                    tool_hashes[tool_name] = hashlib.sha256(src).hexdigest()[:16]
                except (OSError, TypeError):
                    tool_hashes[tool_name] = "source-unavailable"
            else:
                tool_hashes[tool_name] = "not-registered"

        # 3. Cedar/OPA evaluator revision (if configured)
        evaluator_rev = ""
        if self._evaluator is not None:
            evaluator_rev = (
                getattr(self._evaluator, "bundle_revision", "")
                or getattr(self._evaluator, "backend_version", "")
                or "unknown"
            )

        payload = {
            "_fingerprint_schema_version": _FINGERPRINT_SCHEMA_VERSION,
            "policy": policy_data,
            "tool_hashes": tool_hashes,
            "evaluator_revision": evaluator_rev,
        }
        canonical = json.dumps(payload, sort_keys=True, separators=(",", ":"))
        return hashlib.sha256(canonical.encode()).hexdigest()

    def _inject_fingerprint(
        self, metadata: Any, ctx: AdapterExecutionState
    ) -> dict[str, Any]:
        """Add the authorization fingerprint to checkpoint metadata."""
        if metadata is None:
            metadata = {}
        elif not isinstance(metadata, dict):
            metadata = dict(metadata)
        else:
            metadata = dict(metadata)

        fingerprint = self._compute_authorization_fingerprint(ctx)
        metadata["_agt_auth_fingerprint"] = fingerprint
        metadata["_agt_fingerprint_schema"] = _FINGERPRINT_SCHEMA_VERSION
        metadata["_agt_session_id"] = ctx.session_id

        ctx.checkpoints.append(fingerprint[:12])
        self.emit(GovernanceEventType.CHECKPOINT_CREATED, {
            "agent_id": ctx.agent_id,
            "fingerprint_prefix": fingerprint[:12],
            "timestamp": datetime.now().isoformat(),
        })
        logger.debug("Checkpoint fingerprint stored: %s...", fingerprint[:12])
        return metadata

    def _validate_fingerprint(self, checkpoint_result: Any, ctx: AdapterExecutionState) -> None:
        """Validate checkpoint fingerprint on resume — detect stale-auth."""
        metadata = getattr(checkpoint_result, "metadata", None)
        if metadata is None and isinstance(checkpoint_result, dict):
            metadata = checkpoint_result.get("metadata", {})
        self._validate_checkpoint_metadata(metadata or {}, ctx)

    def _validate_checkpoint_metadata(
        self, metadata: dict[str, Any], ctx: AdapterExecutionState
    ) -> None:
        """Core stale-auth validation logic.

        Raises:
            PolicyViolationError: If fingerprint is missing or mismatched
                and ``audit_only_stale_auth`` is ``False`` (default).
        """
        stored = metadata.get("_agt_auth_fingerprint")

        if stored is None:
            msg = (
                "Checkpoint is missing authorization fingerprint — "
                "resume blocked (possible checkpoint from before governance "
                "was applied, or metadata corruption)"
            )
            self.emit(GovernanceEventType.DRIFT_DETECTED, {
                "agent_id": ctx.agent_id,
                "reason": "missing_fingerprint",
                "timestamp": datetime.now().isoformat(),
            })
            if self.audit_only_stale_auth:
                logger.warning("STALE-AUTH AUDIT: %s", msg)
                return
            raise PolicyViolationError(msg)

        current = self._compute_authorization_fingerprint(ctx)
        if stored != current:
            diff_msg = (
                f"Stale authorization detected on checkpoint resume: "
                f"stored fingerprint {stored[:12]}... does not match "
                f"current policy fingerprint {current[:12]}... — "
                "policy or tool grants changed since this checkpoint was saved"
            )
            self.emit(GovernanceEventType.DRIFT_DETECTED, {
                "agent_id": ctx.agent_id,
                "reason": "fingerprint_mismatch",
                "stored_prefix": stored[:12],
                "current_prefix": current[:12],
                "timestamp": datetime.now().isoformat(),
            })
            if self.audit_only_stale_auth:
                logger.warning("STALE-AUTH AUDIT: %s", diff_msg)
                return
            raise PolicyViolationError(diff_msg)

        logger.debug(
            "Checkpoint fingerprint validated OK: %s...", stored[:12]
        )

    # ── Node wrapping internals ───────────────────────────────────────

    def _wrap_nodes(self, graph: Any, ctx: AdapterExecutionState) -> None:
        """Wrap every node in the StateGraph with governance hooks.

        Handles both plain callables and ToolNode instances.
        Adds sentinel to prevent double-wrapping.
        """
        nodes = getattr(graph, "nodes", {})
        for node_name, node_spec in list(nodes.items()):
            # Extract the actual callable from LangGraph's node spec
            fn = self._extract_callable(node_spec)
            if fn is None:
                logger.debug("Skipping node '%s' — callable not extractable", node_name)
                continue

            if getattr(fn, _GOVERNED_SENTINEL, False):
                logger.debug("Node '%s' already governed — skipping", node_name)
                continue

            wrapped = self._make_node_wrapper(node_name, fn, ctx)
            setattr(wrapped, _GOVERNED_SENTINEL, True)

            # Write the wrapped callable back into the graph node spec
            self._set_node_callable(graph, node_name, node_spec, wrapped)
            logger.debug("Governed node: '%s'", node_name)

    def _extract_callable(self, node_spec: Any) -> Any:
        """Extract the raw callable from a LangGraph node spec.

        LangGraph 1.x stores nodes as ``StateNodeSpec(runnable=RunnableCallable)``.
        The actual user function lives at ``node_spec.runnable.func`` (sync) or
        ``node_spec.runnable.afunc`` (async).  We prefer the sync path; the
        wrapper in :meth:`_make_node_wrapper` is always sync because LangGraph
        invokes the func synchronously through RunnableCallable.
        """
        # LangGraph 1.x: StateNodeSpec -> RunnableCallable -> func
        runnable = getattr(node_spec, "runnable", None)
        if runnable is not None:
            fn = getattr(runnable, "func", None)
            if callable(fn):
                return fn
        # Plain callable (no wrapping layer)
        if callable(node_spec):
            return node_spec
        # Fallback: check common attribute names on node_spec directly
        for attr in ("func", "bound", "_func"):
            fn = getattr(node_spec, attr, None)
            if callable(fn):
                return fn
        return None

    def _set_node_callable(
        self, graph: Any, node_name: str, node_spec: Any, wrapped: Any
    ) -> None:
        """Write the wrapped callable back into the graph's node registry.

        For LangGraph 1.x ``StateNodeSpec``, mutate ``node_spec.runnable.func``
        in-place so the existing ``RunnableCallable`` wrapper (and all its
        metadata) is preserved.
        """
        # LangGraph 1.x: set runnable.func directly on the RunnableCallable
        runnable = getattr(node_spec, "runnable", None)
        if runnable is not None and hasattr(runnable, "func") and callable(getattr(runnable, "func", None)):
            try:
                runnable.func = wrapped
                return
            except (AttributeError, TypeError):
                pass
        # Direct replacement in the nodes dict (plain callable path)
        if hasattr(graph, "nodes") and isinstance(graph.nodes, dict):
            graph.nodes[node_name] = wrapped

    def _make_node_wrapper(
        self, node_name: str, fn: Any, ctx: AdapterExecutionState
    ) -> Any:
        """Return a governed wrapper preserving sync/async semantics."""
        import asyncio
        import functools

        kernel = self

        if asyncio.iscoroutinefunction(fn):
            @functools.wraps(fn)
            async def async_governed_node(
                state: Any, config: Any = None, **kwargs: Any
            ) -> Any:
                kernel.before_node_execution(
                    node_name,
                    state if isinstance(state, dict) else {},
                    config or {},
                    ctx,
                )
                try:
                    if config is not None:
                        result = await fn(state, config, **kwargs)
                    else:
                        result = await fn(state, **kwargs)
                except Exception as exc:
                    kernel._last_error = str(exc)
                    raise
                return result

            setattr(async_governed_node, _GOVERNED_SENTINEL, True)
            return async_governed_node
        else:
            @functools.wraps(fn)
            def sync_governed_node(
                state: Any, config: Any = None, **kwargs: Any
            ) -> Any:
                kernel.before_node_execution(
                    node_name,
                    state if isinstance(state, dict) else {},
                    config or {},
                    ctx,
                )
                try:
                    if config is not None:
                        result = fn(state, config, **kwargs)
                    else:
                        result = fn(state, **kwargs)
                except Exception as exc:
                    kernel._last_error = str(exc)
                    raise
                return result

            setattr(sync_governed_node, _GOVERNED_SENTINEL, True)
            return sync_governed_node

    # ── Health / diagnostics ──────────────────────────────────────────

    def health_check(self) -> dict[str, Any]:
        """Return adapter health status."""
        uptime = time.monotonic() - self._start_time
        return {
            "status": "degraded" if self._last_error else "healthy",
            "backend": "langgraph",
            "backend_connected": _HAS_LANGGRAPH,
            "last_error": self._last_error,
            "uptime_seconds": round(uptime, 2),
            "active_contexts": len(self.contexts),
        }
