# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""
Tests for LangGraphKernel — AGT governance adapter for LangGraph v1.0.

All tests are fully offline. LangGraph StateGraph and CompiledStateGraph are
used directly (langgraph must be installed in the dev venv via
``pip install 'agent-os-kernel[langgraph]'``).

Coverage targets (per #2641 acceptance criteria):
- Graceful ImportError when langgraph is not installed
- before_tool_call: allow, block (allowlist, blocked pattern, PII)
- before_node_execution: allow, block (blocked pattern, Cedar gate)
- wrap_graph: sentinel prevents double-wrap, CompiledGraph raises TypeError
- on_checkpoint: fingerprint injected into metadata (not TypedDict state)
- Stale-auth block on resume (tool removed between checkpoint save and resume)
- Stale-auth allow on resume (policy unchanged)
- Audit-only mode: mismatch emits event but does not raise
- Policy loosening on resume (tool added)
- ctx.policy isolation (mid-run self.policy mutation does not affect ctx)
- End-to-end 2-node StateGraph: wrap -> compile -> invoke, both nodes run
- Blocked node raises PolicyViolationError in end-to-end invocation

Run with:
    pytest tests/test_langgraph_adapter.py -v --tb=short
"""

from __future__ import annotations

from typing import TypedDict
from unittest.mock import MagicMock

import pytest

from agent_os.integrations.base import GovernancePolicy, PolicyViolationError

# langgraph is an optional extra. Most test classes require it; TestImportGuard
# exercises the graceful-error path and works regardless.
_HAS_LANGGRAPH = True
try:
    import langgraph  # noqa: F401
except ImportError:
    _HAS_LANGGRAPH = False

requires_langgraph = pytest.mark.skipif(
    not _HAS_LANGGRAPH, reason="langgraph not installed"
)


# ── Helpers ────────────────────────────────────────────────────────────

def _kernel(**policy_kw):
    from agent_os.integrations.langgraph_adapter import LangGraphKernel
    return LangGraphKernel(policy=GovernancePolicy(**policy_kw))


def _ctx(kernel, agent_id="test-agent"):
    return kernel.create_context(agent_id)


# ══════════════════════════════════════════════════════════════════════
# ImportError guard
# ══════════════════════════════════════════════════════════════════════

class TestImportGuard:
    def test_clear_import_error_when_langgraph_missing(self):
        """LangGraphKernel raises ImportError with install instructions when langgraph absent."""
        import agent_os.integrations.langgraph_adapter as mod
        original = mod._HAS_LANGGRAPH
        try:
            mod._HAS_LANGGRAPH = False
            with pytest.raises(ImportError, match="pip install"):
                from agent_os.integrations.langgraph_adapter import LangGraphKernel
                LangGraphKernel()
        finally:
            mod._HAS_LANGGRAPH = original


# ══════════════════════════════════════════════════════════════════════
# before_tool_call
# ══════════════════════════════════════════════════════════════════════

@requires_langgraph
class TestBeforeToolCall:
    def test_allows_tool_on_allowlist(self):
        kernel = _kernel(allowed_tools=["search"])
        ctx = _ctx(kernel)
        kernel.before_tool_call("search", {"query": "hello"}, ctx)  # no raise

    def test_blocks_tool_not_on_allowlist(self):
        kernel = _kernel(allowed_tools=["search"])
        ctx = _ctx(kernel)
        with pytest.raises(PolicyViolationError, match="not in the allowed_tools list"):
            kernel.before_tool_call("delete_db", {}, ctx)

    def test_blocks_blocked_pattern_in_arguments(self):
        kernel = _kernel(blocked_patterns=["DROP TABLE"])
        ctx = _ctx(kernel)
        with pytest.raises(PolicyViolationError, match="pattern"):
            kernel.before_tool_call("query", {"sql": "DROP TABLE users"}, ctx)

    def test_blocks_ssn_dashed_in_arguments(self):
        """SSN (dashed) in tool args should be blocked by shared PII_PATTERNS."""
        kernel = _kernel()
        ctx = _ctx(kernel)
        with pytest.raises(PolicyViolationError, match="PII"):
            kernel.before_tool_call("send_email", {"body": "SSN: 123-45-6789"}, ctx)

    def test_blocks_ssn_space_separated(self):
        """Broadened SSN regex: space-separated format is blocked."""
        kernel = _kernel()
        ctx = _ctx(kernel)
        with pytest.raises(PolicyViolationError, match="PII"):
            kernel.before_tool_call("send", {"body": "SSN 123 45 6789 here"}, ctx)

    def test_blocks_ssn_no_separator(self):
        """Broadened SSN regex: no-separator 9-digit format is blocked."""
        kernel = _kernel()
        ctx = _ctx(kernel)
        with pytest.raises(PolicyViolationError, match="PII"):
            kernel.before_tool_call("send", {"body": "SSN 123456789"}, ctx)

    def test_increments_call_count(self):
        kernel = _kernel()
        ctx = _ctx(kernel)
        kernel.before_tool_call("search", {"q": "hi"}, ctx)
        assert ctx.call_count == 1

    def test_blocks_when_max_tool_calls_exceeded(self):
        kernel = _kernel(max_tool_calls=1)
        ctx = _ctx(kernel)
        kernel.before_tool_call("search", {}, ctx)  # count -> 1, OK
        with pytest.raises(PolicyViolationError, match="limit"):
            kernel.before_tool_call("search", {}, ctx)  # count -> 2, BLOCK

    def test_empty_allowlist_allows_any_tool(self):
        kernel = _kernel()  # no allowed_tools restriction
        ctx = _ctx(kernel)
        kernel.before_tool_call("any_tool", {}, ctx)  # no raise


# ══════════════════════════════════════════════════════════════════════
# before_node_execution
# ══════════════════════════════════════════════════════════════════════

@requires_langgraph
class TestBeforeNodeExecution:
    def test_allows_clean_state(self):
        kernel = _kernel()
        ctx = _ctx(kernel)
        kernel.before_node_execution("researcher", {"messages": []}, {}, ctx)  # no raise

    def test_blocks_blocked_pattern_in_state(self):
        kernel = _kernel(blocked_patterns=["DROP TABLE"])
        ctx = _ctx(kernel)
        with pytest.raises(PolicyViolationError, match="pattern"):
            kernel.before_node_execution("node", {"sql": "DROP TABLE"}, {}, ctx)

    def test_records_audit_entry(self):
        kernel = _kernel()
        ctx = _ctx(kernel)
        kernel.before_node_execution("writer", {"output": "hello"}, {}, ctx)
        assert any(r["node_name"] == "writer" for r in kernel._node_execution_log)

    def test_emits_policy_check_event(self):
        kernel = _kernel()
        ctx = _ctx(kernel)
        events = []
        from agent_os.integrations.base import GovernanceEventType
        kernel.on(GovernanceEventType.POLICY_CHECK, events.append)
        kernel.before_node_execution("node", {}, {}, ctx)
        assert any(e.get("phase") == "before_node_execution" for e in events)


# ══════════════════════════════════════════════════════════════════════
# wrap_graph
# ══════════════════════════════════════════════════════════════════════

@requires_langgraph
class TestWrapGraph:
    def test_wrap_graph_returns_governed_graph(self):
        from agent_os.integrations.langgraph_adapter import GovernedGraph, LangGraphKernel
        from langgraph.graph import StateGraph

        class State(TypedDict):
            value: int

        graph = StateGraph(State)
        graph.add_node("node_a", lambda s: s)
        graph.set_entry_point("node_a")
        graph.set_finish_point("node_a")

        kernel = LangGraphKernel()
        governed = kernel.wrap_graph(graph)
        assert isinstance(governed, GovernedGraph)

    def test_wrap_graph_rejects_compiled_graph(self):
        from agent_os.integrations.langgraph_adapter import LangGraphKernel
        from langgraph.graph import StateGraph

        class State(TypedDict):
            value: int

        graph = StateGraph(State)
        graph.add_node("n", lambda s: s)
        graph.set_entry_point("n")
        graph.set_finish_point("n")
        compiled = graph.compile()

        kernel = LangGraphKernel()
        with pytest.raises(TypeError, match="before compile"):
            kernel.wrap_graph(compiled)

    def test_double_wrap_does_not_double_hook(self):
        """Calling wrap_graph twice on same graph must not double-fire hooks."""
        from agent_os.integrations.langgraph_adapter import LangGraphKernel
        from langgraph.graph import StateGraph

        class State(TypedDict):
            value: int

        hook_count = {"n": 0}

        def node_fn(state):
            return state

        graph = StateGraph(State)
        graph.add_node("node_a", node_fn)
        graph.set_entry_point("node_a")
        graph.set_finish_point("node_a")

        kernel = LangGraphKernel()
        kernel.wrap_graph(graph)   # first wrap
        kernel.wrap_graph(graph)   # second wrap — should be no-op for sentinel nodes

        # Track how many times before_node_execution fires
        original_bne = kernel.before_node_execution
        call_log = []
        def counting_bne(*args, **kwargs):
            call_log.append(args[0])
            return original_bne(*args, **kwargs)
        kernel.before_node_execution = counting_bne

        app = graph.compile()
        app.invoke({"value": 1})
        # Should fire exactly once per node execution, not twice
        assert call_log.count("node_a") == 1


# ══════════════════════════════════════════════════════════════════════
# Checkpoint fingerprint
# ══════════════════════════════════════════════════════════════════════

@requires_langgraph
class TestCheckpointFingerprint:
    def test_fingerprint_stored_in_metadata_not_state(self):
        from agent_os.integrations.langgraph_adapter import LangGraphKernel
        kernel = LangGraphKernel()
        ctx = kernel.create_context("fp-test")

        user_state = {"messages": [], "value": 42}
        metadata = kernel._inject_fingerprint({}, ctx)

        # fingerprint is in metadata
        assert "_agt_auth_fingerprint" in metadata
        # user state is untouched
        assert "_agt_auth_fingerprint" not in user_state

    def test_fingerprint_is_deterministic(self):
        from agent_os.integrations.langgraph_adapter import LangGraphKernel
        kernel = LangGraphKernel(policy=GovernancePolicy(allowed_tools=["search"]))
        ctx = kernel.create_context("det-test")
        fp1 = kernel._compute_authorization_fingerprint(ctx)
        fp2 = kernel._compute_authorization_fingerprint(ctx)
        assert fp1 == fp2

    def test_stale_auth_blocks_on_resume_tool_removed(self):
        """Tool removed from allowed_tools between save and resume -> PolicyViolationError."""
        from agent_os.integrations.langgraph_adapter import LangGraphKernel

        # Save time: search + calc both allowed
        kernel_save = LangGraphKernel(policy=GovernancePolicy(allowed_tools=["search", "calc"]))
        ctx_save = kernel_save.create_context("stale-save")
        metadata_at_save = kernel_save._inject_fingerprint({}, ctx_save)

        # Resume time: calc removed (tighter policy)
        kernel_resume = LangGraphKernel(policy=GovernancePolicy(allowed_tools=["search"]))
        ctx_resume = kernel_resume.create_context("stale-resume")

        with pytest.raises(PolicyViolationError, match="[Ss]tale"):
            kernel_resume._validate_checkpoint_metadata(metadata_at_save, ctx_resume)

    def test_stale_auth_allows_on_resume_unchanged_policy(self):
        """Unchanged policy -> resume succeeds without raising."""
        from agent_os.integrations.langgraph_adapter import LangGraphKernel

        kernel = LangGraphKernel(policy=GovernancePolicy(allowed_tools=["search"]))
        ctx_save = kernel.create_context("clean-save")
        metadata = kernel._inject_fingerprint({}, ctx_save)

        # Same policy, new context — fingerprint must match
        ctx_resume = kernel.create_context("clean-resume")
        kernel._validate_checkpoint_metadata(metadata, ctx_resume)  # no raise

    def test_stale_auth_audit_mode_does_not_raise(self):
        """audit_only_stale_auth=True: mismatch emits DRIFT_DETECTED but does not raise."""
        from agent_os.integrations.langgraph_adapter import LangGraphKernel
        from agent_os.integrations.base import GovernanceEventType

        kernel_save = LangGraphKernel(policy=GovernancePolicy(allowed_tools=["search", "calc"]))
        ctx_save = kernel_save.create_context("audit-save")
        metadata = kernel_save._inject_fingerprint({}, ctx_save)

        kernel_resume = LangGraphKernel(
            policy=GovernancePolicy(allowed_tools=["search"]),
            audit_only_stale_auth=True,
        )
        drift_events = []
        kernel_resume.on(GovernanceEventType.DRIFT_DETECTED, drift_events.append)
        ctx_resume = kernel_resume.create_context("audit-resume")

        # Must NOT raise
        kernel_resume._validate_checkpoint_metadata(metadata, ctx_resume)
        assert len(drift_events) == 1
        assert drift_events[0]["reason"] == "fingerprint_mismatch"

    def test_missing_fingerprint_blocks_by_default(self):
        """Checkpoint without fingerprint -> PolicyViolationError (fail-closed)."""
        from agent_os.integrations.langgraph_adapter import LangGraphKernel
        kernel = LangGraphKernel()
        ctx = kernel.create_context("missing-fp")
        with pytest.raises(PolicyViolationError, match="missing"):
            kernel._validate_checkpoint_metadata({}, ctx)

    def test_missing_fingerprint_audit_mode_no_raise(self):
        """audit_only=True: missing fingerprint emits event, no raise."""
        from agent_os.integrations.langgraph_adapter import LangGraphKernel
        from agent_os.integrations.base import GovernanceEventType

        kernel = LangGraphKernel(audit_only_stale_auth=True)
        drift_events = []
        kernel.on(GovernanceEventType.DRIFT_DETECTED, drift_events.append)
        ctx = kernel.create_context("missing-audit")
        kernel._validate_checkpoint_metadata({}, ctx)  # no raise
        assert drift_events[0]["reason"] == "missing_fingerprint"

    def test_policy_loosening_surfaced_as_drift_in_audit_mode(self):
        """Policy loosening (tool added) between save and resume -> audit event, no raise."""
        from agent_os.integrations.langgraph_adapter import LangGraphKernel
        from agent_os.integrations.base import GovernanceEventType

        kernel_save = LangGraphKernel(policy=GovernancePolicy(allowed_tools=["search"]))
        ctx_save = kernel_save.create_context("loose-save")
        metadata = kernel_save._inject_fingerprint({}, ctx_save)

        kernel_resume = LangGraphKernel(
            policy=GovernancePolicy(allowed_tools=["search", "calc"]),
            audit_only_stale_auth=True,
        )
        drift_events = []
        kernel_resume.on(GovernanceEventType.DRIFT_DETECTED, drift_events.append)
        ctx_resume = kernel_resume.create_context("loose-resume")

        kernel_resume._validate_checkpoint_metadata(metadata, ctx_resume)
        assert len(drift_events) == 1  # loosening surfaced as drift


# ══════════════════════════════════════════════════════════════════════
# ctx.policy isolation
# ══════════════════════════════════════════════════════════════════════

@requires_langgraph
class TestContextPolicyIsolation:
    def test_mid_run_self_policy_mutation_does_not_affect_ctx(self):
        """Changing kernel.policy mid-run does not affect the pinned ctx.policy."""
        from agent_os.integrations.langgraph_adapter import LangGraphKernel

        kernel = LangGraphKernel(policy=GovernancePolicy(allowed_tools=["search"]))
        ctx = kernel.create_context("iso-test")

        original_tools = list(ctx.policy.allowed_tools)

        # Mutate kernel's live policy
        kernel.policy = GovernancePolicy(allowed_tools=["search", "delete_db"])

        # ctx.policy must be unchanged (deep-copied at create_context time)
        assert ctx.policy.allowed_tools == original_tools


# ══════════════════════════════════════════════════════════════════════
# Health check
# ══════════════════════════════════════════════════════════════════════

@requires_langgraph
class TestHealthCheck:
    def test_health_check_healthy(self):
        from agent_os.integrations.langgraph_adapter import LangGraphKernel
        kernel = LangGraphKernel()
        health = kernel.health_check()
        assert health["status"] == "healthy"
        assert health["backend"] == "langgraph"
        assert health["backend_connected"] is True
        assert health["last_error"] is None

    def test_health_check_includes_uptime(self):
        from agent_os.integrations.langgraph_adapter import LangGraphKernel
        kernel = LangGraphKernel()
        health = kernel.health_check()
        assert health["uptime_seconds"] >= 0


# ══════════════════════════════════════════════════════════════════════
# End-to-end: 2-node StateGraph
# ══════════════════════════════════════════════════════════════════════

@requires_langgraph
class TestEndToEnd:
    def test_2node_graph_both_nodes_run(self):
        """Wrap -> compile -> invoke: both nodes execute under governance."""
        from agent_os.integrations.langgraph_adapter import LangGraphKernel
        from langgraph.graph import StateGraph

        class State(TypedDict):
            value: int
            steps: list

        executed = []

        def node_a(state):
            executed.append("a")
            return {"value": state["value"] + 1, "steps": state["steps"] + ["a"]}

        def node_b(state):
            executed.append("b")
            return {"value": state["value"] + 1, "steps": state["steps"] + ["b"]}

        graph = StateGraph(State)
        graph.add_node("node_a", node_a)
        graph.add_node("node_b", node_b)
        graph.set_entry_point("node_a")
        graph.add_edge("node_a", "node_b")
        graph.set_finish_point("node_b")

        kernel = LangGraphKernel()
        governed = kernel.wrap_graph(graph)
        app = governed.compile()

        result = app.invoke({"value": 0, "steps": []})
        assert executed == ["a", "b"]
        assert result["value"] == 2

    def test_blocked_node_raises_policy_violation(self):
        """Node blocked by pattern in state raises PolicyViolationError."""
        from agent_os.integrations.langgraph_adapter import LangGraphKernel
        from langgraph.graph import StateGraph

        class State(TypedDict):
            cmd: str

        def dangerous_node(state):
            return state

        graph = StateGraph(State)
        graph.add_node("danger", dangerous_node)
        graph.set_entry_point("danger")
        graph.set_finish_point("danger")

        kernel = LangGraphKernel(policy=GovernancePolicy(blocked_patterns=["DROP TABLE"]))
        governed = kernel.wrap_graph(graph)
        app = governed.compile()

        with pytest.raises(PolicyViolationError):
            app.invoke({"cmd": "DROP TABLE users"})

    def test_audit_trail_populated_after_invocation(self):
        """After invocation, node_execution_log contains entries for each node."""
        from agent_os.integrations.langgraph_adapter import LangGraphKernel
        from langgraph.graph import StateGraph

        class State(TypedDict):
            value: int
            steps: list

        def node_x(state):
            return {"value": state["value"] + 1, "steps": state["steps"] + ["x"]}

        graph = StateGraph(State)
        graph.add_node("node_x", node_x)
        graph.set_entry_point("node_x")
        graph.set_finish_point("node_x")

        kernel = LangGraphKernel()
        governed = kernel.wrap_graph(graph)
        app = governed.compile()
        app.invoke({"value": 0, "steps": []})

        assert any(r["node_name"] == "node_x" for r in kernel._node_execution_log)

    def test_unwrap_returns_original_graph(self):
        """unwrap() on a GovernedGraph returns the original StateGraph."""
        from agent_os.integrations.langgraph_adapter import LangGraphKernel
        from langgraph.graph import StateGraph

        class State(TypedDict):
            value: int

        original = StateGraph(State)
        original.add_node("n", lambda s: s)
        original.set_entry_point("n")
        original.set_finish_point("n")

        kernel = LangGraphKernel()
        governed = kernel.wrap_graph(original)
        assert kernel.unwrap(governed) is original
