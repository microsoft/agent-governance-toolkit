# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""Tests for the govern() high-level wrapper."""

import os
import pytest
from agentmesh.governance.govern import (
    govern,
    GovernedCallable,
    GovernanceConfig,
    GovernanceDenied,
)
from agentmesh.governance.policy import Policy


# ── Test fixtures ──────────────────────────────────────────────────

ALLOW_ALL_POLICY = """
apiVersion: governance.toolkit/v1
name: allow-all
default_action: allow
rules: []
"""

DENY_EXPORT_POLICY = """
apiVersion: governance.toolkit/v1
name: deny-export
default_action: allow
rules:
  - name: block-export
    condition: "action.type == 'export'"
    action: deny
    description: "Exporting data is not allowed"
"""

MIXED_POLICY = """
apiVersion: governance.toolkit/v1
name: mixed-rules
default_action: deny
rules:
  - name: allow-read
    condition: "action.type == 'read'"
    action: allow
    priority: 10
  - name: block-pii
    condition: "data.contains_pii"
    action: deny
    priority: 100
    description: "PII data cannot be processed"
  - name: warn-large
    condition: "data.size_mb > 100"
    action: warn
    priority: 50
"""


def dummy_tool(action: str = "read", **kwargs):
    """A simple tool function for testing."""
    return {"action": action, "status": "executed", **kwargs}


def add(a: int, b: int) -> int:
    """Simple function to test wrapping."""
    return a + b


# ── Core govern() tests ───────────────────────────────────────────

class TestGovern:
    """Tests for the govern() wrapper function."""

    def test_govern_allows_action(self):
        """Governed function executes when policy allows."""
        safe = govern(dummy_tool, policy=ALLOW_ALL_POLICY)
        result = safe(action="read")
        assert result["status"] == "executed"
        assert result["action"] == "read"

    def test_govern_denies_action(self):
        """Governed function raises GovernanceDenied when policy denies."""
        safe = govern(dummy_tool, policy=DENY_EXPORT_POLICY)
        with pytest.raises(GovernanceDenied) as exc_info:
            safe(action="export")
        assert "block-export" in str(exc_info.value)
        assert exc_info.value.decision.action == "deny"

    def test_govern_allows_non_matching_action(self):
        """Non-matching actions pass through when default is allow."""
        safe = govern(dummy_tool, policy=DENY_EXPORT_POLICY)
        result = safe(action="read")
        assert result["status"] == "executed"

    def test_govern_with_on_deny_callback(self):
        """Custom on_deny callback is called instead of raising."""
        denied_actions = []

        def on_deny(decision):
            denied_actions.append(decision)
            return {"status": "denied", "rule": decision.matched_rule}

        safe = govern(
            dummy_tool,
            policy=DENY_EXPORT_POLICY,
            on_deny=on_deny,
        )
        result = safe(action="export")
        assert result["status"] == "denied"
        assert result["rule"] == "block-export"
        assert len(denied_actions) == 1

    def test_govern_audit_logging(self):
        """Audit log captures allow and deny decisions."""
        safe = govern(dummy_tool, policy=DENY_EXPORT_POLICY, on_deny=lambda d: None)

        # Allowed action
        safe(action="read")
        # Denied action (with on_deny callback so no exception)
        safe(action="export")

        log = safe.audit_log
        assert log is not None
        entries = log.query()
        assert len(entries) >= 2

    def test_govern_no_audit(self):
        """Audit can be disabled."""
        safe = govern(dummy_tool, policy=ALLOW_ALL_POLICY, audit=False)
        safe(action="read")
        assert safe.audit_log is None

    def test_govern_with_policy_file(self, tmp_path):
        """govern() accepts a file path for policy."""
        policy_file = tmp_path / "test-policy.yaml"
        policy_file.write_text(DENY_EXPORT_POLICY)

        safe = govern(dummy_tool, policy=str(policy_file))
        result = safe(action="read")
        assert result["status"] == "executed"

        with pytest.raises(GovernanceDenied):
            safe(action="export")

    def test_govern_with_policy_file_extends(self, tmp_path):
        """govern() resolves extends when loading from file."""
        (tmp_path / "base.yaml").write_text("""
apiVersion: governance.toolkit/v1
name: base
default_action: allow
rules:
  - name: base-deny-delete
    condition: "action.type == 'delete'"
    action: deny
""")
        (tmp_path / "child.yaml").write_text("""
apiVersion: governance.toolkit/v1
name: child
extends: base.yaml
default_action: allow
rules:
  - name: child-allow-read
    condition: "action.type == 'read'"
    action: allow
""")
        safe = govern(dummy_tool, policy=str(tmp_path / "child.yaml"))
        # Inherited deny
        with pytest.raises(GovernanceDenied):
            safe(action="delete")
        # Own allow
        result = safe(action="read")
        assert result["status"] == "executed"

    def test_govern_with_policy_object(self):
        """govern() accepts a pre-built Policy object."""
        policy = Policy.from_yaml(DENY_EXPORT_POLICY)
        safe = govern(dummy_tool, policy=policy)
        with pytest.raises(GovernanceDenied):
            safe(action="export")

    def test_govern_preserves_function_name(self):
        """Wrapped function preserves __name__ and __doc__."""
        safe = govern(dummy_tool, policy=ALLOW_ALL_POLICY)
        assert safe.__wrapped__.__name__ == "dummy_tool"

    def test_govern_passes_through_kwargs(self):
        """Extra kwargs are passed to the wrapped function."""
        safe = govern(dummy_tool, policy=ALLOW_ALL_POLICY)
        result = safe(action="read", resource="users", limit=10)
        assert result["resource"] == "users"
        assert result["limit"] == 10

    def test_govern_wraps_non_tool_function(self):
        """govern() works with any callable, not just 'tool' functions."""
        safe_add = govern(add, policy=ALLOW_ALL_POLICY)
        assert safe_add(a=3, b=4) == 7

    def test_govern_engine_accessible(self):
        """The underlying PolicyEngine is accessible for advanced use."""
        safe = govern(dummy_tool, policy=DENY_EXPORT_POLICY)
        assert safe.engine is not None
        assert len(safe.engine._policies) == 1

    def test_govern_invalid_policy_type(self):
        """Passing an invalid policy type raises TypeError."""
        with pytest.raises(TypeError, match="policy must be"):
            govern(dummy_tool, policy=12345)

    def test_govern_context_from_dict_action(self):
        """Action as dict is passed through to context."""
        safe = govern(dummy_tool, policy=DENY_EXPORT_POLICY)
        with pytest.raises(GovernanceDenied):
            safe(action={"type": "export", "target": "s3"})

    def test_govern_multiple_calls(self):
        """Governed function can be called multiple times."""
        safe = govern(dummy_tool, policy=ALLOW_ALL_POLICY)
        for i in range(10):
            result = safe(action="read", iteration=i)
            assert result["iteration"] == i


# ── Ring enforcement tests ─────────────────────────────────────────

class TestRingEnforcement:
    """Tests for ring-level resource constraint enforcement in govern()."""

    def test_ring3_denies_subprocess_action(self):
        """Ring 3 agent cannot invoke a subprocess-type action."""
        from hypervisor.models import ExecutionRing
        safe = govern(dummy_tool, policy=ALLOW_ALL_POLICY, ring=ExecutionRing.RING_3_SANDBOX)
        with pytest.raises(GovernanceDenied) as exc_info:
            safe(action="subprocess_exec")
        assert exc_info.value.decision.matched_rule == "ring_enforcement"
        assert "subprocess" in exc_info.value.decision.reason

    def test_ring3_denies_network_action(self):
        """Ring 3 agent cannot invoke a network-type action."""
        from hypervisor.models import ExecutionRing
        safe = govern(dummy_tool, policy=ALLOW_ALL_POLICY, ring=ExecutionRing.RING_3_SANDBOX)
        with pytest.raises(GovernanceDenied) as exc_info:
            safe(action="http_request")
        assert exc_info.value.decision.matched_rule == "ring_enforcement"
        assert "network" in exc_info.value.decision.reason

    def test_ring3_allows_tool_execution(self):
        """Ring 3 agent can invoke generic tool-execution actions."""
        from hypervisor.models import ExecutionRing
        safe = govern(dummy_tool, policy=ALLOW_ALL_POLICY, ring=ExecutionRing.RING_3_SANDBOX)
        result = safe(action="read")
        assert result["status"] == "executed"

    def test_ring2_allows_subprocess_action(self):
        """Ring 2 agent is permitted to invoke subprocess-type actions."""
        from hypervisor.models import ExecutionRing
        safe = govern(dummy_tool, policy=ALLOW_ALL_POLICY, ring=ExecutionRing.RING_2_STANDARD)
        result = safe(action="subprocess_exec")
        assert result["status"] == "executed"

    def test_ring2_allows_network_action(self):
        """Ring 2 agent is permitted to invoke network-type actions."""
        from hypervisor.models import ExecutionRing
        safe = govern(dummy_tool, policy=ALLOW_ALL_POLICY, ring=ExecutionRing.RING_2_STANDARD)
        result = safe(action="http_request")
        assert result["status"] == "executed"

    def test_no_ring_no_enforcement(self):
        """When ring is not set, subprocess actions pass through unchanged."""
        safe = govern(dummy_tool, policy=ALLOW_ALL_POLICY)
        result = safe(action="subprocess_exec")
        assert result["status"] == "executed"

    def test_ring_context_injected_for_policy_rules(self):
        """ring.* fields are injected into evaluation context when ring is set."""
        from hypervisor.models import ExecutionRing

        RING_AWARE_POLICY = """
apiVersion: governance.toolkit/v1
name: ring-aware
default_action: deny
rules:
  - name: allow-read-only-ring
    condition: "action.type == 'read'"
    action: allow
"""
        safe = govern(dummy_tool, policy=RING_AWARE_POLICY, ring=ExecutionRing.RING_3_SANDBOX)
        # Policy allows reads; ring 3 allows tool_execution — should pass
        result = safe(action="read")
        assert result["status"] == "executed"

    def test_ring3_on_deny_callback_called(self):
        """on_deny callback receives the ring denial decision."""
        from hypervisor.models import ExecutionRing
        denied = []
        safe = govern(
            dummy_tool,
            policy=ALLOW_ALL_POLICY,
            ring=ExecutionRing.RING_3_SANDBOX,
            on_deny=lambda d: denied.append(d) or {"status": "denied"},
        )
        result = safe(action="subprocess_exec")
        assert result["status"] == "denied"
        assert len(denied) == 1
        assert denied[0].matched_rule == "ring_enforcement"

    def test_ring_denial_does_not_reach_policy_engine(self):
        """A ring-denied action never reaches policy evaluation."""
        from hypervisor.models import ExecutionRing

        # Policy would allow everything — ring should deny first
        safe = govern(dummy_tool, policy=ALLOW_ALL_POLICY, ring=ExecutionRing.RING_3_SANDBOX)
        with pytest.raises(GovernanceDenied) as exc_info:
            safe(action="subprocess_exec")
        # matched_rule comes from ring layer, not from any policy rule
        assert exc_info.value.decision.matched_rule == "ring_enforcement"

    def test_circuit_breaker_trips_after_repeated_violations(self):
        """Repeated ring violations trip the circuit breaker."""
        from hypervisor.rings.breach_detector import RingBreachDetector
        from hypervisor.models import ExecutionRing

        # Use a detector with a very low baseline so the breaker trips quickly
        detector = RingBreachDetector(baseline_rate=0.01)
        # Simulate rapid calls from ring 3 attempting ring 1 access
        for _ in range(50):
            detector.record_call("agent-x", "sess-1", ExecutionRing.RING_3_SANDBOX, ExecutionRing.RING_1_PRIVILEGED)
        assert detector.is_breaker_tripped("agent-x", "sess-1")

    # ── Hardening: shared breach detector across an agent's callables ──

    def test_breach_detector_shared_across_callables_same_agent_session(self):
        """Two GovernedCallable instances for the same (agent_id, session_id)
        MUST share one RingBreachDetector. Otherwise a rogue agent with N
        tools can spend the full per-detector violation budget N times."""
        from hypervisor.models import ExecutionRing
        from agentmesh.governance.govern import (
            GovernanceConfig, GovernedCallable, _reset_shared_breach_detectors,
        )

        _reset_shared_breach_detectors()
        cfg_a = GovernanceConfig(
            policy=ALLOW_ALL_POLICY, agent_id="agent-1", audit=False,
            ring=ExecutionRing.RING_3_SANDBOX, session_id="sess-A",
        )
        cfg_b = GovernanceConfig(
            policy=ALLOW_ALL_POLICY, agent_id="agent-1", audit=False,
            ring=ExecutionRing.RING_3_SANDBOX, session_id="sess-A",
        )
        gc_a = GovernedCallable(dummy_tool, cfg_a)
        gc_b = GovernedCallable(dummy_tool, cfg_b)
        assert gc_a._breach_detector is gc_b._breach_detector

    def test_breach_detector_isolated_across_sessions(self):
        """Different session_ids on the same agent get distinct detectors."""
        from hypervisor.models import ExecutionRing
        from agentmesh.governance.govern import (
            GovernanceConfig, GovernedCallable, _reset_shared_breach_detectors,
        )

        _reset_shared_breach_detectors()
        cfg_a = GovernanceConfig(
            policy=ALLOW_ALL_POLICY, agent_id="agent-1", audit=False,
            ring=ExecutionRing.RING_3_SANDBOX, session_id="sess-A",
        )
        cfg_b = GovernanceConfig(
            policy=ALLOW_ALL_POLICY, agent_id="agent-1", audit=False,
            ring=ExecutionRing.RING_3_SANDBOX, session_id="sess-B",
        )
        gc_a = GovernedCallable(dummy_tool, cfg_a)
        gc_b = GovernedCallable(dummy_tool, cfg_b)
        assert gc_a._breach_detector is not gc_b._breach_detector

    # ── Hardening: exact-token resource inference (no substring matches) ──

    def test_resource_inference_no_false_positive_httponly(self):
        """'set_httponly_flag' must NOT be inferred as a network action."""
        from agentmesh.governance.govern import _infer_resource_type
        from agentmesh.governance import ResourceType
        assert _infer_resource_type("set_httponly_flag") == ResourceType.TOOL_EXECUTION

    def test_resource_inference_no_false_positive_overwrite(self):
        """'overwrite_protection_check' must NOT be inferred as filesystem."""
        from agentmesh.governance.govern import _infer_resource_type
        from agentmesh.governance import ResourceType
        assert _infer_resource_type("overwrite_protection_check") == ResourceType.TOOL_EXECUTION

    def test_resource_inference_true_positives(self):
        """Real subprocess/network/filesystem actions still classify correctly."""
        from agentmesh.governance.govern import _infer_resource_type
        from agentmesh.governance import ResourceType
        assert _infer_resource_type("http_get") == ResourceType.NETWORK
        assert _infer_resource_type("exec.command") == ResourceType.SUBPROCESS
        assert _infer_resource_type("shell-run") == ResourceType.SUBPROCESS
        assert _infer_resource_type("write_file") == ResourceType.FILESYSTEM
        assert _infer_resource_type("read_only_query") == ResourceType.TOOL_EXECUTION

