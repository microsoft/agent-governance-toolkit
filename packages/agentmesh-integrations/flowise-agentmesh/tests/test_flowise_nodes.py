"""Comprehensive tests for Flowise AgentMesh governance nodes."""

import json
import os
import tempfile

import pytest

from flowise_agentmesh.policy import Policy, load_policy
from flowise_agentmesh.governance_node import GovernanceNode, GovernanceResult
from flowise_agentmesh.trust_gate_node import TrustGateNode, TrustResult
from flowise_agentmesh.audit_node import AuditNode, AuditEntry
from flowise_agentmesh.rate_limiter_node import RateLimiterNode


# ── Policy tests ─────────────────────────────────────────────────────

class TestPolicy:
    def test_default_deny(self):
        policy = Policy()
        assert not policy.is_tool_allowed("anything")

    def test_default_allow(self):
        policy = Policy(default_action="allow")
        assert policy.is_tool_allowed("anything")

    def test_allowlist(self):
        policy = Policy(allowed_tools=["read_file", "list_dir"])
        assert policy.is_tool_allowed("read_file")
        assert not policy.is_tool_allowed("delete_file")

    def test_blocklist_overrides_allowlist(self):
        policy = Policy(allowed_tools=["*"], blocked_tools=["rm_*"])
        assert policy.is_tool_allowed("read_file")
        assert not policy.is_tool_allowed("rm_rf")

    def test_wildcard_allowlist(self):
        policy = Policy(allowed_tools=["read_*"])
        assert policy.is_tool_allowed("read_file")
        assert not policy.is_tool_allowed("write_file")

    def test_content_pattern_block(self):
        policy = Policy(blocked_content_patterns=[r"DROP\s+TABLE", r"rm\s+-rf"])
        allowed, reason = policy.check_content("please DROP TABLE users")
        assert not allowed
        assert "DROP" in reason

    def test_content_pattern_pass(self):
        policy = Policy(blocked_content_patterns=[r"DROP\s+TABLE"])
        allowed, reason = policy.check_content("SELECT * FROM users")
        assert allowed
        assert reason is None

    def test_argument_scanning_block(self):
        policy = Policy(blocked_argument_patterns=[r"/etc/passwd", r"\.\./"])
        allowed, reason = policy.check_arguments({"path": "/etc/passwd"})
        assert not allowed

    def test_argument_scanning_pass(self):
        policy = Policy(blocked_argument_patterns=[r"/etc/passwd"])
        allowed, reason = policy.check_arguments({"path": "/home/user/file.txt"})
        assert allowed


class TestLoadPolicy:
    def test_load_from_dict(self):
        policy = load_policy({"allowed_tools": ["search"], "default_action": "deny"})
        assert policy.is_tool_allowed("search")
        assert not policy.is_tool_allowed("delete")

    def test_load_from_yaml_string(self):
        yaml_str = "allowed_tools:\n  - search\ndefault_action: deny\n"
        policy = load_policy(yaml_str)
        assert policy.is_tool_allowed("search")

    def test_load_from_yaml_file(self):
        yaml_content = "allowed_tools:\n  - read_file\nblocked_tools:\n  - rm_*\n"
        with tempfile.NamedTemporaryFile(mode="w", suffix=".yaml", delete=False, encoding="utf-8") as f:
            f.write(yaml_content)
            f.flush()
            path = f.name
        try:
            policy = load_policy(path)
            assert policy.is_tool_allowed("read_file")
            assert not policy.is_tool_allowed("rm_rf")
        finally:
            os.unlink(path)

    def test_load_empty_dict(self):
        policy = load_policy({})
        assert policy.default_action == "deny"


# ── GovernanceNode tests ─────────────────────────────────────────────

class TestGovernanceNode:
    def test_allowed_tool(self):
        node = GovernanceNode(policy={"allowed_tools": ["search"]})
        result = node.evaluate(tool_name="search")
        assert result.allowed

    def test_blocked_tool(self):
        node = GovernanceNode(policy={"allowed_tools": ["search"]})
        result = node.evaluate(tool_name="delete")
        assert not result.allowed
        assert "not allowed" in result.reason

    def test_blocked_content(self):
        node = GovernanceNode(policy={"blocked_content_patterns": [r"password"], "default_action": "allow"})
        result = node.evaluate(content="my password is 1234")
        assert not result.allowed

    def test_blocked_argument(self):
        node = GovernanceNode(policy={
            "blocked_argument_patterns": [r"\.\."],
            "default_action": "allow",
        })
        result = node.evaluate(arguments={"path": "../../etc/passwd"})
        assert not result.allowed

    def test_strict_mode_no_input(self):
        node = GovernanceNode(strict_mode=True)
        result = node.evaluate()
        assert not result.allowed
        assert "Strict mode" in result.reason

    def test_non_strict_mode_no_input(self):
        node = GovernanceNode(strict_mode=False)
        result = node.evaluate()
        assert result.allowed

    def test_run_method_pass(self):
        node = GovernanceNode(policy={"allowed_tools": ["search"]})
        out = node.run({"tool": "search", "content": "hello"})
        assert out["allowed"]
        assert out["output"] is not None

    def test_run_method_block(self):
        node = GovernanceNode(policy={"allowed_tools": ["search"]})
        out = node.run({"tool": "delete"})
        assert not out["allowed"]
        assert out["output"] is None


# ── TrustGateNode tests ──────────────────────────────────────────────

class TestTrustGateNode:
    def test_trusted_tier(self):
        gate = TrustGateNode(min_trust_score=0.7, review_threshold=0.4)
        result = gate.evaluate("agent-1", 0.9)
        assert result.tier == "trusted"

    def test_review_tier(self):
        gate = TrustGateNode(min_trust_score=0.7, review_threshold=0.4)
        result = gate.evaluate("agent-2", 0.5)
        assert result.tier == "review"

    def test_blocked_tier(self):
        gate = TrustGateNode(min_trust_score=0.7, review_threshold=0.4)
        result = gate.evaluate("agent-3", 0.2)
        assert result.tier == "blocked"

    def test_boundary_trusted(self):
        gate = TrustGateNode(min_trust_score=0.7, review_threshold=0.4)
        result = gate.evaluate("agent-4", 0.7)
        assert result.tier == "trusted"

    def test_boundary_review(self):
        gate = TrustGateNode(min_trust_score=0.7, review_threshold=0.4)
        result = gate.evaluate("agent-5", 0.4)
        assert result.tier == "review"

    def test_score_clamping_high(self):
        gate = TrustGateNode()
        result = gate.evaluate("agent-6", 1.5)
        assert result.trust_score == 1.0

    def test_score_clamping_low(self):
        gate = TrustGateNode()
        result = gate.evaluate("agent-7", -0.5)
        assert result.trust_score == 0.0

    def test_invalid_thresholds(self):
        with pytest.raises(ValueError):
            TrustGateNode(min_trust_score=0.3, review_threshold=0.8)

    def test_run_method(self):
        gate = TrustGateNode()
        out = gate.run({"agent_id": "a1", "trust_score": 0.9})
        assert out["tier"] == "trusted"
        assert out["output"] is not None

    def test_run_blocked_output_none(self):
        gate = TrustGateNode(min_trust_score=0.9, review_threshold=0.8)
        out = gate.run({"agent_id": "a1", "trust_score": 0.1})
        assert out["tier"] == "blocked"
        assert out["output"] is None


# ── AuditNode tests ──────────────────────────────────────────────────

class TestAuditNode:
    def test_single_entry(self):
        node = AuditNode()
        entry = node.log({"action": "search", "query": "hello"})
        assert entry.index == 0
        assert entry.previous_hash == "0" * 64
        assert len(entry.hash) == 64

    def test_chain_integrity(self):
        node = AuditNode()
        node.log({"action": "a"}, timestamp=1.0)
        node.log({"action": "b"}, timestamp=2.0)
        node.log({"action": "c"}, timestamp=3.0)
        assert node.verify_chain()

    def test_chain_links(self):
        node = AuditNode()
        e1 = node.log({"x": 1}, timestamp=1.0)
        e2 = node.log({"x": 2}, timestamp=2.0)
        assert e2.previous_hash == e1.hash

    def test_tamper_detection(self):
        node = AuditNode()
        node.log({"action": "a"}, timestamp=1.0)
        node.log({"action": "b"}, timestamp=2.0)
        # Tamper with data
        node._chain[0].data["action"] = "TAMPERED"
        assert not node.verify_chain()

    def test_export_json(self):
        node = AuditNode(export_format="json")
        node.log({"action": "a"}, timestamp=1.0)
        exported = node.export()
        parsed = json.loads(exported)
        assert len(parsed) == 1
        assert parsed[0]["data"]["action"] == "a"

    def test_export_jsonl(self):
        node = AuditNode(export_format="jsonl")
        node.log({"action": "a"}, timestamp=1.0)
        node.log({"action": "b"}, timestamp=2.0)
        lines = node.export().strip().split("\n")
        assert len(lines) == 2

    def test_file_storage(self):
        with tempfile.NamedTemporaryFile(mode="w", suffix=".jsonl", delete=False) as f:
            path = f.name
        try:
            node = AuditNode(storage="file", file_path=path, export_format="jsonl")
            node.log({"action": "a"}, timestamp=1.0)
            node.log({"action": "b"}, timestamp=2.0)
            with open(path, encoding="utf-8") as f:
                lines = f.readlines()
            assert len(lines) == 2
        finally:
            os.unlink(path)

    def test_len(self):
        node = AuditNode()
        assert len(node) == 0
        node.log({"x": 1})
        assert len(node) == 1

    def test_run_method(self):
        node = AuditNode()
        out = node.run({"action": "test"})
        assert out["audit_index"] == 0
        assert out["chain_valid"]
        assert out["output"]["action"] == "test"

    def test_invalid_storage(self):
        with pytest.raises(ValueError):
            AuditNode(storage="redis")

    def test_invalid_export_format(self):
        with pytest.raises(ValueError):
            AuditNode(export_format="csv")

    def test_file_storage_requires_path(self):
        with pytest.raises(ValueError):
            AuditNode(storage="file")

    def test_empty_chain_verifies(self):
        node = AuditNode()
        assert node.verify_chain()

    def test_chain_property_returns_copy(self):
        node = AuditNode()
        node.log({"x": 1})
        chain = node.chain
        chain.clear()
        assert len(node) == 1


# ── RateLimiterNode tests ────────────────────────────────────────────

class TestRateLimiterNode:
    def test_allows_within_limit(self):
        limiter = RateLimiterNode(max_requests=5, window_seconds=60)
        for _ in range(5):
            result = limiter.check(agent_id="a1", now=100.0)
            assert result.allowed

    def test_blocks_over_limit(self):
        limiter = RateLimiterNode(max_requests=2, window_seconds=60)
        limiter.check(agent_id="a1", now=100.0)
        limiter.check(agent_id="a1", now=100.0)
        result = limiter.check(agent_id="a1", now=100.0)
        assert not result.allowed
        assert result.retry_after > 0

    def test_refills_over_time(self):
        limiter = RateLimiterNode(max_requests=1, window_seconds=10)
        limiter.check(agent_id="a1", now=100.0)
        result = limiter.check(agent_id="a1", now=100.0)
        assert not result.allowed
        # After full window, should refill
        result = limiter.check(agent_id="a1", now=111.0)
        assert result.allowed

    def test_per_agent_isolation(self):
        limiter = RateLimiterNode(max_requests=1, window_seconds=60)
        limiter.check(agent_id="a1", now=100.0)
        result = limiter.check(agent_id="a2", now=100.0)
        assert result.allowed

    def test_per_action_isolation(self):
        limiter = RateLimiterNode(max_requests=1, window_seconds=60)
        limiter.check(agent_id="a1", action="search", now=100.0)
        result = limiter.check(agent_id="a1", action="read", now=100.0)
        assert result.allowed

    def test_reset_specific(self):
        limiter = RateLimiterNode(max_requests=1, window_seconds=60)
        limiter.check(agent_id="a1", now=100.0)
        limiter.reset(agent_id="a1")
        result = limiter.check(agent_id="a1", now=100.0)
        assert result.allowed

    def test_reset_all(self):
        limiter = RateLimiterNode(max_requests=1, window_seconds=60)
        limiter.check(agent_id="a1", now=100.0)
        limiter.check(agent_id="a2", now=100.0)
        limiter.reset()
        assert limiter.check(agent_id="a1", now=100.0).allowed
        assert limiter.check(agent_id="a2", now=100.0).allowed

    def test_invalid_max_requests(self):
        with pytest.raises(ValueError):
            RateLimiterNode(max_requests=0)

    def test_invalid_window(self):
        with pytest.raises(ValueError):
            RateLimiterNode(window_seconds=-1)

    def test_run_method(self):
        limiter = RateLimiterNode(max_requests=5, window_seconds=60)
        out = limiter.run({"agent_id": "a1", "action": "search"})
        assert out["allowed"]
        assert out["output"] is not None

    def test_run_method_blocked(self):
        limiter = RateLimiterNode(max_requests=1, window_seconds=60)
        limiter.run({"agent_id": "a1"})
        out = limiter.run({"agent_id": "a1"})
        assert not out["allowed"]
        assert out["output"] is None
