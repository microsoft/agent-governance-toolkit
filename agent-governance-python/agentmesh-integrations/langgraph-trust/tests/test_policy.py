# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""Tests for langgraph_trust.policy — PolicyCheckpoint and GraphTrustRules."""

from langgraph_trust.policy import GraphTrustRules, PolicyCheckpoint


class TestGovernancePolicy:
    def test_from_dict(self):
        data = {
            "name": "strict",
            "max_tokens": 1000,
            "blocked_tools": ["shell_exec"],
            "blocked_patterns": ["password"],
        }
        policy = GraphTrustRules.from_dict(data)
        assert policy.name == "strict"
        assert policy.max_tokens == 1000
        assert policy.blocked_tools == ["shell_exec"]
        assert policy.blocked_patterns == ["password"]

    def test_to_dict_roundtrip(self):
        policy = GraphTrustRules(name="test", max_tool_calls=5)
        d = policy.to_dict()
        p2 = GraphTrustRules.from_dict(d)
        assert p2.name == policy.name
        assert p2.max_tool_calls == policy.max_tool_calls

    def test_defaults(self):
        policy = GraphTrustRules()
        assert policy.name == "default"
        assert policy.max_tokens is None
        assert policy.require_human_approval is False


class TestPolicyCheckpoint:
    def test_pass_no_violations(self):
        policy = GraphTrustRules(name="permissive")
        cp = PolicyCheckpoint(policy=policy)
        result = cp({})
        assert result["trust_result"]["verdict"] == "pass"
        assert "satisfied" in result["trust_result"]["reason"]

    def test_token_limit_exceeded(self):
        policy = GraphTrustRules(max_tokens=100)
        cp = PolicyCheckpoint(policy=policy)
        result = cp({"total_tokens": 200})
        assert result["trust_result"]["verdict"] == "fail"
        assert any("Token limit" in v for v in result["trust_result"]["policy_violations"])

    def test_token_limit_ok(self):
        policy = GraphTrustRules(max_tokens=500)
        cp = PolicyCheckpoint(policy=policy)
        result = cp({"total_tokens": 100})
        assert result["trust_result"]["verdict"] == "pass"

    def test_tool_call_limit(self):
        policy = GraphTrustRules(max_tool_calls=2)
        cp = PolicyCheckpoint(policy=policy)
        result = cp({"tool_calls": ["a", "b", "c"]})
        assert result["trust_result"]["verdict"] == "fail"

    def test_blocked_tool(self):
        policy = GraphTrustRules(blocked_tools=["shell_exec", "file_delete"])
        cp = PolicyCheckpoint(policy=policy)
        result = cp({"tool_calls": [{"name": "shell_exec"}]})
        assert result["trust_result"]["verdict"] == "fail"
        assert any("shell_exec" in v for v in result["trust_result"]["policy_violations"])

    def test_allowed_tool_ok(self):
        policy = GraphTrustRules(allowed_tools=["search", "summarize"])
        cp = PolicyCheckpoint(policy=policy)
        result = cp({"tool_calls": [{"name": "search"}]})
        assert result["trust_result"]["verdict"] == "pass"

    def test_unauthorized_tool(self):
        policy = GraphTrustRules(allowed_tools=["search", "summarize"])
        cp = PolicyCheckpoint(policy=policy)
        result = cp({"tool_calls": [{"name": "hack"}]})
        assert result["trust_result"]["verdict"] == "fail"
        assert any("hack" in v for v in result["trust_result"]["policy_violations"])

    def test_blocked_pattern_in_messages(self):
        policy = GraphTrustRules(blocked_patterns=["password", "secret"])
        cp = PolicyCheckpoint(policy=policy)
        result = cp({"messages": ["Here is the password: abc123"]})
        assert result["trust_result"]["verdict"] == "fail"

    def test_blocked_pattern_case_insensitive(self):
        policy = GraphTrustRules(blocked_patterns=["SECRET"])
        cp = PolicyCheckpoint(policy=policy)
        result = cp({"messages": ["this is a secret"]})
        assert result["trust_result"]["verdict"] == "fail"

    def test_blocked_pattern_no_match(self):
        policy = GraphTrustRules(blocked_patterns=["password"])
        cp = PolicyCheckpoint(policy=policy)
        result = cp({"messages": ["Just a normal message"]})
        assert result["trust_result"]["verdict"] == "pass"

    def test_human_approval_required(self):
        policy = GraphTrustRules(require_human_approval=True)
        cp = PolicyCheckpoint(policy=policy)
        result = cp({})
        assert result["trust_result"]["verdict"] == "fail"
        assert any("Human approval" in v for v in result["trust_result"]["policy_violations"])

    def test_human_approval_granted(self):
        policy = GraphTrustRules(require_human_approval=True)
        cp = PolicyCheckpoint(policy=policy)
        result = cp({"human_approved": True})
        assert result["trust_result"]["verdict"] == "pass"

    def test_multiple_violations(self):
        policy = GraphTrustRules(
            max_tokens=50,
            blocked_tools=["shell_exec"],
            blocked_patterns=["password"],
        )
        cp = PolicyCheckpoint(policy=policy)
        result = cp({
            "total_tokens": 100,
            "tool_calls": [{"name": "shell_exec"}],
            "messages": ["my password is abc"],
        })
        assert result["trust_result"]["verdict"] == "fail"
        assert len(result["trust_result"]["policy_violations"]) == 3

    def test_content_extraction_dict_messages(self):
        policy = GraphTrustRules(blocked_patterns=["danger"])
        cp = PolicyCheckpoint(policy=policy)
        result = cp({"messages": [{"content": "this is danger"}]})
        assert result["trust_result"]["verdict"] == "fail"

    def test_content_extraction_string(self):
        policy = GraphTrustRules(blocked_patterns=["leak"])
        cp = PolicyCheckpoint(policy=policy)
        result = cp({"messages": "data leak detected"})
        assert result["trust_result"]["verdict"] == "fail"

    def test_custom_keys(self):
        policy = GraphTrustRules(max_tokens=100)
        cp = PolicyCheckpoint(policy=policy, tokens_key="my_tokens")
        result = cp({"my_tokens": 200})
        assert result["trust_result"]["verdict"] == "fail"
