"""Tests for GovernancePolicyChecker component."""

import os
import tempfile

import pytest
import yaml

from haystack_agentmesh.governance import GovernancePolicyChecker


# ── Helpers ───────────────────────────────────────────────────────

def _write_policy(policy: dict) -> str:
    fd, path = tempfile.mkstemp(suffix=".yaml")
    with os.fdopen(fd, "w") as fh:
        yaml.dump(policy, fh)
    return path


BASIC_POLICY = {
    "allowed_tools": ["search", "summarize"],
    "blocked_tools": ["delete_all"],
    "blocked_patterns": [
        {"pattern": "DROP TABLE", "type": "substring"},
        {"pattern": r"rm\s+-rf", "type": "regex"},
    ],
    "max_tokens": 1000,
    "rate_limit": {"max_calls": 3, "window_seconds": 60},
}


# ── Tests ─────────────────────────────────────────────────────────

class TestGovernancePolicyChecker:

    def test_allow_valid_tool(self):
        checker = GovernancePolicyChecker(policy_dict=BASIC_POLICY)
        result = checker.run(action="search", params={"query": "hello"})
        assert result["decision"] == "allow"
        assert result["passed"] is True

    def test_deny_blocked_tool(self):
        checker = GovernancePolicyChecker(policy_dict=BASIC_POLICY)
        result = checker.run(action="delete_all")
        assert result["decision"] == "deny"
        assert result["passed"] is False
        assert "blocked" in result["reason"].lower()

    def test_deny_tool_not_in_allowlist(self):
        checker = GovernancePolicyChecker(policy_dict=BASIC_POLICY)
        result = checker.run(action="execute_code")
        assert result["decision"] == "deny"
        assert result["passed"] is False
        assert "not in allowed" in result["reason"].lower()

    def test_deny_blocked_pattern_substring(self):
        checker = GovernancePolicyChecker(policy_dict=BASIC_POLICY)
        result = checker.run(action="search", params={"query": "DROP TABLE users"})
        assert result["decision"] == "deny"
        assert "DROP TABLE" in result["reason"]

    def test_deny_blocked_pattern_regex(self):
        checker = GovernancePolicyChecker(policy_dict=BASIC_POLICY)
        result = checker.run(action="search", params={"cmd": "rm -rf /"})
        assert result["decision"] == "deny"
        assert result["passed"] is False

    def test_deny_token_limit_exceeded(self):
        checker = GovernancePolicyChecker(policy_dict=BASIC_POLICY)
        result = checker.run(action="summarize", params={"tokens": 5000})
        assert result["decision"] == "deny"
        assert "Token limit" in result["reason"]

    def test_allow_within_token_limit(self):
        checker = GovernancePolicyChecker(policy_dict=BASIC_POLICY)
        result = checker.run(action="summarize", params={"tokens": 500})
        assert result["decision"] == "allow"

    def test_rate_limit_triggers_audit(self):
        checker = GovernancePolicyChecker(policy_dict=BASIC_POLICY)
        for _ in range(3):
            checker.run(action="search", params={}, agent_id="agent-1")
        result = checker.run(action="search", params={}, agent_id="agent-1")
        assert result["decision"] == "audit"
        assert result["passed"] is False

    def test_load_from_yaml_file(self):
        path = _write_policy(BASIC_POLICY)
        try:
            checker = GovernancePolicyChecker(policy_path=path)
            result = checker.run(action="search", params={"q": "test"})
            assert result["decision"] == "allow"
        finally:
            os.unlink(path)

    def test_empty_policy_allows_everything(self):
        checker = GovernancePolicyChecker(policy_dict={})
        result = checker.run(action="anything", params={"x": 1})
        assert result["decision"] == "allow"
        assert result["passed"] is True

    def test_glob_pattern_block(self):
        policy = {
            "allowed_tools": ["search"],
            "blocked_patterns": [
                {"pattern": "*.exe", "type": "glob"},
            ],
        }
        checker = GovernancePolicyChecker(policy_dict=policy)
        result = checker.run(action="search", params={"file": "malware.exe"})
        assert result["decision"] == "deny"
