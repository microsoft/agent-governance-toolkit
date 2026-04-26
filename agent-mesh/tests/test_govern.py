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
