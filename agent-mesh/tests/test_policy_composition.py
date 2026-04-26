# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""Tests for policy composition with inheritance (extends)."""

import os
import pytest
import tempfile
from agentmesh.governance.policy import Policy, PolicyEngine


@pytest.fixture
def policy_dir(tmp_path):
    """Create a temp directory with test policy files."""

    # Org baseline — non-negotiable deny rules
    (tmp_path / "org-baseline.yaml").write_text("""
apiVersion: governance.toolkit/v1
name: org-baseline
description: Organization-wide baseline
default_action: deny
rules:
  - name: block-pii-export
    condition: "action.type == 'export' and data.contains_pii"
    action: deny
    priority: 100
  - name: audit-all
    condition: "true"
    action: log
    priority: 0
""")

    # Platform shared rules
    (tmp_path / "platform-shared.yaml").write_text("""
apiVersion: governance.toolkit/v1
name: platform-shared
extends: org-baseline.yaml
default_action: deny
rules:
  - name: rate-limit-api
    condition: "action.type == 'api_call'"
    action: warn
    limit: "100/hour"
    priority: 50
""")

    # App-level policy extending platform
    (tmp_path / "app-policy.yaml").write_text("""
apiVersion: governance.toolkit/v1
name: app-policy
extends:
  - platform-shared.yaml
default_action: deny
rules:
  - name: allow-read
    condition: "action.type == 'read'"
    action: allow
    priority: 10
""")

    # Policy that tries to weaken a parent deny
    (tmp_path / "bad-child.yaml").write_text("""
apiVersion: governance.toolkit/v1
name: bad-child
extends: org-baseline.yaml
default_action: deny
rules:
  - name: block-pii-export
    condition: "action.type == 'export'"
    action: allow
    priority: 200
""")

    # Circular reference A -> B -> A
    (tmp_path / "cycle-a.yaml").write_text("""
apiVersion: governance.toolkit/v1
name: cycle-a
extends: cycle-b.yaml
default_action: deny
rules: []
""")
    (tmp_path / "cycle-b.yaml").write_text("""
apiVersion: governance.toolkit/v1
name: cycle-b
extends: cycle-a.yaml
default_action: deny
rules: []
""")

    # Diamond: D extends B and C, both extend A
    (tmp_path / "diamond-a.yaml").write_text("""
apiVersion: governance.toolkit/v1
name: diamond-a
default_action: deny
rules:
  - name: shared-deny
    condition: "action.type == 'delete'"
    action: deny
    priority: 100
""")
    (tmp_path / "diamond-b.yaml").write_text("""
apiVersion: governance.toolkit/v1
name: diamond-b
extends: diamond-a.yaml
default_action: deny
rules:
  - name: b-rule
    condition: "action.type == 'b'"
    action: warn
""")
    (tmp_path / "diamond-c.yaml").write_text("""
apiVersion: governance.toolkit/v1
name: diamond-c
extends: diamond-a.yaml
default_action: deny
rules:
  - name: c-rule
    condition: "action.type == 'c'"
    action: warn
""")
    (tmp_path / "diamond-d.yaml").write_text("""
apiVersion: governance.toolkit/v1
name: diamond-d
extends:
  - diamond-b.yaml
  - diamond-c.yaml
default_action: deny
rules:
  - name: d-rule
    condition: "action.type == 'd'"
    action: allow
""")

    # Standalone (no extends)
    (tmp_path / "standalone.yaml").write_text("""
apiVersion: governance.toolkit/v1
name: standalone
default_action: deny
rules:
  - name: standalone-rule
    condition: "action.type == 'test'"
    action: allow
""")

    # Self-referencing
    (tmp_path / "self-ref.yaml").write_text("""
apiVersion: governance.toolkit/v1
name: self-ref
extends: self-ref.yaml
default_action: deny
rules: []
""")

    # Missing parent
    (tmp_path / "missing-parent.yaml").write_text("""
apiVersion: governance.toolkit/v1
name: missing-parent
extends: nonexistent.yaml
default_action: deny
rules: []
""")

    return tmp_path


class TestPolicyComposition:
    """Tests for extends-based policy composition."""

    def test_standalone_no_extends(self, policy_dir):
        """Policy without extends loads normally."""
        policy = Policy.from_yaml_file(str(policy_dir / "standalone.yaml"))
        assert policy.name == "standalone"
        assert len(policy.rules) == 1
        assert policy.rules[0].name == "standalone-rule"
        assert policy.extends == []

    def test_single_parent(self, policy_dir):
        """Policy extending one parent inherits its rules."""
        policy = Policy.from_yaml_file(str(policy_dir / "platform-shared.yaml"))
        assert policy.name == "platform-shared"
        rule_names = [r.name for r in policy.rules]
        # Should have parent rules + own rules
        assert "block-pii-export" in rule_names  # from org-baseline
        assert "audit-all" in rule_names  # from org-baseline
        assert "rate-limit-api" in rule_names  # own rule
        assert len(policy.rules) == 3

    def test_three_level_chain(self, policy_dir):
        """app-policy -> platform-shared -> org-baseline (3 levels)."""
        policy = Policy.from_yaml_file(str(policy_dir / "app-policy.yaml"))
        assert policy.name == "app-policy"
        rule_names = [r.name for r in policy.rules]
        assert "block-pii-export" in rule_names  # from org-baseline (grandparent)
        assert "audit-all" in rule_names  # from org-baseline
        assert "rate-limit-api" in rule_names  # from platform-shared (parent)
        assert "allow-read" in rule_names  # own rule
        assert len(policy.rules) == 4

    def test_parent_rules_come_first(self, policy_dir):
        """Parent rules are ordered before child rules."""
        policy = Policy.from_yaml_file(str(policy_dir / "platform-shared.yaml"))
        rule_names = [r.name for r in policy.rules]
        # Parent rules first, then own
        parent_idx = rule_names.index("block-pii-export")
        own_idx = rule_names.index("rate-limit-api")
        assert parent_idx < own_idx

    def test_child_cannot_weaken_parent_deny(self, policy_dir):
        """Child policy cannot override a parent deny with allow."""
        policy = Policy.from_yaml_file(str(policy_dir / "bad-child.yaml"))
        rule_names = [r.name for r in policy.rules]
        # The parent's deny should be present
        assert "block-pii-export" in rule_names
        # The child's allow override should be filtered out
        deny_rules = [r for r in policy.rules if r.name == "block-pii-export"]
        assert all(r.action == "deny" for r in deny_rules)

    def test_circular_reference_rejected(self, policy_dir):
        """Circular extends (A -> B -> A) raises ValueError."""
        with pytest.raises(ValueError, match="Circular"):
            Policy.from_yaml_file(str(policy_dir / "cycle-a.yaml"))

    def test_self_reference_rejected(self, policy_dir):
        """Self-referencing extends raises ValueError."""
        with pytest.raises(ValueError, match="Circular"):
            Policy.from_yaml_file(str(policy_dir / "self-ref.yaml"))

    def test_missing_parent_raises(self, policy_dir):
        """Referencing a nonexistent parent raises FileNotFoundError."""
        with pytest.raises(FileNotFoundError, match="nonexistent.yaml"):
            Policy.from_yaml_file(str(policy_dir / "missing-parent.yaml"))

    def test_diamond_inheritance_deduplication(self, policy_dir):
        """Diamond: D extends B and C, both extend A. A's rules appear once."""
        policy = Policy.from_yaml_file(str(policy_dir / "diamond-d.yaml"))
        rule_names = [r.name for r in policy.rules]
        # A's shared-deny should appear exactly once
        assert rule_names.count("shared-deny") == 1
        # All rules present
        assert "b-rule" in rule_names
        assert "c-rule" in rule_names
        assert "d-rule" in rule_names

    def test_extends_as_string(self, policy_dir):
        """extends can be a single string (not just a list)."""
        policy = Policy.from_yaml_file(str(policy_dir / "platform-shared.yaml"))
        assert len(policy.extends) == 1
        assert policy.extends[0] == "org-baseline.yaml"

    def test_extends_as_list(self, policy_dir):
        """extends can be a list of strings."""
        policy = Policy.from_yaml_file(str(policy_dir / "diamond-d.yaml"))
        assert len(policy.extends) == 2

    def test_from_yaml_without_extends(self):
        """from_yaml (string, no file) works without extends."""
        content = """
apiVersion: governance.toolkit/v1
name: inline-test
default_action: deny
rules:
  - name: test-rule
    condition: "true"
    action: allow
"""
        policy = Policy.from_yaml(content)
        assert policy.name == "inline-test"
        assert len(policy.rules) == 1
        assert policy.extends == []

    def test_engine_load_yaml_file(self, policy_dir):
        """PolicyEngine.load_yaml_file resolves extends."""
        engine = PolicyEngine()
        policy = engine.load_yaml_file(str(policy_dir / "app-policy.yaml"))
        assert policy.name == "app-policy"
        assert len(policy.rules) == 4

    def test_engine_evaluate_with_inherited_rules(self, policy_dir):
        """Evaluate against inherited rules works end-to-end."""
        engine = PolicyEngine()
        engine.load_yaml_file(str(policy_dir / "app-policy.yaml"))

        # This should match the inherited "block-pii-export" deny rule
        result = engine.evaluate("test-agent", {
            "action": {"type": "export"},
            "data": {"contains_pii": True},
        })
        assert not result.allowed
        assert result.action == "deny"

    def test_backward_compatible_load_yaml(self):
        """Existing load_yaml (string) still works unchanged."""
        engine = PolicyEngine()
        policy = engine.load_yaml("""
apiVersion: governance.toolkit/v1
name: compat-test
default_action: deny
rules:
  - name: compat-rule
    condition: "action.type == 'test'"
    action: allow
""")
        assert policy.name == "compat-test"
        assert len(policy.rules) == 1
