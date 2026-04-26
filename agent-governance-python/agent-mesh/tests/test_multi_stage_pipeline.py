# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""Tests for multi-stage policy pipeline."""

import pytest
from agentmesh.governance.policy import Policy, PolicyEngine, PolicyRule


MULTI_STAGE_POLICY = """
apiVersion: governance.toolkit/v1
name: multi-stage
agents: ["*"]
default_action: allow
rules:
  - name: block-injection-input
    stage: pre_input
    condition: "input.contains_injection"
    action: deny
    description: "Prompt injection detected in input"
    priority: 100

  - name: block-export
    stage: pre_tool
    condition: "action.type == 'export'"
    action: deny
    description: "Export not allowed"
    priority: 50

  - name: block-pii-in-output
    stage: post_tool
    condition: "tool.output.contains_pii"
    action: deny
    description: "PII detected in tool output"
    priority: 80

  - name: sanitize-response
    stage: pre_output
    condition: "response.contains_secrets"
    action: deny
    description: "Secrets in agent response"
    priority: 90

  - name: allow-read
    stage: pre_tool
    condition: "action.type == 'read'"
    action: allow
    priority: 10

  - name: log-all-tools
    stage: pre_tool
    condition: "true"
    action: log
    priority: 0
"""


class TestMultiStagePipeline:
    """Tests for stage-aware policy evaluation."""

    def test_rule_default_stage_is_pre_tool(self):
        """Rules without explicit stage default to pre_tool."""
        policy = Policy.from_yaml("""
apiVersion: governance.toolkit/v1
name: default-stage
default_action: allow
rules:
  - name: some-rule
    condition: "true"
    action: allow
""")
        assert policy.rules[0].stage == "pre_tool"

    def test_rule_explicit_stage(self):
        """Rules with explicit stage are parsed correctly."""
        policy = Policy.from_yaml(MULTI_STAGE_POLICY)
        stages = {r.name: r.stage for r in policy.rules}
        assert stages["block-injection-input"] == "pre_input"
        assert stages["block-export"] == "pre_tool"
        assert stages["block-pii-in-output"] == "post_tool"
        assert stages["sanitize-response"] == "pre_output"
        assert stages["allow-read"] == "pre_tool"
        assert stages["log-all-tools"] == "pre_tool"

    def test_evaluate_pre_input_stage(self):
        """Only pre_input rules fire at pre_input stage."""
        engine = PolicyEngine(conflict_strategy="deny_overrides")
        engine.load_yaml(MULTI_STAGE_POLICY)

        # Injection detected — should be denied at pre_input
        result = engine.evaluate("*", {
            "input": {"contains_injection": True},
        }, stage="pre_input")
        assert not result.allowed
        assert result.matched_rule == "block-injection-input"

    def test_evaluate_pre_input_no_match(self):
        """Clean input passes pre_input stage."""
        engine = PolicyEngine(conflict_strategy="deny_overrides")
        engine.load_yaml(MULTI_STAGE_POLICY)

        result = engine.evaluate("*", {
            "input": {"contains_injection": False},
        }, stage="pre_input")
        assert result.allowed

    def test_evaluate_pre_tool_stage(self):
        """Only pre_tool rules fire at pre_tool stage."""
        engine = PolicyEngine(conflict_strategy="deny_overrides")
        engine.load_yaml(MULTI_STAGE_POLICY)

        # Export should be denied
        result = engine.evaluate("*", {
            "action": {"type": "export"},
        }, stage="pre_tool")
        assert not result.allowed
        assert result.matched_rule == "block-export"

    def test_evaluate_pre_tool_allows_read(self):
        """Read action is allowed at pre_tool."""
        engine = PolicyEngine(conflict_strategy="priority_first_match")
        engine.load_yaml(MULTI_STAGE_POLICY)

        result = engine.evaluate("*", {
            "action": {"type": "read"},
        }, stage="pre_tool")
        assert result.allowed

    def test_evaluate_post_tool_stage(self):
        """Only post_tool rules fire at post_tool stage."""
        engine = PolicyEngine(conflict_strategy="deny_overrides")
        engine.load_yaml(MULTI_STAGE_POLICY)

        # PII in tool output — denied
        result = engine.evaluate("*", {
            "tool": {"output": {"contains_pii": True}},
        }, stage="post_tool")
        assert not result.allowed
        assert result.matched_rule == "block-pii-in-output"

    def test_evaluate_post_tool_clean(self):
        """Clean tool output passes post_tool."""
        engine = PolicyEngine(conflict_strategy="deny_overrides")
        engine.load_yaml(MULTI_STAGE_POLICY)

        result = engine.evaluate("*", {
            "tool": {"output": {"contains_pii": False}},
        }, stage="post_tool")
        assert result.allowed

    def test_evaluate_pre_output_stage(self):
        """Only pre_output rules fire at pre_output stage."""
        engine = PolicyEngine(conflict_strategy="deny_overrides")
        engine.load_yaml(MULTI_STAGE_POLICY)

        result = engine.evaluate("*", {
            "response": {"contains_secrets": True},
        }, stage="pre_output")
        assert not result.allowed
        assert result.matched_rule == "sanitize-response"

    def test_stages_are_isolated(self):
        """Rules from one stage don't fire at another stage."""
        engine = PolicyEngine(conflict_strategy="deny_overrides")
        engine.load_yaml(MULTI_STAGE_POLICY)

        # block-export is pre_tool — should NOT fire at post_tool
        result = engine.evaluate("*", {
            "action": {"type": "export"},
        }, stage="post_tool")
        assert result.allowed  # no post_tool rules match this context

    def test_default_stage_is_pre_tool(self):
        """evaluate() without stage arg defaults to pre_tool."""
        engine = PolicyEngine(conflict_strategy="deny_overrides")
        engine.load_yaml(MULTI_STAGE_POLICY)

        # This should only evaluate pre_tool rules
        result = engine.evaluate("*", {
            "action": {"type": "export"},
        })
        assert not result.allowed
        assert result.matched_rule == "block-export"

    def test_backward_compat_no_stage_in_yaml(self):
        """Policies without stage field work as before (all rules = pre_tool)."""
        engine = PolicyEngine(conflict_strategy="deny_overrides")
        engine.load_yaml("""
apiVersion: governance.toolkit/v1
name: legacy-no-stage
agents: ["*"]
default_action: allow
rules:
  - name: block-delete
    condition: "action.type == 'delete'"
    action: deny
""")
        result = engine.evaluate("*", {"action": {"type": "delete"}})
        assert not result.allowed

    def test_multiple_stages_single_policy(self):
        """A single policy can have rules across all 4 stages."""
        policy = Policy.from_yaml(MULTI_STAGE_POLICY)
        stages = set(r.stage for r in policy.rules)
        assert stages == {"pre_input", "pre_tool", "post_tool", "pre_output"}

    def test_stage_with_composition(self, tmp_path):
        """Stage-aware rules work with policy extends."""
        (tmp_path / "parent.yaml").write_text("""
apiVersion: governance.toolkit/v1
name: parent
default_action: allow
rules:
  - name: parent-pre-input
    stage: pre_input
    condition: "input.blocked"
    action: deny
""")
        (tmp_path / "child.yaml").write_text("""
apiVersion: governance.toolkit/v1
name: child
extends: parent.yaml
agents: ["*"]
default_action: allow
rules:
  - name: child-post-tool
    stage: post_tool
    condition: "tool.output.sensitive"
    action: deny
""")
        engine = PolicyEngine(conflict_strategy="deny_overrides")
        policy = engine.load_yaml_file(str(tmp_path / "child.yaml"))

        # Parent pre_input rule
        result = engine.evaluate("*", {"input": {"blocked": True}}, stage="pre_input")
        assert not result.allowed
        assert result.matched_rule == "parent-pre-input"

        # Child post_tool rule
        result = engine.evaluate("*", {"tool": {"output": {"sensitive": True}}}, stage="post_tool")
        assert not result.allowed
        assert result.matched_rule == "child-post-tool"
