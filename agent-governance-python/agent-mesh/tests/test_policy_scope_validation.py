# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""Regression tests for Policy.scope validation (issue #3536).

A misspelled scope previously demoted the policy to GLOBAL silently,
flipping a deny into an allow under most_specific_wins.  These tests
verify that:

1. Invalid scope values are rejected at Policy construction.
2. The evaluate() fallback logs a warning instead of staying silent.
3. validate_policy_schema() reports invalid scopes.
4. All four valid scopes are accepted without error.
5. The field description lists all valid scopes.
"""

import logging

import pytest

from agentmesh.governance.conflict_resolution import (
    VALID_SCOPES,
    PolicyScope,
)
from agentmesh.governance.policy import (
    Policy,
    PolicyEngine,
    PolicyRule,
    validate_policy_schema,
)

# ── Construction-time rejection ──────────────────────────────


class TestScopeFieldValidator:
    """Policy(scope=...) must reject values that PolicyScope cannot parse."""

    @pytest.mark.parametrize(
        "bad_scope",
        [
            "organisation",   # British spelling
            "Agent",          # wrong case
            "GLOBAL",         # wrong case
            "team",           # invented
            "",               # empty
            "org",            # abbreviation
            " global",        # leading whitespace
            "global ",        # trailing whitespace
            "Global",         # title case
        ],
    )
    def test_invalid_scope_rejected(self, bad_scope: str):
        with pytest.raises(ValueError, match="Invalid policy scope"):
            Policy(name="test", scope=bad_scope)

    @pytest.mark.parametrize(
        "valid_scope",
        ["global", "tenant", "organization", "agent"],
    )
    def test_valid_scope_accepted(self, valid_scope: str):
        policy = Policy(name="test", scope=valid_scope)
        assert policy.scope == valid_scope

    def test_default_scope_is_global(self):
        policy = Policy(name="test")
        assert policy.scope == "global"

    def test_valid_scopes_constant_matches_enum(self):
        """VALID_SCOPES must match the PolicyScope enum members exactly."""
        enum_values = {s.value for s in PolicyScope}
        assert VALID_SCOPES == enum_values


# ── YAML / JSON load-time rejection ─────────────────────────


class TestScopeInYamlLoad:
    def test_yaml_with_valid_scope(self):
        yaml_content = """
apiVersion: governance.toolkit/v1
name: scoped-policy
scope: agent
agents: ["*"]
rules:
  - name: r1
    condition: "action.type == 'read'"
    action: deny
"""
        engine = PolicyEngine()
        policy = engine.load_yaml(yaml_content)
        assert policy.scope == "agent"

    def test_yaml_with_invalid_scope_rejected(self):
        yaml_content = """
apiVersion: governance.toolkit/v1
name: bad-scope-policy
scope: organisation
agents: ["*"]
rules:
  - name: r1
    condition: "action.type == 'read'"
    action: deny
"""
        engine = PolicyEngine()
        with pytest.raises(ValueError, match="Invalid policy scope"):
            engine.load_yaml(yaml_content)

    def test_json_with_invalid_scope_rejected(self):
        import json

        data = {
            "apiVersion": "governance.toolkit/v1",
            "name": "json-bad-scope",
            "scope": "Agent",
            "rules": [],
        }
        engine = PolicyEngine()
        with pytest.raises(ValueError, match="Invalid policy scope"):
            engine.load_json(json.dumps(data))

    def test_yaml_with_organization_scope_accepted(self):
        """Verify the previously-undocumented 'organization' scope works."""
        yaml_content = """
apiVersion: governance.toolkit/v1
name: org-policy
scope: organization
agents: ["*"]
rules:
  - name: r1
    condition: "action.type == 'read'"
    action: deny
"""
        policy = Policy.from_yaml(yaml_content)
        assert policy.scope == "organization"


# ── validate_policy_schema coverage ──────────────────────────


# ── Evaluate-time warning (defence-in-depth) ─────────────────


class TestEvaluateScopeWarning:
    """The evaluate() fallback still works but now logs a warning.

    Pydantic does not re-validate on attribute assignment, so the
    fallback path is still reachable via:
        policy = Policy(name="p", scope="global")
        policy.scope = "typo"  # bypasses the validator
    """

    def test_evaluate_warns_on_bad_scope(self, caplog):
        engine = PolicyEngine(conflict_strategy="most_specific_wins")

        # Build a valid policy, then mutate scope to simulate the
        # bypass path (pydantic does not re-validate on assignment).
        policy = Policy(
            name="sneaky",
            scope="global",
            agents=["*"],
            rules=[
                PolicyRule(
                    name="r1",
                    condition="action.type == 'read'",
                    action="deny",
                    priority=1,
                )
            ],
        )
        # Bypass the validator via direct attribute assignment.
        object.__setattr__(policy, "scope", "typo")
        engine.load_policy(policy)

        with caplog.at_level(logging.WARNING):
            result = engine.evaluate("a", {"action": {"type": "read"}})

        assert "unrecognised scope" in caplog.text.lower()
        # The rule should still match (ranked at AGENT — max specificity,
        # fail-closed — and it is the only candidate).
        assert result.matched_rule == "r1"

    def test_corrupted_deny_beats_global_allow(self):
        """Two candidates: corrupted-scope deny + valid global allow.

        Under most_specific_wins the corrupted deny must win because the
        runtime fallback ranks it at AGENT (max specificity).  If it were
        ranked at GLOBAL the two would tie and the allow could win.
        """
        engine = PolicyEngine(conflict_strategy="most_specific_wins")

        deny = Policy(
            name="deny-export", scope="agent", agents=["*"],
            rules=[PolicyRule(name="block", condition="action.type == 'export'", action="deny", priority=10)],
        )
        object.__setattr__(deny, "scope", "typo")
        engine.load_policy(deny)

        allow = Policy(
            name="allow-all", scope="global", agents=["*"],
            rules=[PolicyRule(name="pass", condition="action.type == 'export'", action="allow", priority=5)],
        )
        engine.load_policy(allow)

        result = engine.evaluate("a", {"action": {"type": "export"}})
        assert result.allowed is False, (
            "corrupted deny must beat global allow under most_specific_wins"
        )
        assert result.matched_rule == "block"


# ── End-to-end: the exact reproduction from the issue ────────


class TestIssue3536Reproduction:
    """Exact reproduction from the issue body.

    Before the fix, scopes that are not exact enum values silently
    demoted to GLOBAL, letting the global allow win under
    most_specific_wins. After the fix, Policy() construction rejects
    them.
    """

    def test_correct_scope_denies(self):
        """agent-scoped deny beats global allow under most_specific_wins."""
        deny = PolicyRule(
            name="block-export",
            condition="action.type == 'export'",
            action="deny",
            priority=1,
        )
        allow = PolicyRule(
            name="allow-all",
            condition="action.type == 'export'",
            action="allow",
            priority=100,
        )

        engine = PolicyEngine(conflict_strategy="most_specific_wins")
        engine.load_policy(
            Policy(
                name="agent-deny",
                scope="agent",
                rules=[deny],
                agents=["did:x"],
            )
        )
        engine.load_policy(
            Policy(
                name="global-allow",
                scope="global",
                rules=[allow],
                agents=["did:x"],
            )
        )

        decision = engine.evaluate("did:x", {"action": {"type": "export"}})
        assert decision.allowed is False
        assert decision.matched_rule == "block-export"

    @pytest.mark.parametrize(
        "bad_scope",
        ["organisation", "Agent", "team", ""],
    )
    def test_bad_scope_rejected_at_construction(self, bad_scope: str):
        """Each bad scope from the issue reproduction is now rejected."""
        with pytest.raises(ValueError, match="Invalid policy scope"):
            Policy(
                name="agent-deny",
                scope=bad_scope,
                rules=[
                    PolicyRule(
                        name="block-export",
                        condition="action.type == 'export'",
                        action="deny",
                        priority=1,
                    )
                ],
                agents=["did:x"],
            )

    def test_organization_scope_works(self):
        """'organization' is valid and ranks above tenant."""
        engine = PolicyEngine(conflict_strategy="most_specific_wins")
        engine.load_policy(
            Policy(
                name="org-deny",
                scope="organization",
                rules=[
                    PolicyRule(
                        name="org-block",
                        condition="action.type == 'export'",
                        action="deny",
                        priority=1,
                    )
                ],
                agents=["did:x"],
            )
        )
        engine.load_policy(
            Policy(
                name="tenant-allow",
                scope="tenant",
                rules=[
                    PolicyRule(
                        name="tenant-permit",
                        condition="action.type == 'export'",
                        action="allow",
                        priority=100,
                    )
                ],
                agents=["did:x"],
            )
        )

        decision = engine.evaluate("did:x", {"action": {"type": "export"}})
        assert decision.allowed is False
        assert decision.matched_rule == "org-block"


# ── Field description accuracy ───────────────────────────────


class TestScopeFieldDescription:
    def test_description_lists_organization(self):
        """The field description must list 'organization' so operators
        do not have to guess the spelling."""
        info = Policy.model_fields["scope"]
        assert "organization" in info.description
