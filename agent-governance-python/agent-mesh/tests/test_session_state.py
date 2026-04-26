# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""Tests for session state with monotonic attribute ratchets."""

import pytest
from agentmesh.governance.session_state import SessionState, SessionAttribute


class TestSessionAttribute:
    def test_default_initial_is_first_ordering(self):
        attr = SessionAttribute(name="sens", ordering=["low", "med", "high"])
        assert attr.initial == "low"

    def test_explicit_initial(self):
        attr = SessionAttribute(name="sens", ordering=["low", "med", "high"], initial="med")
        assert attr.initial == "med"

    def test_no_ordering_no_initial(self):
        attr = SessionAttribute(name="tag")
        assert attr.initial is None


class TestSessionState:
    def test_set_and_get(self):
        state = SessionState([
            SessionAttribute(name="level", ordering=["a", "b", "c"]),
        ])
        assert state.get("level") == "a"
        state.set("level", "b")
        assert state.get("level") == "b"

    def test_monotonic_ratchet_up(self):
        state = SessionState([
            SessionAttribute(
                name="data_sensitivity",
                ordering=["public", "internal", "confidential", "restricted"],
                monotonic=True,
            ),
        ])
        assert state.get("data_sensitivity") == "public"

        assert state.set("data_sensitivity", "confidential") is True
        assert state.get("data_sensitivity") == "confidential"

    def test_monotonic_rejects_ratchet_down(self):
        state = SessionState([
            SessionAttribute(
                name="data_sensitivity",
                ordering=["public", "internal", "confidential", "restricted"],
                monotonic=True,
            ),
        ])
        state.set("data_sensitivity", "confidential")

        # Try to go back — should be rejected
        assert state.set("data_sensitivity", "public") is False
        assert state.get("data_sensitivity") == "confidential"

    def test_monotonic_rejects_same_value(self):
        state = SessionState([
            SessionAttribute(
                name="level",
                ordering=["low", "med", "high"],
                monotonic=True,
            ),
        ])
        state.set("level", "med")
        # Same value = not moving forward
        assert state.set("level", "med") is False
        assert state.get("level") == "med"

    def test_monotonic_rejects_unknown_value(self):
        state = SessionState([
            SessionAttribute(
                name="level",
                ordering=["low", "med", "high"],
                monotonic=True,
            ),
        ])
        assert state.set("level", "unknown") is False
        assert state.get("level") == "low"

    def test_non_monotonic_allows_any_direction(self):
        state = SessionState([
            SessionAttribute(
                name="mode",
                ordering=["read", "write", "admin"],
                monotonic=False,
            ),
        ])
        state.set("mode", "admin")
        assert state.get("mode") == "admin"

        # Can go back when not monotonic
        assert state.set("mode", "read") is True
        assert state.get("mode") == "read"

    def test_multiple_attributes(self):
        state = SessionState([
            SessionAttribute(
                name="data_sensitivity",
                ordering=["public", "internal", "confidential"],
                monotonic=True,
            ),
            SessionAttribute(
                name="access_level",
                ordering=["viewer", "editor", "admin"],
                monotonic=False,
            ),
        ])
        state.set("data_sensitivity", "confidential")
        state.set("access_level", "admin")

        assert state.get("data_sensitivity") == "confidential"
        assert state.get("access_level") == "admin"

        # Sensitivity can't go down, access can
        assert state.set("data_sensitivity", "public") is False
        assert state.set("access_level", "viewer") is True

    def test_get_all(self):
        state = SessionState([
            SessionAttribute(name="a", ordering=["x", "y"], initial="x"),
            SessionAttribute(name="b", ordering=["1", "2"], initial="1"),
        ])
        assert state.get_all() == {"a": "x", "b": "1"}

    def test_get_unknown_returns_none(self):
        state = SessionState()
        assert state.get("nonexistent") is None

    def test_inject_context(self):
        state = SessionState([
            SessionAttribute(
                name="data_sensitivity",
                ordering=["public", "confidential"],
                initial="public",
            ),
        ])
        state.set("data_sensitivity", "confidential")

        context = {"action": {"type": "export"}}
        state.inject_context(context)

        assert context["session"]["data_sensitivity"] == "confidential"

    def test_reset(self):
        state = SessionState([
            SessionAttribute(
                name="level",
                ordering=["low", "high"],
                monotonic=True,
                initial="low",
            ),
        ])
        state.set("level", "high")
        assert state.get("level") == "high"

        state.reset()
        assert state.get("level") == "low"

    def test_define_after_init(self):
        state = SessionState()
        state.define(SessionAttribute(
            name="risk",
            ordering=["low", "med", "high"],
            monotonic=True,
        ))
        assert state.get("risk") == "low"
        state.set("risk", "high")
        assert state.set("risk", "low") is False

    def test_ratchet_full_ordering(self):
        """Walk through the full ordering sequence."""
        state = SessionState([
            SessionAttribute(
                name="s",
                ordering=["public", "internal", "confidential", "restricted"],
                monotonic=True,
            ),
        ])
        assert state.set("s", "internal") is True
        assert state.set("s", "confidential") is True
        assert state.set("s", "restricted") is True
        # Can't go back at any point
        assert state.set("s", "confidential") is False
        assert state.set("s", "public") is False
        assert state.get("s") == "restricted"


class TestFromPolicyYaml:
    def test_parse_session_attributes(self):
        state = SessionState.from_policy_yaml("""
session_attributes:
  - name: data_sensitivity
    ordering: [public, internal, confidential, restricted]
    monotonic: true
    initial: public
  - name: region
    ordering: [us, eu, apac]
    monotonic: false
""")
        assert state.get("data_sensitivity") == "public"
        state.set("data_sensitivity", "restricted")
        assert state.set("data_sensitivity", "public") is False

        state.set("region", "eu")
        assert state.set("region", "us") is True  # non-monotonic

    def test_empty_yaml(self):
        state = SessionState.from_policy_yaml("")
        assert state.get_all() == {}

    def test_no_session_attributes_key(self):
        state = SessionState.from_policy_yaml("""
apiVersion: governance.toolkit/v1
name: no-session
rules: []
""")
        assert state.get_all() == {}


class TestIntegrationWithPolicyContext:
    def test_ratchet_blocks_export_after_sensitive_read(self):
        """End-to-end: read confidential doc → export blocked by policy."""
        from agentmesh.governance.policy import PolicyEngine

        engine = PolicyEngine(conflict_strategy="deny_overrides")
        engine.load_yaml("""
apiVersion: governance.toolkit/v1
name: dlp-policy
agents: ["*"]
default_action: allow
rules:
  - name: block-export-sensitive
    stage: pre_tool
    condition: "session.data_sensitivity in ['confidential', 'restricted']"
    action: deny
    description: "Cannot export after touching sensitive data"
    priority: 100
    """)

        state = SessionState([
            SessionAttribute(
                name="data_sensitivity",
                ordering=["public", "internal", "confidential", "restricted"],
                monotonic=True,
            ),
        ])

        # Before reading sensitive data — export is allowed
        ctx1 = {"action": {"type": "export"}}
        state.inject_context(ctx1)
        result1 = engine.evaluate("*", ctx1)
        assert result1.allowed

        # Simulate reading a confidential document
        state.set("data_sensitivity", "confidential")

        # After reading sensitive data — export is blocked
        ctx2 = {"action": {"type": "export"}}
        state.inject_context(ctx2)
        result2 = engine.evaluate("*", ctx2)
        assert not result2.allowed
        assert result2.matched_rule == "block-export-sensitive"

        # Try to reset sensitivity (monotonic — rejected)
        assert state.set("data_sensitivity", "public") is False

        # Export still blocked
        ctx3 = {"action": {"type": "export"}}
        state.inject_context(ctx3)
        result3 = engine.evaluate("*", ctx3)
        assert not result3.allowed
