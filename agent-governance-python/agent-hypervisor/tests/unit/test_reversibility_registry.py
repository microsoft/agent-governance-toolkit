# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""Tests for ReversibilityRegistry."""

from hypervisor.models import ActionDescriptor, ReversibilityLevel
from hypervisor.reversibility.registry import ReversibilityEntry, ReversibilityRegistry


class TestReversibilityRegistry:
    def setup_method(self):
        self.registry = ReversibilityRegistry("session:test-rev")

    def _make_action(self, action_id="act1", reversibility=ReversibilityLevel.FULL, **kw):
        return ActionDescriptor(
            action_id=action_id,
            name=kw.get("name", action_id),
            execute_api=kw.get("execute_api", f"/{action_id}"),
            undo_api=kw.get("undo_api", f"/{action_id}/undo"),
            reversibility=reversibility,
            undo_window_seconds=kw.get("undo_window_seconds", 300),
            compensation_method=kw.get("compensation_method", None),
        )

    # --- register ---

    def test_register_returns_entry(self):
        action = self._make_action("search", ReversibilityLevel.FULL)
        entry = self.registry.register(action)
        assert isinstance(entry, ReversibilityEntry)
        assert entry.action_id == "search"
        assert entry.execute_api == "/search"
        assert entry.undo_api == "/search/undo"
        assert entry.reversibility == ReversibilityLevel.FULL
        assert entry.undo_api_healthy is True

    def test_register_overwrites_existing(self):
        a1 = self._make_action("x", ReversibilityLevel.FULL, undo_api="/v1")
        a2 = self._make_action("x", ReversibilityLevel.PARTIAL, undo_api="/v2")
        self.registry.register(a1)
        self.registry.register(a2)
        assert len(self.registry.entries) == 1
        assert self.registry.get("x").undo_api == "/v2"

    # --- register_from_manifest ---

    def test_register_from_manifest(self):
        actions = [self._make_action(f"a{i}") for i in range(5)]
        count = self.registry.register_from_manifest(actions)
        assert count == 5
        assert len(self.registry.entries) == 5

    def test_register_from_manifest_empty(self):
        count = self.registry.register_from_manifest([])
        assert count == 0
        assert len(self.registry.entries) == 0

    # --- get ---

    def test_get_returns_entry(self):
        self.registry.register(self._make_action("lookup"))
        entry = self.registry.get("lookup")
        assert entry is not None
        assert entry.action_id == "lookup"

    def test_get_returns_none_for_missing(self):
        assert self.registry.get("nonexistent") is None

    # --- get_undo_api ---

    def test_get_undo_api(self):
        action = self._make_action("deploy", undo_api="/deploy/rollback")
        self.registry.register(action)
        assert self.registry.get_undo_api("deploy") == "/deploy/rollback"

    def test_get_undo_api_none_when_no_undo(self):
        action = self._make_action("log", ReversibilityLevel.NONE, undo_api=None)
        self.registry.register(action)
        assert self.registry.get_undo_api("log") is None

    def test_get_undo_api_none_for_missing(self):
        assert self.registry.get_undo_api("missing") is None

    # --- is_reversible ---

    def test_is_reversible_full(self):
        self.registry.register(self._make_action("a", ReversibilityLevel.FULL))
        assert self.registry.is_reversible("a") is True

    def test_is_reversible_partial(self):
        self.registry.register(self._make_action("b", ReversibilityLevel.PARTIAL))
        assert self.registry.is_reversible("b") is True

    def test_is_reversible_none(self):
        self.registry.register(self._make_action("c", ReversibilityLevel.NONE))
        assert self.registry.is_reversible("c") is False

    def test_is_reversible_missing(self):
        assert self.registry.is_reversible("nope") is False

    # --- get_risk_weight ---

    def test_get_risk_weight_full(self):
        self.registry.register(self._make_action("a", ReversibilityLevel.FULL))
        weight = self.registry.get_risk_weight("a")
        assert weight == ReversibilityLevel.FULL.default_risk_weight

    def test_get_risk_weight_none_level(self):
        self.registry.register(self._make_action("b", ReversibilityLevel.NONE))
        weight = self.registry.get_risk_weight("b")
        assert weight == ReversibilityLevel.NONE.default_risk_weight

    def test_get_risk_weight_missing_returns_none_default(self):
        weight = self.registry.get_risk_weight("missing")
        assert weight == ReversibilityLevel.NONE.default_risk_weight

    # --- has_non_reversible_actions ---

    def test_has_non_reversible_actions_true(self):
        self.registry.register(self._make_action("a", ReversibilityLevel.FULL))
        self.registry.register(self._make_action("b", ReversibilityLevel.NONE))
        assert self.registry.has_non_reversible_actions() is True

    def test_has_non_reversible_actions_false(self):
        self.registry.register(self._make_action("a", ReversibilityLevel.FULL))
        self.registry.register(self._make_action("b", ReversibilityLevel.PARTIAL))
        assert self.registry.has_non_reversible_actions() is False

    def test_has_non_reversible_actions_empty(self):
        assert self.registry.has_non_reversible_actions() is False

    # --- mark_undo_unhealthy ---

    def test_mark_undo_unhealthy(self):
        self.registry.register(self._make_action("deploy"))
        self.registry.mark_undo_unhealthy("deploy")
        assert self.registry.get("deploy").undo_api_healthy is False

    def test_mark_undo_unhealthy_missing_no_error(self):
        self.registry.mark_undo_unhealthy("ghost")  # should not raise

    # --- non_reversible_actions property ---

    def test_non_reversible_actions_list(self):
        self.registry.register(self._make_action("safe", ReversibilityLevel.FULL))
        self.registry.register(self._make_action("danger", ReversibilityLevel.NONE))
        self.registry.register(self._make_action("risky", ReversibilityLevel.NONE))
        result = self.registry.non_reversible_actions
        assert set(result) == {"danger", "risky"}

    # --- session_id ---

    def test_session_id_stored(self):
        assert self.registry.session_id == "session:test-rev"
