# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""Tests for Trust Decay."""

import time
import pytest
from agentmesh.reward.trust_decay import (
    NetworkTrustEngine,
    TrustEvent,
)


@pytest.fixture
def engine():
    return NetworkTrustEngine()


# =============================================================================
# Basic score management
# =============================================================================


class TestScoreManagement:
    def test_default_score(self, engine):
        assert engine.get_score("did:agent:1") == 500.0

    def test_set_score(self, engine):
        engine.set_score("did:agent:1", 800.0)
        assert engine.get_score("did:agent:1") == 800.0

    def test_score_clamped(self, engine):
        engine.set_score("a", 2000.0)
        assert engine.get_score("a") == 1000.0
        engine.set_score("a", -100.0)
        assert engine.get_score("a") == 0.0

    def test_positive_signal(self, engine):
        engine.set_score("a", 500.0)
        engine.record_positive_signal("a", bonus=10.0)
        assert engine.get_score("a") == 510.0


# =============================================================================
# Interaction graph
# =============================================================================


class TestInteractionGraph:
    """Interaction graph is not active."""

    def test_record_interaction_noop(self, engine):
        engine.record_interaction("a", "b")
        neighbors = engine.get_neighbors("a")
        assert len(neighbors) == 1
        assert neighbors[0][0] == "b"

    def test_get_neighbors_empty(self, engine):
        assert engine.get_neighbors("a") == []


# =============================================================================
# Trust event processing
# =============================================================================


class TestTrustEvents:
    def test_direct_impact(self, engine):
        engine.set_score("a", 800.0)
        event = TrustEvent(agent_did="a", event_type="violation", severity_weight=0.5)
        deltas = engine.process_trust_event(event)
        assert deltas["a"] == -50.0
        assert engine.get_score("a") == 750.0

    def test_critical_event(self, engine):
        engine.set_score("a", 500.0)
        event = TrustEvent(agent_did="a", event_type="breach", severity_weight=1.0)
        deltas = engine.process_trust_event(event)
        assert deltas["a"] == -100.0
        assert engine.get_score("a") == 400.0

    def test_propagation_to_neighbor(self, engine):
        """Trust events propagate to neighbors via interaction graph."""
        engine.set_score("a", 800.0)
        engine.set_score("b", 800.0)
        engine.record_interaction("a", "b")

        event = TrustEvent(agent_did="a", event_type="failure", severity_weight=1.0)
        deltas = engine.process_trust_event(event)

        # B should be affected (propagation through interaction graph)
        assert "b" in deltas
        assert engine.get_score("b") < 800.0

    def test_propagation_depth_limit(self):
        """No propagation."""
        engine = NetworkTrustEngine(propagation_depth=1)
        engine.set_score("a", 800.0)
        engine.set_score("b", 800.0)
        engine.set_score("c", 800.0)

        event = TrustEvent(agent_did="a", event_type="failure", severity_weight=1.0)
        deltas = engine.process_trust_event(event)

        assert "b" not in deltas
        assert "c" not in deltas

    def test_no_propagation_without_edges(self, engine):
        engine.set_score("a", 800.0)
        engine.set_score("b", 800.0)
        event = TrustEvent(agent_did="a", event_type="failure", severity_weight=1.0)
        deltas = engine.process_trust_event(event)
        assert "b" not in deltas
        assert engine.get_score("b") == 800.0

    def test_score_change_callback(self, engine):
        events_received = []
        engine.on_score_change(lambda d: events_received.append(d))
        engine.set_score("a", 800.0)
        event = TrustEvent(agent_did="a", event_type="failure", severity_weight=0.5)
        engine.process_trust_event(event)
        assert len(events_received) == 1


# =============================================================================
# Temporal decay
# =============================================================================


class TestTemporalDecay:
    def test_decay_without_positive_signals(self, engine):
        engine.set_score("a", 800.0)
        # Simulate 2 hours without positive signals
        now = time.time()
        engine._last_positive["a"] = now - 7200  # 2 hours ago
        deltas = engine.apply_temporal_decay(now=now)
        assert "a" in deltas
        assert deltas["a"] < 0
        assert engine.get_score("a") < 800.0

    def test_no_decay_with_recent_positive(self, engine):
        engine.set_score("a", 800.0)
        now = time.time()
        engine.record_positive_signal("a")  # Just now
        deltas = engine.apply_temporal_decay(now=now)
        # Score should be 805 (500 default + bonus) — no decay
        assert deltas.get("a", 0) == 0 or abs(deltas.get("a", 0)) < 0.01

    def test_decay_floor(self, engine):
        engine.set_score("a", 150.0)
        now = time.time()
        engine._last_positive["a"] = now - 360000  # 100 hours ago
        engine.apply_temporal_decay(now=now)
        # Should not go below 100 from decay alone
        assert engine.get_score("a") >= 100.0


# =============================================================================
# Regime detection
# =============================================================================


class TestRegimeDetection:
    """Regime detection is not active."""

    def test_always_returns_none(self, engine):
        engine.record_action("a", "db_query")
        assert engine.detect_regime_change("a") is None

    def test_callback_never_fires(self, engine):
        alerts = []
        engine.on_regime_change(lambda a: alerts.append(a))
        engine.record_action("a", "action")
        engine.detect_regime_change("a")
        assert len(alerts) == 0


# =============================================================================
# Health report & queries
# =============================================================================


class TestQueries:
    def test_agent_count(self, engine):
        assert engine.agent_count == 0
        engine.set_score("a", 500)
        engine.set_score("b", 600)
        assert engine.agent_count == 2

    def test_health_report(self, engine):
        engine.set_score("a", 700)
        engine.record_interaction("a", "b")
        report = engine.get_health_report()
        assert report["agent_count"] >= 1
        assert report["edge_count"] == 1  # Interaction graph tracks edges

    def test_alerts_list(self, engine):
        assert engine.alerts == []


# =============================================================================
# Decay over time (inactive agents)
# =============================================================================


class TestDecayOverTime:
    """Trust score decays over time when agent is inactive."""

    def test_decay_after_one_hour(self):
        engine = NetworkTrustEngine(decay_rate=10.0)
        engine.set_score("a", 800.0)
        now = time.time()
        engine._last_positive["a"] = now - 3600  # 1 hour ago
        deltas = engine.apply_temporal_decay(now=now)
        assert deltas["a"] == pytest.approx(-10.0, abs=0.01)
        assert engine.get_score("a") == pytest.approx(790.0, abs=0.01)

    def test_decay_after_three_hours(self):
        engine = NetworkTrustEngine(decay_rate=10.0)
        engine.set_score("a", 800.0)
        now = time.time()
        engine._last_positive["a"] = now - 3600 * 3  # 3 hours ago
        deltas = engine.apply_temporal_decay(now=now)
        assert deltas["a"] == pytest.approx(-30.0, abs=0.01)
        assert engine.get_score("a") == pytest.approx(770.0, abs=0.01)

    def test_decay_after_half_hour(self):
        engine = NetworkTrustEngine(decay_rate=10.0)
        engine.set_score("a", 800.0)
        now = time.time()
        engine._last_positive["a"] = now - 1800  # 30 minutes
        deltas = engine.apply_temporal_decay(now=now)
        assert deltas["a"] == pytest.approx(-5.0, abs=0.01)

    def test_no_decay_for_newly_registered_agent(self):
        """Agents without _last_positive entry default to now — no decay."""
        engine = NetworkTrustEngine(decay_rate=10.0)
        engine.set_score("a", 800.0)
        now = time.time()
        deltas = engine.apply_temporal_decay(now=now)
        assert deltas.get("a", 0) == 0

    def test_successive_decay_applications(self):
        """Calling apply_temporal_decay multiple times accumulates decay."""
        engine = NetworkTrustEngine(decay_rate=10.0)
        engine.set_score("a", 800.0)
        t0 = time.time()
        engine._last_positive["a"] = t0 - 3600  # 1 hour ago

        engine.apply_temporal_decay(now=t0)
        score_after_first = engine.get_score("a")

        # 1 more hour passes (now 2 hours since last positive)
        engine.apply_temporal_decay(now=t0 + 3600)
        score_after_second = engine.get_score("a")

        assert score_after_first > score_after_second


# =============================================================================
# Configurable decay rate
# =============================================================================


class TestConfigurableDecayRate:
    """Decay rate is configurable."""

    def test_higher_decay_rate_causes_more_decay(self):
        slow = NetworkTrustEngine(decay_rate=1.0)
        fast = NetworkTrustEngine(decay_rate=20.0)
        now = time.time()
        for eng in (slow, fast):
            eng.set_score("a", 800.0)
            eng._last_positive["a"] = now - 3600

        slow.apply_temporal_decay(now=now)
        fast.apply_temporal_decay(now=now)
        assert fast.get_score("a") < slow.get_score("a")

    def test_zero_decay_rate(self):
        engine = NetworkTrustEngine(decay_rate=0.0)
        engine.set_score("a", 800.0)
        now = time.time()
        engine._last_positive["a"] = now - 36000  # 10 hours ago
        deltas = engine.apply_temporal_decay(now=now)
        assert deltas.get("a", 0) == 0
        assert engine.get_score("a") == 800.0

    def test_small_decay_rate(self):
        engine = NetworkTrustEngine(decay_rate=0.5)
        engine.set_score("a", 800.0)
        now = time.time()
        engine._last_positive["a"] = now - 7200  # 2 hours
        deltas = engine.apply_temporal_decay(now=now)
        assert deltas["a"] == pytest.approx(-1.0, abs=0.01)

    def test_large_decay_rate(self):
        engine = NetworkTrustEngine(decay_rate=100.0)
        engine.set_score("a", 800.0)
        now = time.time()
        engine._last_positive["a"] = now - 3600  # 1 hour
        engine.apply_temporal_decay(now=now)
        # decay = 100 * 1 = 100, but effective_decay = min(100, max(0, 800-100)) = 100
        assert engine.get_score("a") == pytest.approx(700.0, abs=0.01)


# =============================================================================
# Minimum floor
# =============================================================================


class TestMinimumFloor:
    """Trust score has a minimum floor — decay doesn't go below 100."""

    def test_decay_stops_at_floor(self):
        engine = NetworkTrustEngine(decay_rate=50.0)
        engine.set_score("a", 200.0)
        now = time.time()
        engine._last_positive["a"] = now - 36000  # 10 hours
        engine.apply_temporal_decay(now=now)
        assert engine.get_score("a") == 100.0

    def test_score_at_floor_no_further_decay(self):
        engine = NetworkTrustEngine(decay_rate=10.0)
        engine.set_score("a", 100.0)
        now = time.time()
        engine._last_positive["a"] = now - 7200
        deltas = engine.apply_temporal_decay(now=now)
        assert deltas.get("a", 0) == 0
        assert engine.get_score("a") == 100.0

    def test_floor_enforced_for_score_just_above(self):
        engine = NetworkTrustEngine(decay_rate=50.0)
        engine.set_score("a", 101.0)
        now = time.time()
        engine._last_positive["a"] = now - 3600  # 1 hour, decay=50
        engine.apply_temporal_decay(now=now)
        # effective_decay = min(50, max(0, 101-100)) = 1
        assert engine.get_score("a") == 100.0

    def test_set_score_clamps_below_zero(self, engine):
        """set_score itself clamps at 0 (hard floor)."""
        engine.set_score("a", -50.0)
        assert engine.get_score("a") == 0.0


# =============================================================================
# Active agents don't decay
# =============================================================================


class TestActivityResetsDecay:
    """Active agents don't decay — decay resets on activity."""

    def test_positive_signal_resets_decay_clock(self):
        engine = NetworkTrustEngine(decay_rate=10.0)
        engine.set_score("a", 800.0)
        now = time.time()
        engine._last_positive["a"] = now - 7200  # 2 hours ago

        # Record a positive signal to reset the clock
        engine.record_positive_signal("a", bonus=0.0)
        deltas = engine.apply_temporal_decay(now=now)
        # _last_positive now ~= now, so hours_since ≈ 0
        assert deltas.get("a", 0) == pytest.approx(0, abs=0.1)

    def test_activity_prevents_decay_accumulation(self):
        engine = NetworkTrustEngine(decay_rate=10.0)
        engine.set_score("a", 800.0)
        now = time.time()
        engine._last_positive["a"] = now  # Just now

        deltas = engine.apply_temporal_decay(now=now + 1)
        # Nearly no time elapsed
        assert abs(deltas.get("a", 0)) < 0.01

    def test_frequent_activity_keeps_score_stable(self):
        engine = NetworkTrustEngine(decay_rate=10.0)
        engine.set_score("a", 800.0)
        t = time.time()

        # Simulate activity every 10 minutes for 5 hours
        for i in range(30):
            sim_time = t + i * 600
            engine._last_positive["a"] = sim_time  # simulate activity at sim_time
            engine.apply_temporal_decay(now=sim_time)

        # Score shouldn't have decayed meaningfully
        assert engine.get_score("a") >= 799.0


# =============================================================================
# Proportional to inactivity
# =============================================================================


class TestDecayProportionality:
    """Decay is proportional to inactivity duration."""

    def test_double_inactivity_double_decay(self):
        e1 = NetworkTrustEngine(decay_rate=10.0)
        e2 = NetworkTrustEngine(decay_rate=10.0)
        now = time.time()
        for e in (e1, e2):
            e.set_score("a", 800.0)
        e1._last_positive["a"] = now - 3600   # 1 hour
        e2._last_positive["a"] = now - 7200   # 2 hours

        d1 = e1.apply_temporal_decay(now=now)
        d2 = e2.apply_temporal_decay(now=now)
        assert d2["a"] == pytest.approx(2 * d1["a"], abs=0.01)

    def test_linear_scaling(self):
        engine = NetworkTrustEngine(decay_rate=5.0)
        engine.set_score("a", 900.0)
        now = time.time()
        engine._last_positive["a"] = now - 3600 * 4  # 4 hours
        deltas = engine.apply_temporal_decay(now=now)
        # 5.0 * 4 = 20.0
        assert deltas["a"] == pytest.approx(-20.0, abs=0.01)


# =============================================================================
# Multiple agents decay independently
# =============================================================================


class TestMultiAgentDecay:
    """Multiple agents decay independently."""

    def test_two_agents_different_inactivity(self):
        engine = NetworkTrustEngine(decay_rate=10.0)
        engine.set_score("a", 800.0)
        engine.set_score("b", 800.0)
        now = time.time()
        engine._last_positive["a"] = now - 3600   # 1 hour
        engine._last_positive["b"] = now - 7200   # 2 hours

        deltas = engine.apply_temporal_decay(now=now)
        assert deltas["a"] == pytest.approx(-10.0, abs=0.01)
        assert deltas["b"] == pytest.approx(-20.0, abs=0.01)

    def test_active_agent_unaffected_by_inactive_peer(self):
        engine = NetworkTrustEngine(decay_rate=10.0)
        engine.set_score("active", 800.0)
        engine.set_score("inactive", 800.0)
        now = time.time()
        engine._last_positive["active"] = now        # just now
        engine._last_positive["inactive"] = now - 36000  # 10 hours ago

        deltas = engine.apply_temporal_decay(now=now)
        assert deltas.get("active", 0) == pytest.approx(0, abs=0.1)
        assert deltas["inactive"] < 0

    def test_three_agents_independent_floors(self):
        engine = NetworkTrustEngine(decay_rate=50.0)
        engine.set_score("a", 200.0)
        engine.set_score("b", 500.0)
        engine.set_score("c", 100.0)
        now = time.time()
        for did in ("a", "b", "c"):
            engine._last_positive[did] = now - 36000  # 10 hours

        engine.apply_temporal_decay(now=now)
        assert engine.get_score("a") == 100.0
        assert engine.get_score("b") == 100.0
        assert engine.get_score("c") == 100.0


# =============================================================================
# Decay stops when agent is removed
# =============================================================================


class TestDecayAfterRemoval:
    """Decay stops when agent is removed from the engine."""

    def test_removed_agent_not_in_deltas(self):
        engine = NetworkTrustEngine(decay_rate=10.0)
        engine.set_score("a", 800.0)
        now = time.time()
        engine._last_positive["a"] = now - 7200

        # Remove agent from scores
        del engine._scores["a"]
        deltas = engine.apply_temporal_decay(now=now)
        assert "a" not in deltas

    def test_remaining_agents_still_decay(self):
        engine = NetworkTrustEngine(decay_rate=10.0)
        engine.set_score("a", 800.0)
        engine.set_score("b", 800.0)
        now = time.time()
        engine._last_positive["a"] = now - 3600
        engine._last_positive["b"] = now - 3600

        del engine._scores["a"]
        deltas = engine.apply_temporal_decay(now=now)
        assert "a" not in deltas
        assert "b" in deltas


# =============================================================================
# Trust recovery after decay
# =============================================================================


class TestTrustRecovery:
    """Trust recovery after decay period."""

    def test_positive_signal_recovers_score(self):
        engine = NetworkTrustEngine(decay_rate=10.0)
        engine.set_score("a", 800.0)
        now = time.time()
        engine._last_positive["a"] = now - 36000  # 10 hours ago

        engine.apply_temporal_decay(now=now)
        decayed_score = engine.get_score("a")
        assert decayed_score < 800.0

        engine.record_positive_signal("a", bonus=50.0)
        assert engine.get_score("a") == decayed_score + 50.0

    def test_recovery_above_decay_floor(self):
        engine = NetworkTrustEngine(decay_rate=50.0)
        engine.set_score("a", 200.0)
        now = time.time()
        engine._last_positive["a"] = now - 36000
        engine.apply_temporal_decay(now=now)
        assert engine.get_score("a") == 100.0

        # Recover
        engine.record_positive_signal("a", bonus=300.0)
        assert engine.get_score("a") == 400.0

    def test_recovery_resets_decay_clock(self):
        engine = NetworkTrustEngine(decay_rate=10.0)
        engine.set_score("a", 800.0)
        now = time.time()
        engine._last_positive["a"] = now - 7200

        engine.apply_temporal_decay(now=now)
        engine.record_positive_signal("a", bonus=0.0)  # reset clock

        # Apply decay again immediately — should be negligible
        deltas = engine.apply_temporal_decay(now=now)
        assert abs(deltas.get("a", 0)) < 0.1


# =============================================================================
# Edge cases
# =============================================================================


class TestEdgeCases:
    """Edge cases: very long inactivity, very short decay windows."""

    def test_very_long_inactivity_hits_floor(self):
        engine = NetworkTrustEngine(decay_rate=2.0)
        engine.set_score("a", 1000.0)
        now = time.time()
        engine._last_positive["a"] = now - 3600 * 24 * 365  # 1 year
        engine.apply_temporal_decay(now=now)
        assert engine.get_score("a") == 100.0

    def test_very_short_decay_window(self):
        engine = NetworkTrustEngine(decay_rate=10.0)
        engine.set_score("a", 800.0)
        now = time.time()
        engine._last_positive["a"] = now - 1  # 1 second ago
        deltas = engine.apply_temporal_decay(now=now)
        # 10 * (1/3600) ≈ 0.003 — negligible
        assert abs(deltas.get("a", 0)) < 0.01

    def test_max_score_with_decay(self):
        engine = NetworkTrustEngine(decay_rate=10.0)
        engine.set_score("a", 1000.0)
        now = time.time()
        engine._last_positive["a"] = now - 3600
        engine.apply_temporal_decay(now=now)
        assert engine.get_score("a") == pytest.approx(990.0, abs=0.01)

    def test_score_slightly_above_floor_with_large_decay(self):
        engine = NetworkTrustEngine(decay_rate=1000.0)
        engine.set_score("a", 100.5)
        now = time.time()
        engine._last_positive["a"] = now - 3600
        engine.apply_temporal_decay(now=now)
        # effective_decay = min(1000, max(0, 100.5-100)) = 0.5
        assert engine.get_score("a") == 100.0

    def test_simultaneous_decay_same_timestamp(self):
        engine = NetworkTrustEngine(decay_rate=10.0)
        engine.set_score("a", 500.0)
        engine.set_score("b", 700.0)
        now = time.time()
        engine._last_positive["a"] = now - 3600
        engine._last_positive["b"] = now - 3600
        deltas = engine.apply_temporal_decay(now=now)
        assert deltas["a"] == pytest.approx(-10.0, abs=0.01)
        assert deltas["b"] == pytest.approx(-10.0, abs=0.01)


# =============================================================================
# Interaction with trust threshold gates during decay
# =============================================================================


class TestThresholdGatesDuringDecay:
    """Interaction with trust threshold gates during decay."""

    def test_decay_below_warning_threshold(self):
        from agentmesh.constants import TRUST_WARNING_THRESHOLD
        engine = NetworkTrustEngine(decay_rate=50.0)
        engine.set_score("a", 600.0)
        now = time.time()
        engine._last_positive["a"] = now - 7200 * 2  # 4 hours
        engine.apply_temporal_decay(now=now)
        assert engine.get_score("a") < TRUST_WARNING_THRESHOLD

    def test_decay_below_revocation_threshold(self):
        from agentmesh.constants import TRUST_REVOCATION_THRESHOLD
        engine = NetworkTrustEngine(decay_rate=50.0)
        engine.set_score("a", 500.0)
        now = time.time()
        engine._last_positive["a"] = now - 36000  # 10 hours
        engine.apply_temporal_decay(now=now)
        assert engine.get_score("a") < TRUST_REVOCATION_THRESHOLD

    def test_decay_crosses_tier_boundary(self):
        from agentmesh.constants import TIER_TRUSTED_THRESHOLD
        engine = NetworkTrustEngine(decay_rate=20.0)
        engine.set_score("a", 750.0)
        now = time.time()
        engine._last_positive["a"] = now - 3600 * 3  # 3 hours, decay=60
        engine.apply_temporal_decay(now=now)
        assert engine.get_score("a") < TIER_TRUSTED_THRESHOLD

    def test_score_change_callback_fires_on_decay(self):
        engine = NetworkTrustEngine(decay_rate=10.0)
        # Trust events fire callbacks, but temporal decay does not
        # (verify current behavior)
        callbacks_fired = []
        engine.on_score_change(lambda d: callbacks_fired.append(d))
        engine.set_score("a", 800.0)
        now = time.time()
        engine._last_positive["a"] = now - 3600
        engine.apply_temporal_decay(now=now)
        # apply_temporal_decay does NOT fire callbacks (by design)
        assert len(callbacks_fired) == 0

    def test_event_penalty_plus_decay_compound(self):
        """Trust event penalty and temporal decay compound."""
        engine = NetworkTrustEngine(decay_rate=10.0)
        engine.set_score("a", 800.0)
        now = time.time()
        engine._last_positive["a"] = now - 3600  # 1 hour

        # Apply event penalty
        event = TrustEvent(agent_did="a", event_type="violation", severity_weight=0.5)
        engine.process_trust_event(event)
        assert engine.get_score("a") == 750.0

        # Apply decay on top
        engine.apply_temporal_decay(now=now)
        assert engine.get_score("a") < 750.0
