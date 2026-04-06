# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path
import sys

import pandas as pd


ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

import simulator


class FakeSessionState(dict):
    """Minimal session_state stand-in for simulator unit tests."""

    def __getattr__(self, name: str):
        try:
            return self[name]
        except KeyError as exc:
            raise AttributeError(name) from exc

    def __setattr__(self, name: str, value) -> None:
        self[name] = value



def _setup_fake_state(monkeypatch) -> FakeSessionState:
    fake_state = FakeSessionState()
    monkeypatch.setattr(simulator.st, "session_state", fake_state)
    return fake_state



def test_compute_trust_drift_ranges() -> None:
    for _ in range(200):
        assert 0.5 <= simulator._compute_trust_drift("allow") <= 2.0
        assert -2.0 <= simulator._compute_trust_drift("escalate") <= 0.5
        assert -5.0 <= simulator._compute_trust_drift("deny") <= -1.0



def test_clamp_trust_score_normalizes_values() -> None:
    assert simulator._clamp_trust_score(-10) == 0.0
    assert simulator._clamp_trust_score(30.12) == 30.12
    assert simulator._clamp_trust_score(999) == 100.0
    assert simulator._clamp_trust_score(float("inf")) == 50.0
    assert simulator._clamp_trust_score(float("nan")) == 50.0



def test_build_event_generates_valid_payload(monkeypatch) -> None:
    _setup_fake_state(monkeypatch)
    simulator._ensure_trust_map()

    event = simulator._build_event(datetime.now(tz=timezone.utc))

    assert event["agent_source"] in simulator.AGENTS
    assert event["agent_target"] in simulator.AGENTS
    assert event["agent_source"] != event["agent_target"]
    assert event["policy_name"] in simulator.POLICIES
    assert event["decision"] in simulator.DECISIONS
    assert 0.0 <= event["trust_score"] <= 100.0
    assert isinstance(event["details"], str)



def test_initialize_and_append_events(monkeypatch) -> None:
    fake_state = _setup_fake_state(monkeypatch)

    simulator.initialize_state(simulator.SimulationConfig(seed_events=3))
    assert "events" in fake_state
    assert isinstance(fake_state.events, pd.DataFrame)
    assert len(fake_state.events) == 3

    simulator.append_events(5)
    assert len(fake_state.events) == 8



def test_append_events_keeps_rolling_window(monkeypatch) -> None:
    _setup_fake_state(monkeypatch)
    simulator.initialize_state(simulator.SimulationConfig(seed_events=1499))

    simulator.append_events(10)
    assert len(simulator.st.session_state.events) == 1500


def test_append_events_applies_hard_limit(monkeypatch) -> None:
    _setup_fake_state(monkeypatch)
    simulator.initialize_state(simulator.SimulationConfig(seed_events=1))

    simulator.append_events(999)
    assert len(simulator.st.session_state.events) == 11


def test_load_decision_weights_valid_and_invalid(monkeypatch) -> None:
    monkeypatch.setenv("AGD_DECISION_WEIGHTS", "0.7,0.2,0.1")
    valid_weights = simulator._load_decision_weights()
    assert len(valid_weights) == 3
    assert abs(sum(valid_weights) - 1.0) < 1e-9

    monkeypatch.setenv("AGD_DECISION_WEIGHTS", "0.9,0.1")
    assert simulator._load_decision_weights() == simulator.DEFAULT_DECISION_WEIGHTS

    monkeypatch.setenv("AGD_DECISION_WEIGHTS", "1,0,-1")
    assert simulator._load_decision_weights() == simulator.DEFAULT_DECISION_WEIGHTS


def test_ensure_trust_map_normalizes_tampered_state(monkeypatch) -> None:
    fake_state = _setup_fake_state(monkeypatch)
    fake_state.trust_map = {
        ("orchestrator", "research-agent"): 500,
        ("orchestrator", "orchestrator"): 10,
        "bad-key": -5,
    }

    simulator._ensure_trust_map()

    trust_map = fake_state.trust_map
    assert len(trust_map) == len(simulator.AGENTS) * (len(simulator.AGENTS) - 1)
    assert trust_map[("orchestrator", "research-agent")] == 100.0
    assert ("orchestrator", "orchestrator") not in trust_map
