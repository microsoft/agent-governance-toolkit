# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta
import random
from typing import Any

import pandas as pd
import streamlit as st


AGENTS = [
    "orchestrator",
    "research-agent",
    "coding-agent",
    "compliance-agent",
    "retrieval-agent",
    "security-agent",
]

POLICIES = [
    "pii_redaction",
    "tool_allowlist",
    "prompt_injection_guard",
    "data_residency",
    "secret_scanner",
    "rate_limit",
]

DECISIONS = ["allow", "deny", "escalate"]
DECISION_WEIGHTS = [0.78, 0.14, 0.08]

VIOLATION_CATEGORIES = [
    "PII",
    "Prompt Injection",
    "Secrets",
    "Data Residency",
    "Tool Policy",
]


@dataclass(frozen=True)
class SimulationConfig:
    seed_events: int = 80


def _random_agent_pair() -> tuple[str, str]:
    source = random.choice(AGENTS)
    target = random.choice([a for a in AGENTS if a != source])
    return source, target


def _compute_trust_drift(decision: str) -> float:
    if decision == "allow":
        return random.uniform(0.5, 2.0)
    if decision == "escalate":
        return random.uniform(-2.0, 0.5)
    return random.uniform(-5.0, -1.0)


def _ensure_trust_map() -> None:
    if "trust_map" in st.session_state:
        return

    trust_map: dict[tuple[str, str], float] = {}
    for src in AGENTS:
        for dst in AGENTS:
            if src == dst:
                continue
            trust_map[(src, dst)] = random.uniform(65.0, 95.0)
    st.session_state.trust_map = trust_map


def _build_event(ts: datetime) -> dict[str, Any]:
    source, target = _random_agent_pair()
    policy = random.choice(POLICIES)
    decision = random.choices(DECISIONS, weights=DECISION_WEIGHTS, k=1)[0]

    pair = (source, target)
    drift = _compute_trust_drift(decision)
    st.session_state.trust_map[pair] = max(0.0, min(100.0, st.session_state.trust_map[pair] + drift))
    trust_score = round(st.session_state.trust_map[pair], 2)

    violation = decision in {"deny", "escalate"}
    severity = random.choice(["low", "medium", "high", "critical"]) if violation else "none"
    category = random.choice(VIOLATION_CATEGORIES) if violation else "none"

    return {
        "timestamp": ts,
        "audit_id": f"AUD-{random.randint(100000, 999999)}",
        "agent_source": source,
        "agent_target": target,
        "policy_name": policy,
        "decision": decision,
        "trust_score": trust_score,
        "violation": violation,
        "violation_category": category,
        "severity": severity,
        "details": (
            "Policy violation detected and logged for review."
            if violation
            else "Request satisfied all active governance controls."
        ),
    }


def initialize_state(config: SimulationConfig | None = None) -> None:
    config = config or SimulationConfig()

    if "events" in st.session_state:
        return

    _ensure_trust_map()

    now = datetime.utcnow()
    rows = []
    for idx in range(config.seed_events):
        rows.append(_build_event(now - timedelta(seconds=config.seed_events - idx)))

    st.session_state.events = pd.DataFrame(rows)


def append_events(count: int = 1) -> None:
    _ensure_trust_map()
    latest = datetime.utcnow()
    rows = [_build_event(latest + timedelta(milliseconds=i * 100)) for i in range(max(1, count))]
    new_df = pd.DataFrame(rows)

    st.session_state.events = pd.concat([st.session_state.events, new_df], ignore_index=True)
    # Keep recent window for fast rendering in demo mode.
    st.session_state.events = st.session_state.events.tail(1500).reset_index(drop=True)
