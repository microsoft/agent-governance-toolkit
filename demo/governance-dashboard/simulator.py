# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
import logging
import os
import math
import random
from threading import RLock
from typing import Any

import pandas as pd
import streamlit as st


logger = logging.getLogger(__name__)
_STATE_LOCK = RLock()


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
DEFAULT_DECISION_WEIGHTS = [0.78, 0.14, 0.08]

VIOLATION_CATEGORIES = [
    "PII",
    "Prompt Injection",
    "Secrets",
    "Data Residency",
    "Tool Policy",
]


@dataclass(frozen=True)
class SimulationConfig:
    """Configuration values used by the in-app event simulator."""

    seed_events: int = 80


def _load_decision_weights() -> list[float]:
    """Load decision weights from env with strict validation and safe fallback."""

    raw = os.getenv("AGD_DECISION_WEIGHTS", "")
    strict_mode = os.getenv("AGD_STRICT_DECISION_WEIGHTS", "false").strip().lower() in {"1", "true", "yes"}

    def _reject(reason: str) -> list[float]:
        if strict_mode:
            raise ValueError(reason)
        logger.warning("%s Using defaults.", reason)
        return DEFAULT_DECISION_WEIGHTS

    if not raw:
        return DEFAULT_DECISION_WEIGHTS

    try:
        weights = [float(v.strip()) for v in raw.split(",")]
    except ValueError as exc:
        return _reject(f"Invalid AGD_DECISION_WEIGHTS format '{raw}': {exc}")

    if len(weights) != len(DECISIONS):
        return _reject(f"AGD_DECISION_WEIGHTS must provide {len(DECISIONS)} values")
    if any(w <= 0 for w in weights):
        return _reject("AGD_DECISION_WEIGHTS contains non-positive values")

    total = sum(weights)
    if total <= 0:
        return _reject("AGD_DECISION_WEIGHTS sum is invalid")

    return [w / total for w in weights]


DECISION_WEIGHTS = _load_decision_weights()


def _clamp_trust_score(value: Any, fallback: float = 50.0) -> float:
    try:
        score = float(value)
    except (TypeError, ValueError):
        score = fallback

    if math.isnan(score) or math.isinf(score):
        score = fallback

    return round(max(0.0, min(100.0, score)), 2)


def _validate_event_payload(event: dict[str, Any]) -> dict[str, Any]:
    # Normalize generated values to protect the dashboard from malformed state.
    event["agent_source"] = event.get("agent_source") if event.get("agent_source") in AGENTS else AGENTS[0]

    target = event.get("agent_target")
    if target not in AGENTS or target == event["agent_source"]:
        event["agent_target"] = next(a for a in AGENTS if a != event["agent_source"])

    event["policy_name"] = event.get("policy_name") if event.get("policy_name") in POLICIES else POLICIES[0]
    event["decision"] = event.get("decision") if event.get("decision") in DECISIONS else "deny"

    event["trust_score"] = _clamp_trust_score(event.get("trust_score"))
    event["violation"] = bool(event.get("violation"))

    valid_severity = {"none", "low", "medium", "high", "critical"}
    severity = str(event.get("severity", "none")).lower()
    event["severity"] = severity if severity in valid_severity else "none"

    valid_categories = {"none", *VIOLATION_CATEGORIES}
    category = str(event.get("violation_category", "none"))
    event["violation_category"] = category if category in valid_categories else "none"

    event["details"] = str(event.get("details", ""))

    return event


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
    with _STATE_LOCK:
        trust_map: dict[tuple[str, str], float] = {}
        raw_map = st.session_state.get("trust_map")

        if isinstance(raw_map, dict):
            for key, value in raw_map.items():
                if (
                    isinstance(key, tuple)
                    and len(key) == 2
                    and key[0] in AGENTS
                    and key[1] in AGENTS
                    and key[0] != key[1]
                ):
                    trust_map[(key[0], key[1])] = _clamp_trust_score(value)
                else:
                    logger.warning("Dropping invalid trust_map key: %s", key)

        for src in AGENTS:
            for dst in AGENTS:
                if src == dst:
                    continue
                if (src, dst) not in trust_map:
                    trust_map[(src, dst)] = _clamp_trust_score(random.uniform(65.0, 95.0))

        st.session_state.trust_map = trust_map


def _build_event(ts: datetime) -> dict[str, Any]:
    source, target = _random_agent_pair()
    policy = random.choice(POLICIES)
    decision = random.choices(DECISIONS, weights=DECISION_WEIGHTS, k=1)[0]

    pair = (source, target)
    drift = _compute_trust_drift(decision)
    with _STATE_LOCK:
        current_score = _clamp_trust_score(st.session_state.trust_map.get(pair, random.uniform(65.0, 95.0)))
        st.session_state.trust_map[pair] = _clamp_trust_score(current_score + drift)
        trust_score = _clamp_trust_score(st.session_state.trust_map[pair])

    violation = decision in {"deny", "escalate"}
    severity = random.choice(["low", "medium", "high", "critical"]) if violation else "none"
    category = random.choice(VIOLATION_CATEGORIES) if violation else "none"

    event = {
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

    return _validate_event_payload(event)


def initialize_state(config: SimulationConfig | None = None) -> None:
    """Initialize session-scoped simulator state and seed baseline events."""

    config = config or SimulationConfig()

    with _STATE_LOCK:
        if "events" in st.session_state:
            return

        _ensure_trust_map()

        now = datetime.now(tz=timezone.utc)
        rows = []
        for idx in range(config.seed_events):
            rows.append(_build_event(now - timedelta(seconds=config.seed_events - idx)))

        st.session_state.events = pd.DataFrame(rows)


def append_events(count: int = 1) -> None:
    """Append generated events to session state while preserving a rolling window."""

    try:
        parsed_count = int(count)
    except (TypeError, ValueError):
        parsed_count = 1

    bounded_count = max(1, min(10, parsed_count))
    _ensure_trust_map()
    latest = datetime.now(tz=timezone.utc)
    rows = [_build_event(latest + timedelta(milliseconds=i * 100)) for i in range(bounded_count)]
    new_df = pd.DataFrame(rows)

    with _STATE_LOCK:
        st.session_state.events = pd.concat([st.session_state.events, new_df], ignore_index=True)
        # Keep recent window for fast rendering in demo mode.
        st.session_state.events = st.session_state.events.tail(1500).reset_index(drop=True)
