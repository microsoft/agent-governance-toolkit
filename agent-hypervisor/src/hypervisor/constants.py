# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""Centralized constants for the Agent Hypervisor package.

All thresholds, limits, and magic numbers used across modules are defined
here so they can be maintained in a single place.  Modules should import
from ``hypervisor.constants`` rather than hard-coding values locally.
"""

from __future__ import annotations

# ---------------------------------------------------------------------------
# Ring trust-score thresholds
# ---------------------------------------------------------------------------
RING_1_TRUST_THRESHOLD: float = 0.95
"""Minimum effective score (with consensus) for Ring 1 (Privileged)."""

RING_2_TRUST_THRESHOLD: float = 0.60
"""Minimum effective score for Ring 2 (Standard)."""

RING_1_ENFORCER_THRESHOLD: float = 0.70
"""Trust threshold used by the RingEnforcer for Ring 1 access."""

# ---------------------------------------------------------------------------
# Rate-limiter defaults  (requests/sec, burst capacity)
# ---------------------------------------------------------------------------
RATE_LIMIT_RING_0: tuple[float, float] = (100.0, 200.0)
"""Ring 0 (Root/SRE): generous rate limit."""

RATE_LIMIT_RING_1: tuple[float, float] = (50.0, 100.0)
"""Ring 1 (Privileged): moderate rate limit."""

RATE_LIMIT_RING_2: tuple[float, float] = (20.0, 40.0)
"""Ring 2 (Standard): conservative rate limit."""

RATE_LIMIT_RING_3: tuple[float, float] = (5.0, 10.0)
"""Ring 3 (Sandbox): strict rate limit."""

RATE_LIMIT_FALLBACK: tuple[float, float] = RATE_LIMIT_RING_2
"""Fallback rate limit when a ring is not found in the limits map."""

# ---------------------------------------------------------------------------
# Vouching / sponsorship thresholds
# ---------------------------------------------------------------------------
VOUCHING_SCORE_SCALE: float = 1000.0
"""Maximum trust-score scale used by the vouching engine."""

VOUCHING_MIN_VOUCHER_SCORE: float = 0.50
"""Minimum score required to sponsor another agent."""

VOUCHING_DEFAULT_BOND_PCT: float = 0.20
"""Default percentage of sigma bonded when sponsoring."""

VOUCHING_DEFAULT_MAX_EXPOSURE: float = 0.80
"""Maximum exposure percentage for bonding."""

# ---------------------------------------------------------------------------
# Saga orchestrator defaults
# ---------------------------------------------------------------------------
SAGA_DEFAULT_MAX_RETRIES: int = 2
"""Default maximum retries per saga step."""

SAGA_DEFAULT_RETRY_DELAY_SECONDS: float = 1.0
"""Default delay between saga step retries (multiplied by attempt number)."""

SAGA_DEFAULT_STEP_TIMEOUT_SECONDS: int = 300
"""Default timeout for a single saga step (5 minutes)."""

# ---------------------------------------------------------------------------
# Validation limits (models.py)
# ---------------------------------------------------------------------------
MAX_AGENT_ID_LENGTH: int = 256
"""Maximum length of an agent identifier string."""

MAX_NAME_LENGTH: int = 256
"""Maximum length of resource names."""

MAX_API_PATH_LENGTH: int = 2048
"""Maximum length of an API path."""

MAX_PARTICIPANTS_LIMIT: int = 1000
"""Maximum number of participants in a session."""

MAX_DURATION_LIMIT: int = 604_800
"""Maximum session duration in seconds (7 days)."""

MAX_UNDO_WINDOW: int = 86_400
"""Maximum undo window in seconds (24 hours)."""

# ---------------------------------------------------------------------------
# SessionConfig defaults
# ---------------------------------------------------------------------------
SESSION_DEFAULT_MIN_EFF_SCORE: float = 0.60
"""Default minimum effective score for session participation."""

# ---------------------------------------------------------------------------
# Risk-weight ranges by ReversibilityLevel
# ---------------------------------------------------------------------------
RISK_WEIGHT_FULL: tuple[float, float] = (0.1, 0.3)
"""Risk weight range for fully reversible actions."""

RISK_WEIGHT_PARTIAL: tuple[float, float] = (0.5, 0.8)
"""Risk weight range for partially reversible actions."""

RISK_WEIGHT_NONE: tuple[float, float] = (0.9, 1.0)
"""Risk weight range for non-reversible actions."""
