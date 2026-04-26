# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""Smoke tests for the agent-lightning package."""

from __future__ import annotations

import pytest


def test_top_level_imports():
    """All public symbols are importable from agent_lightning_gov."""
    from agent_lightning_gov import (
        FlightRecorderEmitter,
        GovernedEnvironment,
        GovernedRunner,
        PolicyReward,
        policy_penalty,
    )
    assert GovernedRunner is not None
    assert PolicyReward is not None
    assert FlightRecorderEmitter is not None
    assert GovernedEnvironment is not None
    assert callable(policy_penalty)


def test_backward_compat_shim():
    """Importing from agent_os.integrations.agent_lightning still works."""
    pytest.importorskip("agent_os", reason="agent-os-kernel not installed")
    from agent_os.integrations.agent_lightning import (
        GovernedRunner,
        PolicyReward,
        FlightRecorderEmitter,
    )
    assert GovernedRunner is not None
    assert PolicyReward is not None
    assert FlightRecorderEmitter is not None


def test_runner_policy_violation_type():
    """GovernedRunner exposes PolicyViolationType enum."""
    from agent_lightning_gov.runner import PolicyViolationType

    assert hasattr(PolicyViolationType, "BLOCKED")
    assert hasattr(PolicyViolationType, "MODIFIED")
    assert hasattr(PolicyViolationType, "WARNED")


def test_reward_config():
    """RewardConfig has expected defaults."""
    from agent_lightning_gov.reward import RewardConfig

    cfg = RewardConfig()
    assert cfg.critical_penalty == -100.0
    assert cfg.high_penalty == -50.0
