# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""Tests for blue-green deployment strategy."""

import pytest

from agent_sre.delivery.blue_green import (
    BlueGreenConfig,
    BlueGreenManager,
    Environment,
    EnvironmentState,
)

# Config with zero timeouts for fast tests
_FAST = BlueGreenConfig(drain_timeout_seconds=0, health_check_interval_seconds=0, validation_timeout_seconds=0)


class TestInitialState:
    """Blue=active, green=inactive on startup."""

    def test_blue_is_active(self) -> None:
        mgr = BlueGreenManager()
        active = mgr.get_active()
        assert active.name == Environment.BLUE
        assert active.state == EnvironmentState.ACTIVE

    def test_green_is_inactive(self) -> None:
        mgr = BlueGreenManager()
        inactive = mgr.get_inactive()
        assert inactive.name == Environment.GREEN
        assert inactive.state == EnvironmentState.INACTIVE


class TestDeploy:
    """Deploy new version to inactive environment."""

    def test_deploy_sets_deploying_state(self) -> None:
        mgr = BlueGreenManager()
        env = mgr.deploy("v2.0.0")
        assert env.state == EnvironmentState.DEPLOYING
        assert env.agent_version == "v2.0.0"
        assert env.name == Environment.GREEN

    def test_deploy_emits_event(self) -> None:
        mgr = BlueGreenManager()
        mgr.deploy("v2.0.0")
        assert len(mgr.events) == 1
        assert mgr.events[0].event_type == "deploy"
        assert mgr.events[0].details["version"] == "v2.0.0"


class TestValidate:
    """Validate with health check function."""

    def test_passing_health_check(self) -> None:
        mgr = BlueGreenManager(config=_FAST)
        mgr.deploy("v2.0.0")
        result = mgr.validate(lambda: True)
        assert result is True
        inactive = mgr.get_inactive()
        assert inactive.health_status == "healthy"

    def test_failing_health_check(self) -> None:
        mgr = BlueGreenManager(config=_FAST)
        mgr.deploy("v2.0.0")
        result = mgr.validate(lambda: False)
        assert result is False
        inactive = mgr.get_inactive()
        assert inactive.health_status == "unhealthy"
        assert inactive.state == EnvironmentState.INACTIVE

    def test_exception_in_health_check_treated_as_failure(self) -> None:
        mgr = BlueGreenManager(config=_FAST)
        mgr.deploy("v2.0.0")

        def bad_check() -> bool:
            raise ConnectionError("unreachable")

        result = mgr.validate(bad_check)
        assert result is False


class TestSwitch:
    """Switch traffic between environments."""

    def test_switch_makes_inactive_active(self) -> None:
        mgr = BlueGreenManager(config=_FAST)
        mgr.deploy("v2.0.0")
        mgr.validate(lambda: True)
        new_active = mgr.switch()
        assert new_active.name == Environment.GREEN
        assert new_active.state == EnvironmentState.ACTIVE

    def test_switch_drains_previous_active(self) -> None:
        mgr = BlueGreenManager(config=_FAST)
        mgr.deploy("v2.0.0")
        mgr.validate(lambda: True)
        mgr.switch()
        old = mgr.get_inactive()
        assert old.name == Environment.BLUE
        assert old.state == EnvironmentState.INACTIVE

    def test_switch_fails_when_not_healthy(self) -> None:
        mgr = BlueGreenManager(config=_FAST)
        mgr.deploy("v2.0.0")
        mgr.validate(lambda: False)
        with pytest.raises(RuntimeError, match="health_status"):
            mgr.switch()


class TestRollback:
    """Rollback switches back to previous environment."""

    def test_rollback_restores_previous_active(self) -> None:
        mgr = BlueGreenManager(config=_FAST)
        mgr.deploy("v2.0.0")
        mgr.validate(lambda: True)
        mgr.switch()
        restored = mgr.rollback()
        assert restored.name == Environment.BLUE
        assert restored.state == EnvironmentState.ACTIVE

    def test_rollback_without_previous_raises(self) -> None:
        mgr = BlueGreenManager(config=_FAST)
        with pytest.raises(RuntimeError, match="No previous environment"):
            mgr.rollback()

    def test_rollback_emits_event(self) -> None:
        mgr = BlueGreenManager(config=_FAST)
        mgr.deploy("v2.0.0")
        mgr.validate(lambda: True)
        mgr.switch()
        mgr.rollback()
        rollback_events = [e for e in mgr.events if e.event_type == "rollback"]
        assert len(rollback_events) == 1


class TestFailedValidationPreventsSwitch:
    """Failed validation must prevent traffic switch."""

    def test_cannot_switch_after_failed_validation(self) -> None:
        mgr = BlueGreenManager(config=_FAST)
        mgr.deploy("v2.0.0")
        mgr.validate(lambda: False)
        with pytest.raises(RuntimeError):
            mgr.switch()


class TestFullLifecycle:
    """Full lifecycle: deploy → validate → switch → deploy → validate → switch."""

    def test_two_full_cycles(self) -> None:
        mgr = BlueGreenManager(config=_FAST)

        # Cycle 1: deploy v2 to green, switch to green
        mgr.deploy("v2.0.0")
        assert mgr.validate(lambda: True)
        active = mgr.switch()
        assert active.name == Environment.GREEN
        assert active.agent_version == "v2.0.0"

        # Cycle 2: deploy v3 to blue (now inactive), switch to blue
        mgr.deploy("v3.0.0")
        inactive = mgr.get_inactive()
        assert inactive.name == Environment.BLUE
        assert inactive.agent_version == "v3.0.0"
        assert mgr.validate(lambda: True)
        active = mgr.switch()
        assert active.name == Environment.BLUE
        assert active.agent_version == "v3.0.0"


class TestGetStatus:
    """Status shows both environments."""

    def test_status_contains_both_envs(self) -> None:
        mgr = BlueGreenManager()
        status = mgr.get_status()
        assert "blue" in status
        assert "green" in status
        assert status["active_environment"] == "blue"

    def test_status_after_deploy(self) -> None:
        mgr = BlueGreenManager(config=_FAST)
        mgr.deploy("v2.0.0")
        status = mgr.get_status()
        assert status["green"]["agent_version"] == "v2.0.0"
        assert status["green"]["state"] == EnvironmentState.DEPLOYING

    def test_status_tracks_events(self) -> None:
        mgr = BlueGreenManager(config=_FAST)
        mgr.deploy("v2.0.0")
        mgr.validate(lambda: True)
        status = mgr.get_status()
        assert status["events_count"] > 0


class TestConfig:
    """Custom configuration is respected."""

    def test_default_config(self) -> None:
        mgr = BlueGreenManager()
        assert mgr.config.validation_timeout_seconds == 60
        assert mgr.config.auto_rollback_on_failure is True

    def test_custom_config(self) -> None:
        cfg = BlueGreenConfig(
            validation_timeout_seconds=120,
            drain_timeout_seconds=60,
            auto_rollback_on_failure=False,
        )
        mgr = BlueGreenManager(config=cfg)
        assert mgr.config.validation_timeout_seconds == 120
        assert mgr.config.auto_rollback_on_failure is False
