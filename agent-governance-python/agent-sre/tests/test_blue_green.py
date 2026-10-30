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


class _FakeClock:
    """Stands in for the ``time`` module that ``blue_green`` uses."""

    def __init__(self) -> None:
        self.now = 0.0

    def monotonic(self) -> float:
        return self.now

    def time(self) -> float:
        return self.now

    def sleep(self, seconds: float) -> None:
        # Like time.sleep, reject a negative length.
        if seconds < 0:
            raise ValueError("sleep length must be non-negative")
        self.now += seconds


class _TooManyChecks(BaseException):
    """Escapes ``validate``'s ``except Exception`` to stop a loop that never ends."""


class TestValidateTimeout:
    """The validation timeout is measured on the clock, not by summing intervals."""

    def test_time_spent_in_health_checks_counts_against_timeout(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        clock = _FakeClock()
        monkeypatch.setattr("agent_sre.delivery.blue_green.time", clock)
        calls = []

        def slow_failing_check() -> bool:
            calls.append(clock.now)
            clock.now += 30  # each check takes 30 seconds
            return False

        mgr = BlueGreenManager(
            config=BlueGreenConfig(
                health_check_interval_seconds=5,
                validation_timeout_seconds=60,
            )
        )
        mgr.deploy("v2.0.0")

        assert mgr.validate(slow_failing_check) is False
        # Checks start at 0s and 35s; the second one ends past the 60s timeout.
        assert calls == [0.0, 35.0]

    def test_zero_interval_stops_at_timeout(self, monkeypatch: pytest.MonkeyPatch) -> None:
        clock = _FakeClock()
        monkeypatch.setattr("agent_sre.delivery.blue_green.time", clock)
        calls = 0

        def failing_check() -> bool:
            nonlocal calls
            calls += 1
            if calls > 1000:
                raise _TooManyChecks
            clock.now += 1  # each check takes 1 second
            return False

        mgr = BlueGreenManager(
            config=BlueGreenConfig(
                health_check_interval_seconds=0,
                validation_timeout_seconds=10,
            )
        )
        mgr.deploy("v2.0.0")

        assert mgr.validate(failing_check) is False
        assert calls == 10
        inactive = mgr.get_inactive()
        assert inactive.health_status == "unhealthy"
        assert inactive.state == EnvironmentState.INACTIVE

    def test_negative_interval_does_not_raise(self, monkeypatch: pytest.MonkeyPatch) -> None:
        clock = _FakeClock()
        monkeypatch.setattr("agent_sre.delivery.blue_green.time", clock)

        def failing_check() -> bool:
            clock.now += 1
            return False

        mgr = BlueGreenManager(
            config=BlueGreenConfig(
                health_check_interval_seconds=-1,
                validation_timeout_seconds=3,
            )
        )
        mgr.deploy("v2.0.0")

        assert mgr.validate(failing_check) is False
        assert mgr.get_inactive().state == EnvironmentState.INACTIVE


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
