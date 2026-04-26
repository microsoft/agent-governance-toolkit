# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""Comprehensive tests for agent-lightning governance integration (#492).

Covers GovernedRunner, PolicyReward, RewardConfig, GovernedEnvironment,
and FlightRecorderEmitter with 50+ test cases.
"""

from __future__ import annotations

import asyncio
import json
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from agent_lightning_gov.emitter import (
    FlightRecorderEmitter,
    LightningSpan,
    create_emitter,
)
from agent_lightning_gov.environment import (
    EnvironmentConfig,
    EnvironmentState,
    GovernedEnvironment,
    create_governed_env,
)
from agent_lightning_gov.reward import (
    CompositeReward,
    PolicyReward,
    RewardConfig,
    create_policy_reward,
    policy_penalty,
)
from agent_lightning_gov.runner import (
    GovernedRollout,
    GovernedRunner,
    PolicyViolation,
    PolicyViolationError,
    PolicyViolationType,
)

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_mock_kernel(**overrides: Any) -> MagicMock:
    """Create a mock kernel suitable for most tests."""
    kernel = MagicMock(spec=[
        "execute", "reset", "policies", "on_policy_violation", "on_signal",
    ])
    kernel.execute = MagicMock(return_value="result")
    kernel.reset = MagicMock()
    kernel.policies = []
    for k, v in overrides.items():
        setattr(kernel, k, v)
    return kernel


@dataclass
class _FakeViolation:
    severity: str = "medium"


@dataclass
class _FakeRollout:
    success: bool = True
    task_output: Any = "out"
    violations: list = field(default_factory=list)


@dataclass
class _FakeEntry:
    type: str = "policy_check"
    id: str = "e1"
    timestamp: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    agent_id: str = "agent-1"
    policy_name: str = "SQLPolicy"
    result: str = "deny"
    violated: bool = True


# ===================================================================
# GovernedRunner
# ===================================================================


class TestGovernedRunnerInit:
    def test_create_with_mock_kernel(self):
        kernel = _make_mock_kernel()
        runner = GovernedRunner(kernel)
        assert runner.kernel is kernel
        assert runner._total_violations == 0
        assert runner._total_rollouts == 0

    def test_defaults(self):
        runner = GovernedRunner(_make_mock_kernel())
        assert runner.fail_on_violation is False
        assert runner.log_violations is True
        assert runner.violation_callback is None

    def test_custom_flags(self):
        cb = MagicMock()
        runner = GovernedRunner(
            _make_mock_kernel(),
            fail_on_violation=True,
            log_violations=False,
            violation_callback=cb,
        )
        assert runner.fail_on_violation is True
        assert runner.log_violations is False
        assert runner.violation_callback is cb


class TestGovernedRunnerStep:
    @pytest.fixture()
    def runner(self):
        kernel = _make_mock_kernel()
        r = GovernedRunner(kernel)
        r.agent = AsyncMock(return_value="agent-result")
        return r

    def test_step_allowed_action(self, runner):
        rollout = asyncio.run(runner.step("do something safe"))
        assert isinstance(rollout, GovernedRollout)
        assert rollout.success is True
        assert rollout.task_input == "do something safe"
        assert rollout.violations == []

    def test_step_denied_action_records_violation(self, runner):
        runner._handle_violation("SQLPolicy", "DROP TABLE", "critical", True)
        assert runner._total_violations == 1
        assert len(runner._current_violations) == 1
        assert runner._current_violations[0].violation_type == PolicyViolationType.BLOCKED

    def test_step_warned_action(self, runner):
        runner._handle_violation("CostPolicy", "high cost", "medium", False)
        v = runner._current_violations[0]
        assert v.violation_type == PolicyViolationType.WARNED
        assert v.action_blocked is False

    def test_step_fail_on_violation_raises(self):
        kernel = _make_mock_kernel()
        runner = GovernedRunner(kernel, fail_on_violation=True)
        with pytest.raises(PolicyViolationError):
            runner._handle_violation("P", "desc", "critical", True)


class TestGovernedRunnerViolationTracking:
    def test_violation_count_increments(self):
        runner = GovernedRunner(_make_mock_kernel())
        for i in range(5):
            runner._handle_violation("P", f"v{i}", "low", False)
        assert runner._total_violations == 5

    def test_clear_current_state(self):
        runner = GovernedRunner(_make_mock_kernel())
        runner._handle_violation("P", "v", "low", False)
        runner._handle_signal("SIGSTOP", "a1")
        runner._clear_current_state()
        assert runner._current_violations == []
        assert runner._current_signals == []


class TestGovernedRunnerCallbacks:
    def test_violation_callback_invoked(self):
        cb = MagicMock()
        runner = GovernedRunner(_make_mock_kernel(), violation_callback=cb)
        runner._handle_violation("P", "d", "high", True)
        cb.assert_called_once()
        assert isinstance(cb.call_args[0][0], PolicyViolation)

    def test_callback_not_invoked_when_none(self):
        runner = GovernedRunner(_make_mock_kernel())
        runner._handle_violation("P", "d", "high", True)  # should not raise


class TestGovernedRunnerStats:
    def test_get_stats_initial(self):
        runner = GovernedRunner(_make_mock_kernel())
        stats = runner.get_stats()
        assert stats["total_rollouts"] == 0
        assert stats["total_violations"] == 0
        assert stats["violation_rate"] == 0.0

    def test_violation_rate(self):
        runner = GovernedRunner(_make_mock_kernel())
        runner._total_rollouts = 10
        runner._total_violations = 3
        assert runner.get_violation_rate() == pytest.approx(0.3)


class TestGovernedRunnerLifecycle:
    def test_init_worker(self):
        runner = GovernedRunner(_make_mock_kernel())
        store = MagicMock()
        runner.init_worker(42, store)
        assert runner.worker_id == 42
        assert runner.store is store

    def test_teardown_worker(self):
        runner = GovernedRunner(_make_mock_kernel())
        runner.teardown_worker(1)  # should not raise

    def test_teardown(self):
        runner = GovernedRunner(_make_mock_kernel())
        runner.teardown()  # should not raise


# ===================================================================
# PolicyViolation / GovernedRollout data-classes
# ===================================================================


class TestPolicyViolation:
    def test_severity_penalty_critical(self):
        v = PolicyViolation(
            PolicyViolationType.BLOCKED, "P", "d", "critical"
        )
        assert v.penalty == 100.0

    def test_severity_penalty_high(self):
        v = PolicyViolation(PolicyViolationType.BLOCKED, "P", "d", "high")
        assert v.penalty == 50.0

    def test_severity_penalty_medium(self):
        v = PolicyViolation(PolicyViolationType.WARNED, "P", "d", "medium")
        assert v.penalty == 10.0

    def test_severity_penalty_low(self):
        v = PolicyViolation(PolicyViolationType.WARNED, "P", "d", "low")
        assert v.penalty == 1.0

    def test_unknown_severity_defaults(self):
        v = PolicyViolation(PolicyViolationType.WARNED, "P", "d", "unknown")
        assert v.penalty == 10.0


class TestGovernedRollout:
    def test_total_penalty_calculated(self):
        violations = [
            PolicyViolation(PolicyViolationType.BLOCKED, "A", "d", "critical"),
            PolicyViolation(PolicyViolationType.WARNED, "B", "d", "low"),
        ]
        rollout = GovernedRollout(
            task_input="in", task_output="out", success=True, violations=violations
        )
        assert rollout.total_penalty == 101.0

    def test_empty_violations_zero_penalty(self):
        rollout = GovernedRollout(task_input="in", task_output="out", success=True)
        assert rollout.total_penalty == 0.0


# ===================================================================
# PolicyReward
# ===================================================================


class TestPolicyRewardPenalty:
    def test_penalty_for_violation(self):
        kernel = _make_mock_kernel()
        reward = PolicyReward(kernel)
        rollout = _FakeRollout(violations=[_FakeViolation("high")])
        r = reward(rollout, emit=False)
        # base=1.0, penalty=-50, no clean bonus
        assert r == pytest.approx(-49.0)

    def test_no_penalty_for_clean_action(self):
        kernel = _make_mock_kernel()
        reward = PolicyReward(kernel)
        rollout = _FakeRollout(violations=[])
        r = reward(rollout, emit=False)
        # base=1.0, clean_bonus=5.0
        assert r == pytest.approx(6.0)


class TestPolicyRewardSeverityLevels:
    @pytest.mark.parametrize(
        "severity,expected_penalty",
        [
            ("critical", -100.0),
            ("high", -50.0),
            ("medium", -10.0),
            ("low", -1.0),
        ],
    )
    def test_configurable_penalty_levels(self, severity, expected_penalty):
        kernel = _make_mock_kernel()
        reward = PolicyReward(kernel)
        rollout = _FakeRollout(violations=[_FakeViolation(severity)])
        r = reward(rollout, emit=False)
        # base=1.0, + expected_penalty, no clean bonus
        assert r == pytest.approx(1.0 + expected_penalty)


class TestPolicyRewardCleanBonus:
    def test_clean_bonus_applied(self):
        cfg = RewardConfig(clean_bonus=20.0)
        reward = PolicyReward(_make_mock_kernel(), config=cfg)
        r = reward(_FakeRollout(violations=[]), emit=False)
        assert r == pytest.approx(1.0 + 20.0)

    def test_no_clean_bonus_on_violation(self):
        cfg = RewardConfig(clean_bonus=20.0)
        reward = PolicyReward(_make_mock_kernel(), config=cfg)
        r = reward(_FakeRollout(violations=[_FakeViolation("low")]), emit=False)
        assert r == pytest.approx(1.0 - 1.0)  # no bonus added


class TestPolicyRewardMultiplicative:
    def test_multiplicative_mode(self):
        cfg = RewardConfig(multiplicative=True, multiplicative_factor=0.5)
        reward = PolicyReward(_make_mock_kernel(), config=cfg)
        rollout = _FakeRollout(violations=[_FakeViolation("low")])
        r = reward(rollout, emit=False)
        # multiplicative: base(1.0) * 0.5 = 0.5
        assert r == pytest.approx(0.5)

    def test_multiplicative_no_violations(self):
        cfg = RewardConfig(multiplicative=True, multiplicative_factor=0.5, clean_bonus=5.0)
        reward = PolicyReward(_make_mock_kernel(), config=cfg)
        rollout = _FakeRollout(violations=[])
        r = reward(rollout, emit=False)
        # No violations → additive path: base=1.0 + clean_bonus=5.0
        assert r == pytest.approx(6.0)


class TestPolicyRewardZeroViolations:
    def test_full_reward_on_zero_violations(self):
        cfg = RewardConfig(clean_bonus=0.0, max_reward=None, min_reward=None)
        reward = PolicyReward(_make_mock_kernel(), config=cfg)
        rollout = _FakeRollout(violations=[])
        r = reward(rollout, emit=False)
        assert r == pytest.approx(1.0)


class TestPolicyRewardStats:
    def test_stats_after_calls(self):
        reward = PolicyReward(_make_mock_kernel())
        reward(_FakeRollout(violations=[]), emit=False)
        reward(_FakeRollout(violations=[_FakeViolation()]), emit=False)
        stats = reward.get_stats()
        assert stats["total_rewards"] == 2
        assert stats["clean_rate"] == pytest.approx(0.5)
        assert stats["violation_rate"] == pytest.approx(0.5)

    def test_reset_stats(self):
        reward = PolicyReward(_make_mock_kernel())
        reward(_FakeRollout(violations=[]), emit=False)
        reward.reset_stats()
        assert reward.get_stats()["total_rewards"] == 0


class TestPolicyPenaltyHelper:
    def test_basic_penalty(self):
        assert policy_penalty([_FakeViolation("high")]) == pytest.approx(-50.0)

    def test_empty_list(self):
        assert policy_penalty([]) == 0.0

    def test_custom_penalties(self):
        r = policy_penalty(
            [_FakeViolation("critical")], critical_penalty=-200.0
        )
        assert r == pytest.approx(-200.0)


class TestCreatePolicyReward:
    def test_factory_with_defaults(self):
        pr = create_policy_reward(_make_mock_kernel())
        assert isinstance(pr, PolicyReward)

    def test_factory_custom_severity(self):
        pr = create_policy_reward(
            _make_mock_kernel(),
            severity_penalties={"critical": -500.0},
        )
        assert pr.config.critical_penalty == -500.0


# ===================================================================
# RewardConfig
# ===================================================================


class TestRewardConfig:
    def test_default_values(self):
        cfg = RewardConfig()
        assert cfg.critical_penalty == -100.0
        assert cfg.high_penalty == -50.0
        assert cfg.medium_penalty == -10.0
        assert cfg.low_penalty == -1.0
        assert cfg.clean_bonus == 5.0
        assert cfg.multiplicative is False
        assert cfg.min_reward == -100.0
        assert cfg.max_reward == 100.0

    def test_custom_config(self):
        cfg = RewardConfig(
            critical_penalty=-200.0,
            clean_bonus=10.0,
            multiplicative=True,
            multiplicative_factor=0.3,
        )
        assert cfg.critical_penalty == -200.0
        assert cfg.clean_bonus == 10.0
        assert cfg.multiplicative is True
        assert cfg.multiplicative_factor == 0.3

    def test_penalty_ranges_negative(self):
        cfg = RewardConfig()
        assert cfg.critical_penalty < 0
        assert cfg.high_penalty < 0
        assert cfg.medium_penalty < 0
        assert cfg.low_penalty < 0

    def test_clean_bonus_non_negative(self):
        cfg = RewardConfig()
        assert cfg.clean_bonus >= 0


# ===================================================================
# CompositeReward
# ===================================================================


class TestCompositeReward:
    def test_weighted_sum(self):
        fn1 = lambda r: 10.0
        fn2 = lambda r: 20.0
        comp = CompositeReward([(fn1, 0.5), (fn2, 0.5)])
        assert comp(_FakeRollout()) == pytest.approx(15.0)

    def test_normalize(self):
        fn1 = lambda r: 10.0
        fn2 = lambda r: 20.0
        comp = CompositeReward([(fn1, 2.0), (fn2, 8.0)], normalize=True)
        # weights become 0.2 and 0.8
        assert comp(_FakeRollout()) == pytest.approx(10 * 0.2 + 20 * 0.8)


# ===================================================================
# GovernedEnvironment
# ===================================================================


class TestGovernedEnvironmentReset:
    def test_reset_returns_initial_state(self):
        env = GovernedEnvironment(_make_mock_kernel())
        state, info = env.reset()
        assert state is None  # no task_generator
        assert "episode" in info

    def test_reset_with_task_generator(self):
        env = GovernedEnvironment(
            _make_mock_kernel(),
            task_generator=lambda: "task-1",
        )
        state, info = env.reset()
        assert state == "task-1"

    def test_reset_calls_kernel_reset(self):
        kernel = _make_mock_kernel()
        env = GovernedEnvironment(kernel)
        env.reset()
        kernel.reset.assert_called_once()

    def test_reset_increments_episode_count(self):
        env = GovernedEnvironment(_make_mock_kernel())
        env.reset()
        env.reset()
        assert env._total_episodes == 2


class TestGovernedEnvironmentStep:
    def test_step_with_valid_action(self):
        env = GovernedEnvironment(_make_mock_kernel())
        env.reset()
        state, reward, terminated, truncated, info = env.step("action-1")
        assert info["success"] is True
        assert terminated is False

    def test_step_increments_step_count(self):
        env = GovernedEnvironment(_make_mock_kernel())
        env.reset()
        env.step("a1")
        env.step("a2")
        assert env._state.step_count == 2

    def test_step_policy_violation_termination(self):
        kernel = _make_mock_kernel()

        def trigger_violation(action):
            env._handle_violation("P", "critical action", "critical", True)
            return "result"

        kernel.execute = MagicMock(side_effect=trigger_violation)
        env = GovernedEnvironment(
            kernel, config=EnvironmentConfig(terminate_on_critical=True)
        )
        env.reset()
        _, _, terminated, _, _ = env.step("bad-action")
        assert terminated is True

    def test_step_truncates_at_max_steps(self):
        cfg = EnvironmentConfig(max_steps=2)
        env = GovernedEnvironment(_make_mock_kernel(), config=cfg)
        env.reset()
        env.step("a1")
        _, _, _, truncated, _ = env.step("a2")
        assert truncated is True


class TestGovernedEnvironmentGymInterface:
    def test_terminated_property(self):
        env = GovernedEnvironment(_make_mock_kernel())
        env.reset()
        assert env.terminated is False
        env._state.terminated = True
        assert env.terminated is True

    def test_close(self):
        env = GovernedEnvironment(_make_mock_kernel())
        env.close()  # should not raise


class TestGovernedEnvironmentTaskGenerator:
    def test_task_generator_called_on_reset(self):
        gen = MagicMock(return_value="task-2")
        env = GovernedEnvironment(_make_mock_kernel(), task_generator=gen)
        env.reset()
        gen.assert_called_once()

    def test_different_tasks_per_reset(self):
        counter = {"n": 0}

        def gen():
            counter["n"] += 1
            return f"task-{counter['n']}"

        env = GovernedEnvironment(_make_mock_kernel(), task_generator=gen)
        s1, _ = env.reset()
        s2, _ = env.reset()
        assert s1 == "task-1"
        assert s2 == "task-2"


class TestGovernedEnvironmentMetrics:
    def test_get_metrics_initial(self):
        env = GovernedEnvironment(_make_mock_kernel())
        m = env.get_metrics()
        assert m["total_episodes"] == 0
        assert m["total_steps"] == 0

    def test_get_metrics_after_episode(self):
        env = GovernedEnvironment(_make_mock_kernel())
        env.reset()
        env.step("a1")
        env.step("a2")
        m = env.get_metrics()
        assert m["total_episodes"] == 1
        assert m["total_steps"] == 2


class TestCreateGovernedEnv:
    def test_factory(self):
        env = create_governed_env(_make_mock_kernel(), max_steps=50)
        assert env.config.max_steps == 50


class TestEnvironmentConfig:
    def test_defaults(self):
        cfg = EnvironmentConfig()
        assert cfg.max_steps == 100
        assert cfg.terminate_on_critical is True

    def test_custom(self):
        cfg = EnvironmentConfig(max_steps=200, violation_penalty=-20.0)
        assert cfg.max_steps == 200
        assert cfg.violation_penalty == -20.0


class TestEnvironmentState:
    def test_defaults(self):
        st = EnvironmentState()
        assert st.step_count == 0
        assert st.terminated is False


# ===================================================================
# FlightRecorderEmitter
# ===================================================================


def _make_recorder(entries: list | None = None) -> MagicMock:
    recorder = MagicMock(spec=["entries"])
    recorder.entries = entries or []
    return recorder


class TestFlightRecorderEmitterCreate:
    def test_create_emitter(self):
        recorder = _make_recorder()
        emitter = FlightRecorderEmitter(recorder)
        assert emitter.recorder is recorder
        assert emitter._emitted_count == 0

    def test_create_emitter_factory(self):
        recorder = _make_recorder()
        emitter = create_emitter(recorder, trace_id_prefix="test")
        assert emitter.trace_id_prefix == "test"


class TestFlightRecorderEmitterLogSpan:
    def test_get_spans_converts_entries(self):
        entries = [_FakeEntry()]
        emitter = FlightRecorderEmitter(_make_recorder(entries))
        spans = emitter.get_spans()
        assert len(spans) == 1
        assert isinstance(spans[0], LightningSpan)
        assert spans[0].attributes["agent_os.entry_type"] == "policy_check"

    def test_get_spans_filters_policy_checks(self):
        entries = [_FakeEntry(type="policy_check")]
        emitter = FlightRecorderEmitter(
            _make_recorder(entries), include_policy_checks=False
        )
        spans = emitter.get_spans()
        assert len(spans) == 0

    def test_get_spans_filters_signals(self):
        entries = [_FakeEntry(type="signal")]
        emitter = FlightRecorderEmitter(
            _make_recorder(entries), include_signals=False
        )
        spans = emitter.get_spans()
        assert len(spans) == 0

    def test_get_spans_filters_tool_calls(self):
        entries = [_FakeEntry(type="tool_call")]
        emitter = FlightRecorderEmitter(
            _make_recorder(entries), include_tool_calls=False
        )
        spans = emitter.get_spans()
        assert len(spans) == 0


class TestFlightRecorderEmitterExport:
    def test_emit_to_store(self):
        entries = [_FakeEntry(), _FakeEntry(id="e2")]
        emitter = FlightRecorderEmitter(_make_recorder(entries))
        store = MagicMock()
        count = emitter.emit_to_store(store)
        assert count == 2
        assert store.emit_span.call_count == 2

    def test_emit_to_store_add_span_fallback(self):
        entries = [_FakeEntry()]
        emitter = FlightRecorderEmitter(_make_recorder(entries))
        store = MagicMock(spec=["add_span"])
        count = emitter.emit_to_store(store)
        assert count == 1
        store.add_span.assert_called_once()

    def test_export_to_file(self, tmp_path):
        entries = [_FakeEntry()]
        emitter = FlightRecorderEmitter(_make_recorder(entries))
        fp = str(tmp_path / "spans.json")
        count = emitter.export_to_file(fp)
        assert count == 1
        with open(fp) as f:
            data = json.load(f)
        assert len(data) == 1
        assert data[0]["span_id"] == "e1"


class TestFlightRecorderEmitterViolationSummary:
    def test_violation_summary(self):
        entries = [
            _FakeEntry(violated=True, policy_name="SQLPolicy"),
            _FakeEntry(id="e2", violated=False, policy_name="CostPolicy"),
        ]
        emitter = FlightRecorderEmitter(_make_recorder(entries))
        summary = emitter.get_violation_summary()
        assert summary["total_entries"] == 2
        assert summary["total_violations"] == 1
        assert "SQLPolicy" in summary["policies_violated"]

    def test_violation_summary_empty(self):
        emitter = FlightRecorderEmitter(_make_recorder([]))
        summary = emitter.get_violation_summary()
        assert summary["total_violations"] == 0
        assert summary["violation_rate"] == 0.0


class TestFlightRecorderEmitterStreaming:
    def test_get_new_spans_incremental(self):
        entries = [_FakeEntry(), _FakeEntry(id="e2")]
        recorder = _make_recorder(entries)
        emitter = FlightRecorderEmitter(recorder)

        first = emitter.get_new_spans()
        assert len(first) == 2

        # No new entries → empty
        second = emitter.get_new_spans()
        assert len(second) == 0

    def test_stats(self):
        entries = [_FakeEntry()]
        emitter = FlightRecorderEmitter(_make_recorder(entries))
        emitter.get_spans()
        stats = emitter.get_stats()
        assert stats["emitted_count"] == 1


class TestLightningSpan:
    def test_to_dict(self):
        span = LightningSpan(
            span_id="s1",
            trace_id="t1",
            name="test",
            start_time=datetime(2024, 1, 1, tzinfo=timezone.utc),
        )
        d = span.to_dict()
        assert d["span_id"] == "s1"
        assert d["end_time"] is None

    def test_to_json(self):
        span = LightningSpan(
            span_id="s1",
            trace_id="t1",
            name="test",
            start_time=datetime(2024, 1, 1, tzinfo=timezone.utc),
        )
        j = span.to_json()
        assert isinstance(j, str)
        parsed = json.loads(j)
        assert parsed["trace_id"] == "t1"
