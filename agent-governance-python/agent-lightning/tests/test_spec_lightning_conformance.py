# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""
Conformance tests for AGENT-LIGHTNING-GOVERNANCE-1.0.

Every test references a specific section of the specification.
Tests marked [Pure Specification] verify normative requirements.
Tests marked [Default Implementation] verify reference defaults.
"""

from __future__ import annotations

import json
import unittest
from dataclasses import fields
from datetime import datetime, timezone
from unittest.mock import MagicMock

# ---------------------------------------------------------------------------
# Imports under test
# ---------------------------------------------------------------------------

from agent_lightning_gov.runner import (
    GovernedRollout,
    GovernedRunner,
    PolicyViolation,
    PolicyViolationError,
    PolicyViolationType,
)
from agent_lightning_gov.reward import (
    CompositeReward,
    PolicyReward,
    RewardConfig,
    policy_penalty,
)
from agent_lightning_gov.environment import (
    EnvironmentConfig,
    EnvironmentState,
    GovernedEnvironment,
)
from agent_lightning_gov.emitter import (
    FlightRecorderEmitter,
    LightningSpan,
)


# ---------------------------------------------------------------------------
# Test helpers
# ---------------------------------------------------------------------------


def _mock_kernel(**overrides):
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


def _make_violation(severity="medium", policy_name="TestPolicy",
                    description="test violation",
                    violation_type=PolicyViolationType.WARNED,
                    action_blocked=False, penalty=None):
    """Create a PolicyViolation for testing."""
    return PolicyViolation(
        violation_type=violation_type,
        policy_name=policy_name,
        description=description,
        severity=severity,
        action_blocked=action_blocked,
        penalty=penalty,
    )


def _make_rollout(success=True, violations=None, task_input="in",
                  task_output="out", signals_sent=None):
    """Create a GovernedRollout for testing."""
    return GovernedRollout(
        task_input=task_input,
        task_output=task_output,
        success=success,
        violations=violations or [],
        signals_sent=signals_sent or [],
    )


# ═══════════════════════════════════════════════════════════════════════════
# Section 4: Policy Violations
# ═══════════════════════════════════════════════════════════════════════════


class TestPolicyViolationType(unittest.TestCase):
    """Spec S4 -- PolicyViolationType enum values."""

    def test_blocked_value(self):
        """S4.1 -- BLOCKED has value 'blocked'."""
        self.assertEqual(PolicyViolationType.BLOCKED.value, "blocked")

    def test_modified_value(self):
        """S4.2 -- MODIFIED has value 'modified'."""
        self.assertEqual(PolicyViolationType.MODIFIED.value, "modified")

    def test_warned_value(self):
        """S4.3 -- WARNED has value 'warned'."""
        self.assertEqual(PolicyViolationType.WARNED.value, "warned")

    def test_signal_sent_value(self):
        """S4.4 -- SIGNAL_SENT has value 'signal_sent'."""
        self.assertEqual(PolicyViolationType.SIGNAL_SENT.value, "signal_sent")

    def test_enum_member_count(self):
        """S4.5 -- Exactly 4 enum members."""
        self.assertEqual(len(PolicyViolationType), 4)


class TestPolicyViolation(unittest.TestCase):
    """Spec S4 -- PolicyViolation dataclass."""

    def test_required_fields(self):
        """S4.6 -- PolicyViolation has all required fields."""
        v = _make_violation()
        self.assertIsInstance(v.violation_type, PolicyViolationType)
        self.assertIsInstance(v.policy_name, str)
        self.assertIsInstance(v.description, str)
        self.assertIsInstance(v.severity, str)
        self.assertIsInstance(v.timestamp, datetime)

    def test_default_action_blocked_false(self):
        """S4.7 -- action_blocked defaults to False."""
        v = _make_violation()
        self.assertFalse(v.action_blocked)

    def test_severity_penalty_critical(self):
        """S4.8 -- critical severity maps to 100.0 penalty."""
        v = _make_violation(severity="critical")
        self.assertEqual(v.penalty, 100.0)

    def test_severity_penalty_high(self):
        """S4.9 -- high severity maps to 50.0 penalty."""
        v = _make_violation(severity="high")
        self.assertEqual(v.penalty, 50.0)

    def test_severity_penalty_medium(self):
        """S4.10 -- medium severity maps to 10.0 penalty."""
        v = _make_violation(severity="medium")
        self.assertEqual(v.penalty, 10.0)

    def test_severity_penalty_low(self):
        """S4.11 -- low severity maps to 1.0 penalty."""
        v = _make_violation(severity="low")
        self.assertEqual(v.penalty, 1.0)

    def test_severity_penalty_unknown_fallback(self):
        """S4.12 -- unknown severity falls back to 10.0."""
        v = _make_violation(severity="unknown_level")
        self.assertEqual(v.penalty, 10.0)

    def test_explicit_penalty_preserved(self):
        """S4.13 -- caller-supplied penalty is NOT overwritten."""
        v = _make_violation(severity="critical", penalty=42.0)
        self.assertEqual(v.penalty, 42.0)

    def test_severity_penalties_dict(self):
        """S4.14 -- SEVERITY_PENALTIES class attribute matches spec."""
        expected = {"critical": 100.0, "high": 50.0, "medium": 10.0, "low": 1.0}
        self.assertEqual(PolicyViolation.SEVERITY_PENALTIES, expected)


# ═══════════════════════════════════════════════════════════════════════════
# Section 5: GovernedRollout
# ═══════════════════════════════════════════════════════════════════════════


class TestGovernedRollout(unittest.TestCase):
    """Spec S5 -- GovernedRollout dataclass."""

    def test_auto_computed_penalty_empty(self):
        """S5.1 -- total_penalty is 0 when no violations."""
        r = _make_rollout()
        self.assertEqual(r.total_penalty, 0.0)

    def test_auto_computed_penalty_single(self):
        """S5.2 -- total_penalty sums single violation penalty."""
        v = _make_violation(severity="high")
        r = _make_rollout(violations=[v])
        self.assertEqual(r.total_penalty, 50.0)

    def test_auto_computed_penalty_multiple(self):
        """S5.3 -- total_penalty sums multiple violation penalties."""
        v1 = _make_violation(severity="critical")
        v2 = _make_violation(severity="low")
        r = _make_rollout(violations=[v1, v2])
        self.assertEqual(r.total_penalty, 101.0)

    def test_default_fields(self):
        """S5.4 -- default violations=[], signals_sent=[], execution_time_ms=0."""
        r = GovernedRollout(task_input="x", task_output="y", success=True)
        self.assertEqual(r.violations, [])
        self.assertEqual(r.signals_sent, [])
        self.assertEqual(r.execution_time_ms, 0.0)

    def test_success_field(self):
        """S5.5 -- success field stored correctly."""
        r_ok = _make_rollout(success=True)
        r_fail = _make_rollout(success=False)
        self.assertTrue(r_ok.success)
        self.assertFalse(r_fail.success)


# ═══════════════════════════════════════════════════════════════════════════
# Section 3: GovernedRunner
# ═══════════════════════════════════════════════════════════════════════════


class TestGovernedRunner(unittest.TestCase):
    """Spec S3 -- GovernedRunner."""

    def test_init_with_kernel(self):
        """S3.1 -- GovernedRunner stores kernel reference."""
        kernel = _mock_kernel()
        runner = GovernedRunner(kernel)
        self.assertIs(runner.kernel, kernel)

    def test_default_fail_on_violation(self):
        """S3.2 -- fail_on_violation defaults to False."""
        runner = GovernedRunner(_mock_kernel())
        self.assertFalse(runner.fail_on_violation)

    def test_default_log_violations(self):
        """S3.3 -- log_violations defaults to True."""
        runner = GovernedRunner(_mock_kernel())
        self.assertTrue(runner.log_violations)

    def test_default_violation_callback_none(self):
        """S3.4 -- violation_callback defaults to None."""
        runner = GovernedRunner(_mock_kernel())
        self.assertIsNone(runner.violation_callback)

    def test_custom_fail_on_violation(self):
        """S3.5 -- fail_on_violation=True is stored."""
        runner = GovernedRunner(_mock_kernel(), fail_on_violation=True)
        self.assertTrue(runner.fail_on_violation)

    def test_violation_callback_stored(self):
        """S3.6 -- violation_callback is stored."""
        cb = MagicMock()
        runner = GovernedRunner(_mock_kernel(), violation_callback=cb)
        self.assertIs(runner.violation_callback, cb)

    def test_get_stats_initial(self):
        """S3.7 -- get_stats returns zeroed counters initially."""
        runner = GovernedRunner(_mock_kernel())
        stats = runner.get_stats()
        self.assertEqual(stats["total_rollouts"], 0)
        self.assertEqual(stats["total_violations"], 0)
        self.assertEqual(stats["violation_rate"], 0.0)

    def test_get_violation_rate_zero_rollouts(self):
        """S3.8 -- get_violation_rate returns 0.0 with no rollouts."""
        runner = GovernedRunner(_mock_kernel())
        self.assertEqual(runner.get_violation_rate(), 0.0)

    def test_handle_violation_increments_total(self):
        """S3.9 -- _handle_violation increments _total_violations."""
        runner = GovernedRunner(_mock_kernel())
        runner._handle_violation("P", "d", "medium", False)
        self.assertEqual(runner._total_violations, 1)

    def test_handle_violation_appends_to_list(self):
        """S3.10 -- _handle_violation appends to _current_violations."""
        runner = GovernedRunner(_mock_kernel())
        runner._handle_violation("P", "d", "medium", False)
        self.assertEqual(len(runner._current_violations), 1)
        self.assertIsInstance(runner._current_violations[0], PolicyViolation)

    def test_violation_callback_invoked(self):
        """S3.11 -- violation_callback is called on violation."""
        cb = MagicMock()
        runner = GovernedRunner(_mock_kernel(), violation_callback=cb)
        runner._handle_violation("P", "d", "low", False)
        cb.assert_called_once()
        self.assertIsInstance(cb.call_args[0][0], PolicyViolation)

    def test_get_stats_keys(self):
        """S3.12 -- get_stats returns dict with required keys."""
        runner = GovernedRunner(_mock_kernel())
        stats = runner.get_stats()
        for key in ("total_rollouts", "total_violations", "violation_rate"):
            self.assertIn(key, stats)


# ═══════════════════════════════════════════════════════════════════════════
# Section 6: RewardConfig & PolicyReward
# ═══════════════════════════════════════════════════════════════════════════


class TestRewardConfig(unittest.TestCase):
    """Spec S6 -- RewardConfig defaults."""

    def test_default_critical_penalty(self):
        """S6.1 -- critical_penalty defaults to -100.0."""
        self.assertEqual(RewardConfig().critical_penalty, -100.0)

    def test_default_high_penalty(self):
        """S6.2 -- high_penalty defaults to -50.0."""
        self.assertEqual(RewardConfig().high_penalty, -50.0)

    def test_default_medium_penalty(self):
        """S6.3 -- medium_penalty defaults to -10.0."""
        self.assertEqual(RewardConfig().medium_penalty, -10.0)

    def test_default_low_penalty(self):
        """S6.4 -- low_penalty defaults to -1.0."""
        self.assertEqual(RewardConfig().low_penalty, -1.0)

    def test_default_clean_bonus(self):
        """S6.5 -- clean_bonus defaults to 5.0."""
        self.assertEqual(RewardConfig().clean_bonus, 5.0)

    def test_default_multiplicative_false(self):
        """S6.6 -- multiplicative defaults to False."""
        self.assertFalse(RewardConfig().multiplicative)

    def test_default_multiplicative_factor(self):
        """S6.7 -- multiplicative_factor defaults to 0.5."""
        self.assertEqual(RewardConfig().multiplicative_factor, 0.5)

    def test_default_min_reward(self):
        """S6.8 -- min_reward defaults to -100.0."""
        self.assertEqual(RewardConfig().min_reward, -100.0)

    def test_default_max_reward(self):
        """S6.9 -- max_reward defaults to 100.0."""
        self.assertEqual(RewardConfig().max_reward, 100.0)


class TestPolicyReward(unittest.TestCase):
    """Spec S6 -- PolicyReward reward shaping."""

    def test_clean_rollout_gets_bonus(self):
        """S6.10 -- clean rollout gets base_reward + clean_bonus."""
        reward_fn = PolicyReward(_mock_kernel())
        rollout = _make_rollout(success=True, violations=[])
        # default base = 1.0 for success, clean_bonus = 5.0
        result = reward_fn(rollout, emit=False)
        self.assertEqual(result, 6.0)

    def test_violation_applies_penalty(self):
        """S6.11 -- violation subtracts penalty from reward."""
        reward_fn = PolicyReward(_mock_kernel())
        v = _make_violation(severity="medium")
        rollout = _make_rollout(success=True, violations=[v])
        # base=1.0, penalty=-10.0 => -9.0
        result = reward_fn(rollout, emit=False)
        self.assertEqual(result, -9.0)

    def test_multiplicative_mode(self):
        """S6.12 -- multiplicative mode multiplies base by factor."""
        config = RewardConfig(multiplicative=True, multiplicative_factor=0.5)
        reward_fn = PolicyReward(_mock_kernel(), config=config)
        v = _make_violation(severity="low")
        rollout = _make_rollout(success=True, violations=[v])
        # base=1.0, multiplicative => 1.0*0.5=0.5 (no clean bonus)
        result = reward_fn(rollout, emit=False)
        self.assertEqual(result, 0.5)

    def test_min_reward_clamp(self):
        """S6.13 -- reward is clamped to min_reward."""
        config = RewardConfig(min_reward=-50.0)
        reward_fn = PolicyReward(_mock_kernel(), config=config)
        v = _make_violation(severity="critical")
        rollout = _make_rollout(success=True, violations=[v])
        result = reward_fn(rollout, emit=False)
        self.assertGreaterEqual(result, -50.0)

    def test_max_reward_clamp(self):
        """S6.14 -- reward is clamped to max_reward."""
        config = RewardConfig(max_reward=3.0)
        reward_fn = PolicyReward(_mock_kernel(), config=config)
        rollout = _make_rollout(success=True, violations=[])
        result = reward_fn(rollout, emit=False)
        self.assertLessEqual(result, 3.0)

    def test_custom_base_reward_fn(self):
        """S6.15 -- custom base_reward_fn is used."""
        reward_fn = PolicyReward(
            _mock_kernel(),
            base_reward_fn=lambda r: 10.0,
        )
        rollout = _make_rollout(success=True, violations=[])
        result = reward_fn(rollout, emit=False)
        # 10.0 + 5.0 clean bonus = 15.0
        self.assertEqual(result, 15.0)

    def test_failed_rollout_base_reward(self):
        """S6.16 -- failed rollout gets base reward 0.0."""
        reward_fn = PolicyReward(_mock_kernel())
        rollout = _make_rollout(success=False, violations=[])
        result = reward_fn(rollout, emit=False)
        # 0.0 + 5.0 clean bonus = 5.0
        self.assertEqual(result, 5.0)


# ═══════════════════════════════════════════════════════════════════════════
# Section 7: policy_penalty function
# ═══════════════════════════════════════════════════════════════════════════


class TestPolicyPenalty(unittest.TestCase):
    """Spec S7 -- policy_penalty helper function."""

    def test_empty_violations(self):
        """S7.1 -- no violations returns 0.0."""
        self.assertEqual(policy_penalty([]), 0.0)

    def test_single_critical(self):
        """S7.2 -- single critical violation."""
        v = _make_violation(severity="critical")
        self.assertEqual(policy_penalty([v]), -100.0)

    def test_single_high(self):
        """S7.3 -- single high violation."""
        v = _make_violation(severity="high")
        self.assertEqual(policy_penalty([v]), -50.0)

    def test_single_medium(self):
        """S7.4 -- single medium violation."""
        v = _make_violation(severity="medium")
        self.assertEqual(policy_penalty([v]), -10.0)

    def test_single_low(self):
        """S7.5 -- single low violation."""
        v = _make_violation(severity="low")
        self.assertEqual(policy_penalty([v]), -1.0)

    def test_multiple_violations_sum(self):
        """S7.6 -- multiple violations sum correctly."""
        vs = [_make_violation(severity="critical"), _make_violation(severity="low")]
        self.assertEqual(policy_penalty(vs), -101.0)

    def test_unknown_severity_uses_medium_default(self):
        """S7.7 -- unknown severity falls back to medium_penalty."""
        v = _make_violation(severity="exotic")
        self.assertEqual(policy_penalty([v]), -10.0)

    def test_custom_penalty_values(self):
        """S7.8 -- custom penalty kwargs override defaults."""
        v = _make_violation(severity="critical")
        result = policy_penalty([v], critical_penalty=-200.0)
        self.assertEqual(result, -200.0)


# ═══════════════════════════════════════════════════════════════════════════
# Section 8: CompositeReward
# ═══════════════════════════════════════════════════════════════════════════


class TestCompositeReward(unittest.TestCase):
    """Spec S8 -- CompositeReward weighted components."""

    def test_single_component(self):
        """S8.1 -- single component returns weighted value."""
        cr = CompositeReward([(lambda r: 10.0, 1.0)])
        self.assertEqual(cr(_make_rollout()), 10.0)

    def test_two_components_weighted(self):
        """S8.2 -- two components with different weights."""
        cr = CompositeReward([
            (lambda r: 10.0, 1.0),
            (lambda r: 20.0, 0.5),
        ])
        # 10*1.0 + 20*0.5 = 20.0
        self.assertEqual(cr(_make_rollout()), 20.0)

    def test_normalize_weights(self):
        """S8.3 -- normalize=True normalizes weights to sum to 1."""
        cr = CompositeReward(
            [(lambda r: 10.0, 2.0), (lambda r: 20.0, 2.0)],
            normalize=True,
        )
        # weights become 0.5 each: 10*0.5 + 20*0.5 = 15.0
        self.assertEqual(cr(_make_rollout()), 15.0)

    def test_zero_weight_component(self):
        """S8.4 -- zero-weight component contributes nothing."""
        cr = CompositeReward([
            (lambda r: 100.0, 0.0),
            (lambda r: 5.0, 1.0),
        ])
        self.assertEqual(cr(_make_rollout()), 5.0)


# ═══════════════════════════════════════════════════════════════════════════
# Section 9: EnvironmentConfig & GovernedEnvironment
# ═══════════════════════════════════════════════════════════════════════════


class TestEnvironmentConfig(unittest.TestCase):
    """Spec S9 -- EnvironmentConfig defaults."""

    def test_default_max_steps(self):
        """S9.1 -- max_steps defaults to 100."""
        self.assertEqual(EnvironmentConfig().max_steps, 100)

    def test_default_violation_penalty(self):
        """S9.2 -- violation_penalty defaults to -10.0."""
        self.assertEqual(EnvironmentConfig().violation_penalty, -10.0)

    def test_default_terminate_on_critical(self):
        """S9.3 -- terminate_on_critical defaults to True."""
        self.assertTrue(EnvironmentConfig().terminate_on_critical)

    def test_default_step_penalty(self):
        """S9.4 -- step_penalty defaults to -0.1."""
        self.assertEqual(EnvironmentConfig().step_penalty, -0.1)

    def test_default_success_bonus(self):
        """S9.5 -- success_bonus defaults to 10.0."""
        self.assertEqual(EnvironmentConfig().success_bonus, 10.0)

    def test_default_reset_kernel_state(self):
        """S9.6 -- reset_kernel_state defaults to True."""
        self.assertTrue(EnvironmentConfig().reset_kernel_state)


# ═══════════════════════════════════════════════════════════════════════════
# Section 10: EnvironmentState
# ═══════════════════════════════════════════════════════════════════════════


class TestEnvironmentState(unittest.TestCase):
    """Spec S10 -- EnvironmentState dataclass defaults."""

    def test_default_step_count(self):
        """S10.1 -- step_count defaults to 0."""
        self.assertEqual(EnvironmentState().step_count, 0)

    def test_default_total_reward(self):
        """S10.2 -- total_reward defaults to 0.0."""
        self.assertEqual(EnvironmentState().total_reward, 0.0)

    def test_default_violations_empty(self):
        """S10.3 -- violations defaults to empty list."""
        self.assertEqual(EnvironmentState().violations, [])

    def test_default_terminated_false(self):
        """S10.4 -- terminated defaults to False."""
        self.assertFalse(EnvironmentState().terminated)

    def test_default_truncated_false(self):
        """S10.5 -- truncated defaults to False."""
        self.assertFalse(EnvironmentState().truncated)

    def test_default_info_empty(self):
        """S10.6 -- info defaults to empty dict."""
        self.assertEqual(EnvironmentState().info, {})


class TestGovernedEnvironment(unittest.TestCase):
    """Spec S9 -- GovernedEnvironment reset/step lifecycle."""

    def test_reset_returns_tuple(self):
        """S9.7 -- reset returns (state, info) tuple."""
        env = GovernedEnvironment(_mock_kernel())
        result = env.reset()
        self.assertIsInstance(result, tuple)
        self.assertEqual(len(result), 2)

    def test_reset_info_has_episode(self):
        """S9.8 -- reset info dict contains 'episode' key."""
        env = GovernedEnvironment(_mock_kernel())
        _, info = env.reset()
        self.assertIn("episode", info)

    def test_reset_increments_episode(self):
        """S9.9 -- each reset increments episode count."""
        env = GovernedEnvironment(_mock_kernel())
        _, info1 = env.reset()
        _, info2 = env.reset()
        self.assertEqual(info2["episode"], info1["episode"] + 1)

    def test_step_returns_five_tuple(self):
        """S9.10 -- step returns (state, reward, terminated, truncated, info)."""
        env = GovernedEnvironment(_mock_kernel())
        env.reset()
        result = env.step("action")
        self.assertIsInstance(result, tuple)
        self.assertEqual(len(result), 5)

    def test_terminate_on_critical_violation(self):
        """S9.11 -- critical violation terminates episode."""
        kernel = _mock_kernel()
        # Wire kernel.execute to trigger a critical violation via the env hook
        def _exec_with_violation(action):
            env._handle_violation("P", "critical fail", "critical", True)
            return "result"
        kernel.execute = _exec_with_violation
        env = GovernedEnvironment(kernel, config=EnvironmentConfig(terminate_on_critical=True))
        env.reset()
        _, _, terminated, _, _ = env.step("action")
        self.assertTrue(terminated)

    def test_max_steps_truncation(self):
        """S9.12 -- exceeding max_steps sets truncated=True."""
        kernel = _mock_kernel()
        config = EnvironmentConfig(max_steps=2)
        env = GovernedEnvironment(kernel, config=config)
        env.reset()
        env.step("a1")
        _, _, _, truncated, _ = env.step("a2")
        self.assertTrue(truncated)

    def test_terminated_property(self):
        """S9.13 -- terminated property reflects state."""
        env = GovernedEnvironment(_mock_kernel())
        env.reset()
        self.assertFalse(env.terminated)

    def test_get_metrics_keys(self):
        """S9.14 -- get_metrics returns required keys."""
        env = GovernedEnvironment(_mock_kernel())
        metrics = env.get_metrics()
        for key in ("total_episodes", "total_steps", "total_violations",
                     "successful_episodes", "success_rate",
                     "violations_per_episode", "steps_per_episode"):
            self.assertIn(key, metrics)

    def test_close_does_not_raise(self):
        """S9.15 -- close() completes without error."""
        env = GovernedEnvironment(_mock_kernel())
        env.close()

    def test_task_generator_used_on_reset(self):
        """S9.16 -- task_generator is called on reset."""
        gen = MagicMock(return_value="task_1")
        env = GovernedEnvironment(_mock_kernel(), task_generator=gen)
        state, _ = env.reset()
        gen.assert_called_once()
        self.assertEqual(state, "task_1")

    def test_custom_reward_fn(self):
        """S9.17 -- custom reward_fn is used in step."""
        custom_reward = MagicMock(return_value=42.0)
        env = GovernedEnvironment(_mock_kernel(), reward_fn=custom_reward)
        env.reset()
        _, reward, _, _, _ = env.step("action")
        custom_reward.assert_called_once()
        # reward includes step_penalty(-0.1) + success_bonus(10.0)
        self.assertAlmostEqual(reward, 42.0 + (-0.1) + 10.0, places=5)


# ═══════════════════════════════════════════════════════════════════════════
# Section 11: LightningSpan & FlightRecorderEmitter
# ═══════════════════════════════════════════════════════════════════════════


class TestLightningSpan(unittest.TestCase):
    """Spec S11 -- LightningSpan serialization."""

    def _make_span(self):
        now = datetime(2024, 1, 1, tzinfo=timezone.utc)
        return LightningSpan(
            span_id="s1",
            trace_id="t1",
            name="test_span",
            start_time=now,
            end_time=now,
            attributes={"key": "value"},
            events=[{"name": "evt"}],
        )

    def test_to_dict_keys(self):
        """S11.1 -- to_dict has required keys."""
        d = self._make_span().to_dict()
        for key in ("span_id", "trace_id", "name", "start_time",
                     "end_time", "attributes", "events"):
            self.assertIn(key, d)

    def test_to_dict_values(self):
        """S11.2 -- to_dict values match fields."""
        span = self._make_span()
        d = span.to_dict()
        self.assertEqual(d["span_id"], "s1")
        self.assertEqual(d["trace_id"], "t1")
        self.assertEqual(d["name"], "test_span")

    def test_to_dict_start_time_iso(self):
        """S11.3 -- start_time is serialized as ISO string."""
        d = self._make_span().to_dict()
        self.assertIsInstance(d["start_time"], str)
        self.assertIn("2024-01-01", d["start_time"])

    def test_to_dict_end_time_none(self):
        """S11.4 -- end_time=None serializes to None."""
        span = LightningSpan(
            span_id="s1", trace_id="t1", name="n",
            start_time=datetime.now(timezone.utc),
        )
        d = span.to_dict()
        self.assertIsNone(d["end_time"])

    def test_to_json_returns_string(self):
        """S11.5 -- to_json returns valid JSON string."""
        j = self._make_span().to_json()
        self.assertIsInstance(j, str)
        parsed = json.loads(j)
        self.assertEqual(parsed["span_id"], "s1")

    def test_default_attributes_empty(self):
        """S11.6 -- default attributes is empty dict."""
        span = LightningSpan(
            span_id="s1", trace_id="t1", name="n",
            start_time=datetime.now(timezone.utc),
        )
        self.assertEqual(span.attributes, {})

    def test_default_events_empty(self):
        """S11.7 -- default events is empty list."""
        span = LightningSpan(
            span_id="s1", trace_id="t1", name="n",
            start_time=datetime.now(timezone.utc),
        )
        self.assertEqual(span.events, [])


class TestFlightRecorderEmitter(unittest.TestCase):
    """Spec S11 -- FlightRecorderEmitter."""

    def test_creation_defaults(self):
        """S11.8 -- default flags: include_policy_checks/signals/tool_calls=True."""
        recorder = MagicMock()
        recorder.get_entries = MagicMock(return_value=[])
        emitter = FlightRecorderEmitter(recorder)
        self.assertTrue(emitter.include_policy_checks)
        self.assertTrue(emitter.include_signals)
        self.assertTrue(emitter.include_tool_calls)

    def test_default_trace_id_prefix(self):
        """S11.9 -- default trace_id_prefix is 'agentos'."""
        recorder = MagicMock()
        emitter = FlightRecorderEmitter(recorder)
        self.assertEqual(emitter.trace_id_prefix, "agentos")

    def test_get_stats_initial(self):
        """S11.10 -- get_stats returns zeroed counters initially."""
        recorder = MagicMock()
        emitter = FlightRecorderEmitter(recorder)
        stats = emitter.get_stats()
        self.assertEqual(stats["emitted_count"], 0)
        self.assertEqual(stats["last_position"], 0)

    def test_get_spans_empty_recorder(self):
        """S11.11 -- get_spans returns empty list for empty recorder."""
        recorder = MagicMock()
        recorder.get_entries = MagicMock(return_value=[])
        emitter = FlightRecorderEmitter(recorder)
        self.assertEqual(emitter.get_spans(), [])

    def test_get_new_spans_incremental(self):
        """S11.12 -- get_new_spans only returns new entries."""
        recorder = MagicMock()
        entry = MagicMock()
        entry.type = "policy_check"
        entry.id = "e1"
        entry.timestamp = datetime.now(timezone.utc)
        entry.agent_id = "a1"
        entry.policy_name = "P"
        entry.result = "deny"
        entry.violated = True
        recorder.get_entries = MagicMock(return_value=[entry])
        emitter = FlightRecorderEmitter(recorder)
        first = emitter.get_new_spans()
        self.assertEqual(len(first), 1)
        second = emitter.get_new_spans()
        self.assertEqual(len(second), 0)


# ═══════════════════════════════════════════════════════════════════════════
# Section 16: Failure Semantics
# ═══════════════════════════════════════════════════════════════════════════


class TestFailureSemantics(unittest.TestCase):
    """Spec S16 -- PolicyViolationError and fail_on_violation."""

    def test_policy_violation_error_is_exception(self):
        """S16.1 -- PolicyViolationError is an Exception subclass."""
        self.assertTrue(issubclass(PolicyViolationError, Exception))

    def test_policy_violation_error_stores_violation(self):
        """S16.2 -- PolicyViolationError.violation stores the violation."""
        v = _make_violation(severity="critical")
        err = PolicyViolationError(v)
        self.assertIs(err.violation, v)

    def test_policy_violation_error_message(self):
        """S16.3 -- PolicyViolationError message includes description."""
        v = _make_violation(description="bad action")
        err = PolicyViolationError(v)
        self.assertIn("bad action", str(err))

    def test_fail_on_violation_raises_on_blocked(self):
        """S16.4 -- fail_on_violation=True raises on blocked violation."""
        runner = GovernedRunner(_mock_kernel(), fail_on_violation=True)
        with self.assertRaises(PolicyViolationError):
            runner._handle_violation("P", "blocked action", "critical", blocked=True)

    def test_fail_on_violation_no_raise_on_warn(self):
        """S16.5 -- fail_on_violation=True does NOT raise on non-blocked."""
        runner = GovernedRunner(_mock_kernel(), fail_on_violation=True)
        # Should not raise
        runner._handle_violation("P", "warned action", "medium", blocked=False)

    def test_fail_on_violation_false_no_raise(self):
        """S16.6 -- fail_on_violation=False never raises."""
        runner = GovernedRunner(_mock_kernel(), fail_on_violation=False)
        runner._handle_violation("P", "blocked action", "critical", blocked=True)


if __name__ == "__main__":
    unittest.main()
