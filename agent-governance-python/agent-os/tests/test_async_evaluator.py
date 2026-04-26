# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""Tests for the async-safe and thread-safe policy evaluator.

Validates concurrency guarantees including:
* asyncio coroutine safety
* threading safety via ThreadPoolExecutor
* read-write lock correctness under concurrent load
* batch evaluation
* policy reload under concurrent reads
* statistics tracking
* error handling in concurrent scenarios
"""

from __future__ import annotations

import asyncio
import tempfile
import textwrap
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from typing import Any
from unittest.mock import MagicMock, patch

import pytest

from agent_os.policies.async_evaluator import (
    AsyncPolicyEvaluator,
    ConcurrencyStats,
    _ReadWriteLock,
)
from agent_os.policies.evaluator import PolicyDecision, PolicyEvaluator
from agent_os.policies.schema import (
    PolicyAction,
    PolicyCondition,
    PolicyDefaults,
    PolicyDocument,
    PolicyOperator,
    PolicyRule,
)


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


def _make_policy_doc(
    name: str = "test-policy",
    default_action: PolicyAction = PolicyAction.ALLOW,
) -> PolicyDocument:
    """Create a minimal policy document with two rules."""
    return PolicyDocument(
        version="1.0",
        name=name,
        description="Test policy for async evaluator",
        rules=[
            PolicyRule(
                name="deny_high_tokens",
                condition=PolicyCondition(
                    field="token_count",
                    operator=PolicyOperator.GT,
                    value=1000,
                ),
                action=PolicyAction.DENY,
                priority=100,
                message="Token count exceeds limit",
            ),
            PolicyRule(
                name="allow_safe_tool",
                condition=PolicyCondition(
                    field="tool_name",
                    operator=PolicyOperator.EQ,
                    value="read_file",
                ),
                action=PolicyAction.ALLOW,
                priority=50,
                message="Safe tool allowed",
            ),
        ],
        defaults=PolicyDefaults(action=default_action),
    )


@pytest.fixture()
def evaluator() -> PolicyEvaluator:
    """A synchronous evaluator loaded with a test policy."""
    return PolicyEvaluator(policies=[_make_policy_doc()])


@pytest.fixture()
def async_evaluator(evaluator: PolicyEvaluator) -> AsyncPolicyEvaluator:
    """An async evaluator wrapping the synchronous evaluator."""
    return AsyncPolicyEvaluator(evaluator)


# ---------------------------------------------------------------------------
# ConcurrencyStats unit tests
# ---------------------------------------------------------------------------


class TestConcurrencyStats:
    def test_defaults(self):
        stats = ConcurrencyStats()
        assert stats.evaluation_count == 0
        assert stats.total_evaluation_time == 0.0
        assert stats.error_count == 0
        assert stats.reload_count == 0
        assert stats.concurrent_peak == 0

    def test_average_evaluation_time_zero_division(self):
        stats = ConcurrencyStats()
        assert stats.average_evaluation_time == 0.0

    def test_average_evaluation_time(self):
        stats = ConcurrencyStats(evaluation_count=4, total_evaluation_time=2.0)
        assert stats.average_evaluation_time == 0.5

    def test_as_dict(self):
        stats = ConcurrencyStats(
            evaluation_count=10,
            total_evaluation_time=1.5,
            error_count=1,
            reload_count=2,
            concurrent_peak=3,
        )
        d = stats.as_dict()
        assert d["evaluation_count"] == 10
        assert d["average_evaluation_time"] == 0.15
        assert d["error_count"] == 1
        assert d["reload_count"] == 2
        assert d["concurrent_peak"] == 3


# ---------------------------------------------------------------------------
# ReadWriteLock unit tests
# ---------------------------------------------------------------------------


class TestReadWriteLock:
    def test_multiple_readers(self):
        """Multiple readers can hold the lock concurrently."""
        rw = _ReadWriteLock()
        rw.acquire_read()
        rw.acquire_read()  # second reader — should not deadlock
        rw.release_read()
        rw.release_read()

    def test_writer_excludes_readers(self):
        """A writer blocks new readers until it releases."""
        rw = _ReadWriteLock()
        rw.acquire_write()
        # Attempting to acquire read in a separate thread should block.
        acquired = []

        def try_read():
            rw.acquire_read()
            acquired.append(True)
            rw.release_read()

        import threading

        t = threading.Thread(target=try_read)
        t.start()
        t.join(timeout=0.1)
        # Thread should still be blocked
        assert acquired == []
        rw.release_write()
        t.join(timeout=1.0)
        assert acquired == [True]


# ---------------------------------------------------------------------------
# Basic async evaluation
# ---------------------------------------------------------------------------


class TestAsyncEvaluate:
    async def test_evaluate_allow_default(self, async_evaluator):
        """Evaluating a benign context returns the default allow."""
        result = await async_evaluator.evaluate({"some_field": "value"})
        assert isinstance(result, PolicyDecision)
        assert result.allowed is True
        assert result.action == "allow"

    async def test_evaluate_deny_rule(self, async_evaluator):
        """A high token count triggers the deny rule."""
        result = await async_evaluator.evaluate({"token_count": 5000})
        assert result.allowed is False
        assert result.matched_rule == "deny_high_tokens"
        assert result.action == "deny"

    async def test_evaluate_allow_rule(self, async_evaluator):
        """A safe tool triggers the explicit allow rule."""
        result = await async_evaluator.evaluate({"tool_name": "read_file"})
        assert result.allowed is True
        assert result.matched_rule == "allow_safe_tool"

    async def test_evaluator_property(self, async_evaluator, evaluator):
        """The ``evaluator`` property exposes the wrapped evaluator."""
        assert async_evaluator.evaluator is evaluator


# ---------------------------------------------------------------------------
# Thread-safe synchronous evaluation
# ---------------------------------------------------------------------------


class TestEvaluateSync:
    def test_sync_evaluate_allow(self, async_evaluator):
        result = async_evaluator.evaluate_sync({"tool_name": "read_file"})
        assert result.allowed is True
        assert result.matched_rule == "allow_safe_tool"

    def test_sync_evaluate_deny(self, async_evaluator):
        result = async_evaluator.evaluate_sync({"token_count": 9999})
        assert result.allowed is False

    def test_thread_pool_safety(self, async_evaluator):
        """10+ threads evaluating simultaneously produce correct results."""
        contexts = [{"token_count": i} for i in range(2000, 2020)]
        with ThreadPoolExecutor(max_workers=12) as pool:
            futures = [
                pool.submit(async_evaluator.evaluate_sync, ctx)
                for ctx in contexts
            ]
            results = [f.result(timeout=5) for f in futures]

        # All should be denied (token_count > 1000 for every context)
        assert len(results) == 20
        for r in results:
            assert r.allowed is False
            assert r.matched_rule == "deny_high_tokens"

    def test_thread_pool_mixed(self, async_evaluator):
        """Threads with mixed allow/deny contexts all return correctly."""
        allow_ctx = {"tool_name": "read_file"}
        deny_ctx = {"token_count": 5000}

        with ThreadPoolExecutor(max_workers=10) as pool:
            futures_allow = [
                pool.submit(async_evaluator.evaluate_sync, allow_ctx)
                for _ in range(10)
            ]
            futures_deny = [
                pool.submit(async_evaluator.evaluate_sync, deny_ctx)
                for _ in range(10)
            ]

        for f in futures_allow:
            assert f.result(timeout=5).allowed is True
        for f in futures_deny:
            assert f.result(timeout=5).allowed is False


# ---------------------------------------------------------------------------
# Asyncio concurrent evaluation
# ---------------------------------------------------------------------------


class TestAsyncConcurrency:
    async def test_many_concurrent_evaluations(self, async_evaluator):
        """50+ concurrent async tasks produce correct results."""
        contexts = [{"token_count": 2000 + i} for i in range(60)]
        tasks = [async_evaluator.evaluate(ctx) for ctx in contexts]
        results = await asyncio.gather(*tasks)

        assert len(results) == 60
        for r in results:
            assert r.allowed is False
            assert r.matched_rule == "deny_high_tokens"

    async def test_concurrent_mixed_decisions(self, async_evaluator):
        """Concurrent tasks with different outcomes resolve correctly."""
        allow_ctx = {"tool_name": "read_file"}
        deny_ctx = {"token_count": 5000}
        default_ctx = {"unrelated": 42}

        tasks = (
            [async_evaluator.evaluate(allow_ctx) for _ in range(20)]
            + [async_evaluator.evaluate(deny_ctx) for _ in range(20)]
            + [async_evaluator.evaluate(default_ctx) for _ in range(10)]
        )
        results = await asyncio.gather(*tasks)

        allows = [r for r in results if r.matched_rule == "allow_safe_tool"]
        denies = [r for r in results if r.matched_rule == "deny_high_tokens"]
        defaults = [r for r in results if r.matched_rule is None]

        assert len(allows) == 20
        assert len(denies) == 20
        assert len(defaults) == 10
        assert all(r.allowed for r in allows)
        assert all(not r.allowed for r in denies)
        assert all(r.allowed for r in defaults)


# ---------------------------------------------------------------------------
# Batch evaluation
# ---------------------------------------------------------------------------


class TestBatchEvaluation:
    async def test_batch_returns_ordered_results(self, async_evaluator):
        """Batch evaluation returns one result per context in order."""
        contexts = [
            {"tool_name": "read_file"},
            {"token_count": 5000},
            {"unrelated": True},
        ]
        results = await async_evaluator.evaluate_batch(contexts)

        assert len(results) == 3
        assert results[0].allowed is True
        assert results[0].matched_rule == "allow_safe_tool"
        assert results[1].allowed is False
        assert results[1].matched_rule == "deny_high_tokens"
        assert results[2].allowed is True
        assert results[2].matched_rule is None

    async def test_batch_empty(self, async_evaluator):
        """Batch evaluation with empty list returns empty list."""
        results = await async_evaluator.evaluate_batch([])
        assert results == []

    async def test_batch_large(self, async_evaluator):
        """Batch evaluation handles 100 items."""
        contexts = [{"token_count": i} for i in range(100)]
        results = await async_evaluator.evaluate_batch(contexts)
        assert len(results) == 100
        # token_count <= 1000 → allow (default); > 1000 → deny
        for i, r in enumerate(results):
            if i > 1000:
                assert r.allowed is False
            # items 0..1000 get default allow (token_count not GT 1000)


# ---------------------------------------------------------------------------
# Policy reload under concurrent reads
# ---------------------------------------------------------------------------


class TestPolicyReload:
    async def test_reload_policies(self, async_evaluator):
        """Reload replaces the policy set."""
        with tempfile.TemporaryDirectory() as tmpdir:
            policy_yaml = textwrap.dedent("""\
                version: "1.0"
                name: reloaded-policy
                description: A freshly reloaded policy
                rules:
                  - name: block_everything
                    condition:
                      field: action
                      operator: eq
                      value: any
                    action: deny
                    priority: 200
                    message: Everything is blocked
                defaults:
                  action: deny
            """)
            Path(tmpdir, "reloaded.yaml").write_text(policy_yaml)
            await async_evaluator.reload_policies(tmpdir)

        # After reload the old "allow_safe_tool" rule is gone
        result = await async_evaluator.evaluate({"tool_name": "read_file"})
        assert result.allowed is False  # default is now deny

        # The new rule matches
        result = await async_evaluator.evaluate({"action": "any"})
        assert result.allowed is False
        assert result.matched_rule == "block_everything"

    async def test_reload_increments_stats(self, async_evaluator):
        """Each reload bumps the reload counter."""
        with tempfile.TemporaryDirectory() as tmpdir:
            Path(tmpdir, "empty.yaml").write_text(
                'version: "1.0"\nname: empty\nrules: []\ndefaults:\n  action: allow\n'
            )
            await async_evaluator.reload_policies(tmpdir)
            await async_evaluator.reload_policies(tmpdir)

        stats = async_evaluator.get_stats()
        assert stats["reload_count"] == 2

    async def test_reload_during_concurrent_reads(self, async_evaluator):
        """Reads complete or wait while a reload is in progress."""
        # Pre-evaluate to confirm baseline
        result = await async_evaluator.evaluate({"tool_name": "read_file"})
        assert result.allowed is True

        # Launch several reads then a reload then more reads
        pre_reads = [
            async_evaluator.evaluate({"tool_name": "read_file"})
            for _ in range(10)
        ]

        with tempfile.TemporaryDirectory() as tmpdir:
            Path(tmpdir, "new.yaml").write_text(
                'version: "1.0"\nname: new\nrules: []\ndefaults:\n  action: deny\n'
            )
            reload_coro = async_evaluator.reload_policies(tmpdir)
            post_reads = [
                async_evaluator.evaluate({"unrelated": True})
                for _ in range(10)
            ]

            # Gather all — some reads may see old or new policies
            all_tasks = pre_reads + [reload_coro] + post_reads
            results = await asyncio.gather(*all_tasks, return_exceptions=True)

        # No exceptions should have been raised
        for r in results:
            assert not isinstance(r, Exception)


# ---------------------------------------------------------------------------
# Statistics tracking
# ---------------------------------------------------------------------------


class TestStatsTracking:
    async def test_evaluation_count(self, async_evaluator):
        """Each evaluation increments the counter."""
        for _ in range(5):
            await async_evaluator.evaluate({"x": 1})

        stats = async_evaluator.get_stats()
        assert stats["evaluation_count"] == 5

    async def test_total_and_average_time(self, async_evaluator):
        """Total and average time are positive after evaluations."""
        await async_evaluator.evaluate({"x": 1})
        stats = async_evaluator.get_stats()
        assert stats["total_evaluation_time"] > 0
        assert stats["average_evaluation_time"] > 0

    def test_sync_evaluation_count(self, async_evaluator):
        """Synchronous evaluations also update stats."""
        async_evaluator.evaluate_sync({"x": 1})
        async_evaluator.evaluate_sync({"x": 2})
        stats = async_evaluator.get_stats()
        assert stats["evaluation_count"] == 2

    async def test_stats_after_batch(self, async_evaluator):
        """Batch evaluation increments count for each context."""
        contexts = [{"x": i} for i in range(7)]
        await async_evaluator.evaluate_batch(contexts)
        stats = async_evaluator.get_stats()
        assert stats["evaluation_count"] == 7

    def test_initial_stats(self, async_evaluator):
        """Fresh evaluator has zeroed stats."""
        stats = async_evaluator.get_stats()
        assert stats["evaluation_count"] == 0
        assert stats["error_count"] == 0
        assert stats["reload_count"] == 0


# ---------------------------------------------------------------------------
# Error handling in concurrent scenarios
# ---------------------------------------------------------------------------


class TestErrorHandling:
    async def test_underlying_evaluator_exception(self):
        """When the underlying evaluator raises, error_count increments."""
        broken_evaluator = PolicyEvaluator(policies=[])
        # Monkey-patch evaluate to raise
        broken_evaluator.evaluate = MagicMock(
            side_effect=RuntimeError("boom")
        )
        async_eval = AsyncPolicyEvaluator(broken_evaluator)

        with pytest.raises(RuntimeError, match="boom"):
            await async_eval.evaluate({"x": 1})

        stats = async_eval.get_stats()
        assert stats["error_count"] == 1
        # evaluation_count still increments (it's in the finally block)
        assert stats["evaluation_count"] == 1

    def test_sync_error_increments_stats(self):
        """Synchronous path also tracks errors."""
        broken_evaluator = PolicyEvaluator(policies=[])
        broken_evaluator.evaluate = MagicMock(
            side_effect=ValueError("sync boom")
        )
        async_eval = AsyncPolicyEvaluator(broken_evaluator)

        with pytest.raises(ValueError, match="sync boom"):
            async_eval.evaluate_sync({"x": 1})

        stats = async_eval.get_stats()
        assert stats["error_count"] == 1

    async def test_error_does_not_poison_lock(self):
        """After an error the evaluator remains usable."""
        evaluator = PolicyEvaluator(policies=[_make_policy_doc()])
        async_eval = AsyncPolicyEvaluator(evaluator)

        call_count = 0
        original_evaluate = evaluator.evaluate

        def flaky_evaluate(ctx):
            nonlocal call_count
            call_count += 1
            if call_count == 1:
                raise RuntimeError("transient failure")
            return original_evaluate(ctx)

        evaluator.evaluate = flaky_evaluate

        # First call fails
        with pytest.raises(RuntimeError, match="transient failure"):
            await async_eval.evaluate({"x": 1})

        # Second call succeeds — lock was properly released
        result = await async_eval.evaluate({"tool_name": "read_file"})
        assert result.allowed is True
        assert result.matched_rule == "allow_safe_tool"

    async def test_concurrent_errors_and_successes(self):
        """Mix of failing and succeeding concurrent tasks."""
        evaluator = PolicyEvaluator(policies=[_make_policy_doc()])
        async_eval = AsyncPolicyEvaluator(evaluator)

        call_count = 0
        original_evaluate = evaluator.evaluate

        def sometimes_fail(ctx):
            nonlocal call_count
            call_count += 1
            if ctx.get("fail"):
                raise RuntimeError("deliberate")
            return original_evaluate(ctx)

        evaluator.evaluate = sometimes_fail

        tasks = (
            [async_eval.evaluate({"fail": True}) for _ in range(5)]
            + [async_eval.evaluate({"tool_name": "read_file"}) for _ in range(5)]
        )
        results = await asyncio.gather(*tasks, return_exceptions=True)

        errors = [r for r in results if isinstance(r, RuntimeError)]
        successes = [r for r in results if isinstance(r, PolicyDecision)]

        assert len(errors) == 5
        assert len(successes) == 5
        for s in successes:
            assert s.allowed is True

        stats = async_eval.get_stats()
        assert stats["evaluation_count"] == 10
        assert stats["error_count"] == 5
