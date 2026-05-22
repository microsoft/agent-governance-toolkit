# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""Concurrency tests for AsyncTrustPolicyEvaluator and its RW lock."""

from __future__ import annotations

import asyncio
import queue
import threading
from concurrent.futures import ThreadPoolExecutor

from agentmesh.governance.async_policy_evaluator import (
    AsyncTrustPolicyEvaluator,
    _ReadWriteLock,
)
from agentmesh.governance.policy_evaluator import PolicyEvaluator
from agentmesh.governance.trust_policy import (
    TrustCondition,
    TrustDefaults,
    TrustPolicy,
    TrustRule,
)


def _make_policy(default_action: str = "allow") -> TrustPolicy:
    """Create a minimal trust policy for evaluator tests."""
    return TrustPolicy(
        name="async-evaluator-test",
        version="1.0",
        rules=[
            TrustRule(
                name="deny_high_risk",
                condition=TrustCondition(
                    field="risk_score",
                    operator="gt",
                    value=75,
                ),
                action="deny",
                priority=10,
            )
        ],
        defaults=TrustDefaults(
            min_trust_score=0,
            max_delegation_depth=20,
            allowed_namespaces=["*"],
            require_handshake=False,
        ),
    )


class TestReadWriteLock:
    def test_multiple_concurrent_readers(self):
        """Multiple readers should hold the lock at the same time."""
        rw = _ReadWriteLock()
        start = threading.Barrier(4)
        all_reading = threading.Barrier(4)
        counter_lock = threading.Lock()
        active = 0
        peak = 0

        def reader():
            nonlocal active, peak
            start.wait(timeout=2.0)
            rw.acquire_read()
            try:
                with counter_lock:
                    active += 1
                    peak = max(peak, active)
                all_reading.wait(timeout=2.0)
            finally:
                with counter_lock:
                    active -= 1
                rw.release_read()

        threads = [threading.Thread(target=reader) for _ in range(3)]
        for thread in threads:
            thread.start()

        start.wait(timeout=2.0)
        all_reading.wait(timeout=2.0)

        for thread in threads:
            thread.join(timeout=2.0)
            assert not thread.is_alive()

        assert peak == 3

    def test_writer_blocks_reader_until_release(self):
        rw = _ReadWriteLock()
        rw.acquire_write()

        attempt_started = threading.Event()
        acquired = threading.Event()

        def reader():
            attempt_started.set()
            rw.acquire_read()
            try:
                acquired.set()
            finally:
                rw.release_read()

        thread = threading.Thread(target=reader)
        thread.start()

        assert attempt_started.wait(timeout=2.0)
        assert not acquired.wait(timeout=0.5)
        rw.release_write()

        assert acquired.wait(timeout=2.0)
        thread.join(timeout=2.0)
        assert not thread.is_alive()

    def test_reader_blocks_writer_until_release(self):
        rw = _ReadWriteLock()
        rw.acquire_read()

        attempt_started = threading.Event()
        acquired = threading.Event()

        def writer():
            attempt_started.set()
            rw.acquire_write()
            try:
                acquired.set()
            finally:
                rw.release_write()

        thread = threading.Thread(target=writer)
        thread.start()

        assert attempt_started.wait(timeout=2.0)
        assert not acquired.wait(timeout=0.5)
        rw.release_read()

        assert acquired.wait(timeout=2.0)
        thread.join(timeout=2.0)
        assert not thread.is_alive()

    def test_waiting_writer_blocks_new_reader(self):
        rw = _ReadWriteLock()
        rw.acquire_read()

        writer_attempt_started = threading.Event()
        writer_acquired = threading.Event()
        second_reader_attempt_started = threading.Event()
        second_reader_acquired = threading.Event()

        def writer():
            writer_attempt_started.set()
            rw.acquire_write()
            try:
                writer_acquired.set()
            finally:
                rw.release_write()

        def second_reader():
            second_reader_attempt_started.set()
            rw.acquire_read()
            try:
                second_reader_acquired.set()
            finally:
                rw.release_read()

        writer_thread = threading.Thread(target=writer)
        writer_thread.start()
        assert writer_attempt_started.wait(timeout=2.0)

        second_reader_thread = threading.Thread(target=second_reader)
        second_reader_thread.start()
        assert second_reader_attempt_started.wait(timeout=2.0)

        # Reader should be blocked while a writer is waiting.
        assert not second_reader_acquired.wait(timeout=0.5)

        rw.release_read()

        assert writer_acquired.wait(timeout=2.0)
        writer_thread.join(timeout=2.0)
        second_reader_thread.join(timeout=2.0)
        assert not writer_thread.is_alive()
        assert not second_reader_thread.is_alive()

    def test_release_read_without_acquire_raises(self):
        rw = _ReadWriteLock()
        try:
            rw.release_read()
        except RuntimeError as exc:
            assert "release_read called without matching acquire_read" in str(exc)
        else:  # pragma: no cover - defensive assertion
            raise AssertionError("Expected RuntimeError from release_read without acquire")

    def test_release_write_without_acquire_raises(self):
        rw = _ReadWriteLock()
        try:
            rw.release_write()
        except RuntimeError as exc:
            assert "release_write called without matching acquire_write" in str(exc)
        else:  # pragma: no cover - defensive assertion
            raise AssertionError("Expected RuntimeError from release_write without acquire")

    def test_cross_thread_final_reader_release_does_not_raise(self):
        """Regression: first and final readers can be different threads."""
        rw = _ReadWriteLock()
        a_has_lock = threading.Event()
        b_has_lock = threading.Event()
        a_can_release = threading.Event()
        errors: queue.Queue[Exception] = queue.Queue()

        def reader_a():
            try:
                rw.acquire_read()
                a_has_lock.set()
                a_can_release.wait(timeout=2.0)
                rw.release_read()
            except Exception as exc:  # pragma: no cover - only for diagnostics
                errors.put(exc)

        def reader_b():
            try:
                a_has_lock.wait(timeout=2.0)
                rw.acquire_read()
                b_has_lock.set()
                a_can_release.set()
                rw.release_read()
            except Exception as exc:  # pragma: no cover - only for diagnostics
                errors.put(exc)

        ta = threading.Thread(target=reader_a)
        tb = threading.Thread(target=reader_b)
        ta.start()
        tb.start()

        ta.join(timeout=2.0)
        tb.join(timeout=2.0)

        assert not ta.is_alive()
        assert not tb.is_alive()
        assert a_has_lock.is_set()
        assert b_has_lock.is_set()
        assert errors.empty()


class TestAsyncTrustPolicyEvaluatorConcurrency:
    def test_repeated_concurrent_evaluate_sync_is_stable(self):
        evaluator = PolicyEvaluator([_make_policy()])
        async_eval = AsyncTrustPolicyEvaluator(evaluator)

        contexts = [
            {"risk_score": 50},
            {"risk_score": 99},
            {"risk_score": 10},
            {"risk_score": 80},
        ]

        for _ in range(60):
            with ThreadPoolExecutor(max_workers=8) as pool:
                futures = [
                    pool.submit(async_eval.evaluate_sync, contexts[i % len(contexts)])
                    for i in range(24)
                ]
                results = [future.result(timeout=5.0) for future in futures]

            assert len(results) == 24
            assert all(result.action in {"allow", "deny"} for result in results)

        stats = async_eval.get_stats()
        assert stats["evaluation_count"] == 60 * 24
        assert stats["error_count"] == 0

    def test_reload_and_reads_concurrent_no_runtime_error(self):
        async def _run() -> list[object]:
            evaluator = PolicyEvaluator([_make_policy(default_action="allow")])
            async_eval = AsyncTrustPolicyEvaluator(evaluator)

            deny_by_default = _make_policy(default_action="deny")
            allow_by_default = _make_policy(default_action="allow")

            tasks: list[asyncio.Future] = []
            for i in range(30):
                tasks.append(asyncio.ensure_future(async_eval.evaluate({"risk_score": i})))
                if i % 5 == 0:
                    policies = [deny_by_default] if (i // 5) % 2 else [allow_by_default]
                    tasks.append(asyncio.ensure_future(async_eval.reload_policies(policies)))

            return await asyncio.gather(*tasks, return_exceptions=True)

        results = asyncio.run(_run())
        runtime_errors = [
            item
            for item in results
            if isinstance(item, RuntimeError) and "cannot release un-acquired lock" in str(item)
        ]

        assert not runtime_errors
        assert all(not isinstance(item, Exception) for item in results)
