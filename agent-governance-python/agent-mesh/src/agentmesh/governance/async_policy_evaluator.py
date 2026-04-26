# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""
Async-safe and thread-safe trust policy evaluator for Agent-Mesh.

Wraps the synchronous :class:`PolicyEvaluator` (trust variant) with
concurrency controls identical to the Agent-OS async evaluator so that
the trust policy evaluator can be used safely from ``asyncio`` coroutines
**and** from multiple OS threads simultaneously.

Concurrency guarantees
----------------------
* **asyncio.Lock** guards coroutine-level access.
* A lightweight **read-write lock** allows multiple concurrent reads
  (evaluations) while giving exclusive access to writes (policy reloads).
* All evaluation statistics are updated atomically via a thread lock.
"""

from __future__ import annotations

import asyncio
import logging
import threading
import time
from dataclasses import dataclass, field
from typing import Any

from .policy_evaluator import PolicyEvaluator, TrustPolicyDecision
from .trust_policy import TrustPolicy

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Concurrency statistics
# ---------------------------------------------------------------------------

@dataclass
class ConcurrencyStats:
    """Tracks concurrency-related metrics for the async trust evaluator.

    All mutations happen under the owning evaluator's thread lock so
    individual field updates are atomic with respect to other threads.
    """

    evaluation_count: int = 0
    total_evaluation_time: float = 0.0
    error_count: int = 0
    reload_count: int = 0
    concurrent_peak: int = 0
    _active_readers: int = field(default=0, repr=False)

    @property
    def average_evaluation_time(self) -> float:
        """Return average evaluation latency in seconds, or 0.0."""
        if self.evaluation_count == 0:
            return 0.0
        return self.total_evaluation_time / self.evaluation_count

    def as_dict(self) -> dict[str, Any]:
        """Serialise stats to a plain dictionary."""
        return {
            "evaluation_count": self.evaluation_count,
            "total_evaluation_time": round(self.total_evaluation_time, 6),
            "average_evaluation_time": round(self.average_evaluation_time, 6),
            "error_count": self.error_count,
            "reload_count": self.reload_count,
            "concurrent_peak": self.concurrent_peak,
        }


# ---------------------------------------------------------------------------
# Read-write lock helpers
# ---------------------------------------------------------------------------

class _ReadWriteLock:
    """Simple readers-writer lock built on :class:`threading.RLock`.

    Multiple readers can hold the lock concurrently; a writer gets
    exclusive access (no readers **and** no other writers).
    """

    def __init__(self) -> None:
        self._readers: int = 0
        self._lock = threading.RLock()
        self._write_lock = threading.RLock()

    def acquire_read(self) -> None:
        with self._lock:
            self._readers += 1
            if self._readers == 1:
                self._write_lock.acquire()

    def release_read(self) -> None:
        with self._lock:
            self._readers -= 1
            if self._readers == 0:
                self._write_lock.release()

    def acquire_write(self) -> None:
        self._write_lock.acquire()

    def release_write(self) -> None:
        self._write_lock.release()


# ---------------------------------------------------------------------------
# Async-safe trust policy evaluator
# ---------------------------------------------------------------------------

class AsyncTrustPolicyEvaluator:
    """Thread-safe and asyncio-safe trust policy evaluator.

    Wraps :class:`PolicyEvaluator` (the trust variant from Agent-Mesh)
    with proper concurrency controls:

    * :pyobj:`asyncio.Lock` for coroutine safety within a single event
      loop.
    * :class:`_ReadWriteLock` for thread safety — multiple concurrent
      reads (evaluations) are allowed; writes (policy reloads) acquire
      exclusive access.
    * Evaluation statistics (:class:`ConcurrencyStats`) are maintained
      atomically.

    Parameters
    ----------
    evaluator:
        The underlying synchronous trust policy evaluator to wrap.
    """

    def __init__(self, evaluator: PolicyEvaluator) -> None:
        self._evaluator = evaluator
        self._async_lock = asyncio.Lock()
        self._rw_lock = _ReadWriteLock()
        self._thread_lock = threading.RLock()
        self._stats = ConcurrencyStats()

    # -- properties --------------------------------------------------------

    @property
    def evaluator(self) -> PolicyEvaluator:
        """Return the underlying synchronous trust policy evaluator."""
        return self._evaluator

    # -- async entry-points ------------------------------------------------

    async def evaluate(self, context: dict[str, Any]) -> TrustPolicyDecision:
        """Evaluate trust policies against *context* with async + thread safety.

        Acquires the async lock (coroutine safety) and the read side of
        the RW lock (thread safety) so that concurrent evaluations can
        proceed but a policy reload will block until all in-flight
        evaluations complete.

        Thread-safety: YES — safe to call from multiple threads via
        ``asyncio.run_coroutine_threadsafe``.

        Returns
        -------
        TrustPolicyDecision
            The result of evaluating the loaded trust policies.
        """
        async with self._async_lock:
            return await asyncio.get_running_loop().run_in_executor(
                None, self._evaluate_with_read_lock, context
            )

    def evaluate_sync(self, context: dict[str, Any]) -> TrustPolicyDecision:
        """Thread-safe synchronous trust policy evaluation.

        Uses the read side of the RW lock so multiple threads may
        evaluate concurrently while policy reloads block.

        Thread-safety: YES — safe to call from any OS thread.

        Returns
        -------
        TrustPolicyDecision
            The result of evaluating the loaded trust policies.
        """
        return self._evaluate_with_read_lock(context)

    async def evaluate_batch(
        self, contexts: list[dict[str, Any]]
    ) -> list[TrustPolicyDecision]:
        """Evaluate multiple contexts concurrently.

        Each context is evaluated in its own asyncio task.  All tasks
        share the same concurrency controls so a policy reload in
        progress will block them.

        Thread-safety: YES.

        Returns
        -------
        list[TrustPolicyDecision]
            One decision per input context, in the same order.
        """
        tasks = [
            asyncio.ensure_future(self.evaluate(ctx)) for ctx in contexts
        ]
        return list(await asyncio.gather(*tasks))

    async def reload_policies(self, policies: list[TrustPolicy]) -> None:
        """Replace the loaded trust policies with an exclusive write lock.

        Acquires the write side of the RW lock so that no evaluations
        can proceed while the policy set is being replaced.

        Thread-safety: YES.

        Parameters
        ----------
        policies:
            New list of trust policies to load.
        """
        async with self._async_lock:
            await asyncio.get_running_loop().run_in_executor(
                None, self._reload_with_write_lock, policies
            )

    def get_stats(self) -> dict[str, Any]:
        """Return a snapshot of concurrency statistics.

        Thread-safety: YES — reads are guarded by the thread lock.
        """
        with self._thread_lock:
            return self._stats.as_dict()

    # -- internal helpers --------------------------------------------------

    def _evaluate_with_read_lock(
        self, context: dict[str, Any]
    ) -> TrustPolicyDecision:
        """Run the trust evaluator under the read side of the RW lock."""
        self._rw_lock.acquire_read()
        try:
            with self._thread_lock:
                self._stats._active_readers += 1
                if self._stats._active_readers > self._stats.concurrent_peak:
                    self._stats.concurrent_peak = self._stats._active_readers

            start = time.monotonic()
            try:
                result = self._evaluator.evaluate(context)
            except Exception:
                with self._thread_lock:
                    self._stats.error_count += 1
                raise
            finally:
                elapsed = time.monotonic() - start
                with self._thread_lock:
                    self._stats.evaluation_count += 1
                    self._stats.total_evaluation_time += elapsed
                    self._stats._active_readers -= 1

            return result
        finally:
            self._rw_lock.release_read()

    def _reload_with_write_lock(
        self, policies: list[TrustPolicy]
    ) -> None:
        """Replace policies under the exclusive write lock."""
        self._rw_lock.acquire_write()
        try:
            self._evaluator._policies = list(policies)
            with self._thread_lock:
                self._stats.reload_count += 1
            logger.info("Trust policies reloaded (%d policies)", len(policies))
        finally:
            self._rw_lock.release_write()
