# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
import threading
import time
from types import SimpleNamespace
import pytest
from agent_rag_governance.rate_limiter import RateLimiter


def test_zero_limit_always_allows():
    limiter = RateLimiter()
    for _ in range(1000):
        assert limiter.check("agent", limit=0) is True


def test_under_limit_passes():
    limiter = RateLimiter()
    for _ in range(5):
        assert limiter.check("agent", limit=10) is True


def test_at_limit_fails():
    limiter = RateLimiter()
    for _ in range(10):
        limiter.check("agent", limit=10)
    assert limiter.check("agent", limit=10) is False


def test_different_agents_independent():
    limiter = RateLimiter()
    for _ in range(10):
        limiter.check("agent-a", limit=10)
    # agent-a is at limit, agent-b should still pass
    assert limiter.check("agent-b", limit=10) is True


def test_reset_clears_state():
    limiter = RateLimiter()
    for _ in range(10):
        limiter.check("agent", limit=10)
    assert limiter.check("agent", limit=10) is False
    limiter.reset("agent")
    assert limiter.check("agent", limit=10) is True


def test_window_expiry():
    limiter = RateLimiter(window_seconds=1)
    for _ in range(5):
        limiter.check("agent", limit=5)
    assert limiter.check("agent", limit=5) is False
    time.sleep(1.1)
    assert limiter.check("agent", limit=5) is True


def test_delayed_caller_uses_admission_time(monkeypatch: pytest.MonkeyPatch) -> None:
    from agent_rag_governance import rate_limiter

    now = [0.0]
    monkeypatch.setattr(rate_limiter, "time", SimpleNamespace(monotonic=lambda: now[0]))
    limiter = RateLimiter(window_seconds=5)
    paused = threading.Event()
    release = threading.Event()
    admissions = []
    allowed = {}

    class ScheduledLock:
        def __init__(self):
            self.lock = threading.Lock()

        def __enter__(self):
            if threading.current_thread().name == "delayed":
                paused.set()
                assert release.wait(timeout=5)
            self.lock.acquire()
            admissions.append((threading.current_thread().name, now[0]))

        def __exit__(self, *args):
            self.lock.release()

    limiter._lock = ScheduledLock()

    def delayed_check():
        allowed["delayed"] = limiter.check("agent", limit=2)

    thread = threading.Thread(target=delayed_check, name="delayed")
    thread.start()
    try:
        assert paused.wait(timeout=5)
        now[0] = 10.0
        assert limiter.check("agent", limit=2)
        now[0] = 10.5
    finally:
        release.set()
        thread.join(timeout=5)
    assert not thread.is_alive()
    assert allowed["delayed"]

    now[0] = 15.1
    assert limiter.check("agent", limit=2)
    now[0] = 15.2
    assert not limiter.check("agent", limit=2)
    assert [at for _, at in admissions] == [10.0, 10.5, 15.1, 15.2]


def test_exact_window_boundary_is_still_counted(monkeypatch: pytest.MonkeyPatch) -> None:
    from agent_rag_governance import rate_limiter

    now = [10.0]
    monkeypatch.setattr(rate_limiter, "time", SimpleNamespace(monotonic=lambda: now[0]))
    limiter = RateLimiter(window_seconds=5)
    assert limiter.check("agent", limit=1)
    now[0] = 15.0
    assert not limiter.check("agent", limit=1)
    now[0] = 15.1
    assert limiter.check("agent", limit=1)
