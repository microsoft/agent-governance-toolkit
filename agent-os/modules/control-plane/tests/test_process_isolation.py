# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""
Tests for process-level agent isolation.

Verifies that agents run in separate OS processes and can be
forcefully terminated using real OS signals (SIGKILL).
"""

from __future__ import annotations

import multiprocessing
import os
import platform
import sys
import time

import pytest

from agent_control_plane.process_isolation import (
    AgentProcessHandle,
    AgentProcessResult,
    AgentProcessState,
    IsolatedSignalDispatcher,
    IsolationLevel,
    ProcessIsolationManager,
    create_isolated_signal_dispatcher,
)
from agent_control_plane.signals import (
    AgentKernelPanic,
    AgentSignal,
)


# ========== Target functions (module-level for pickling) ==========


def simple_agent(value: str) -> str:
    """Agent that returns a value immediately."""
    return f"result:{value}"


def slow_agent(duration: float) -> str:
    """Agent that takes a while to complete."""
    time.sleep(duration)
    return "slow_done"


def crashing_agent() -> None:
    """Agent that raises an exception."""
    raise RuntimeError("Agent crashed intentionally")


def infinite_agent() -> None:
    """Agent that never returns (for kill testing)."""
    while True:
        time.sleep(0.1)


def catching_agent() -> str:
    """
    Adversarial agent that catches BaseException.
    In-process: this catches AgentKernelPanic.
    Process-level SIGKILL: this CANNOT catch os.kill(SIGKILL).
    """
    try:
        while True:
            time.sleep(0.1)
    except BaseException:
        return "escaped!"


def heartbeat_agent(count: int) -> str:
    """Agent that does work in small steps."""
    for _ in range(count):
        time.sleep(0.05)
    return f"done:{count}"


def exit_agent(code: int) -> None:
    """Agent that calls sys.exit."""
    sys.exit(code)


def returning_agent(val: int) -> int:
    """Agent that returns a numeric value."""
    return val * 2


# ========== Enum Tests ==========


class TestIsolationLevel:
    """Verify IsolationLevel enum values."""

    def test_enum_values(self):
        assert IsolationLevel.COOPERATIVE.value == "cooperative"
        assert IsolationLevel.PROCESS.value == "process"
        assert IsolationLevel.SUBPROCESS.value == "subprocess"

    def test_str_comparison(self):
        """str(Enum) mixin allows string equality."""
        assert IsolationLevel.PROCESS == "process"
        assert IsolationLevel.COOPERATIVE == "cooperative"


class TestAgentProcessState:
    """Verify AgentProcessState enum values."""

    def test_enum_values(self):
        assert AgentProcessState.PENDING.value == "pending"
        assert AgentProcessState.RUNNING.value == "running"
        assert AgentProcessState.COMPLETED.value == "completed"
        assert AgentProcessState.TERMINATED.value == "terminated"
        assert AgentProcessState.FAILED.value == "failed"


# ========== Result Tests ==========


class TestAgentProcessResult:
    """Verify AgentProcessResult dataclass defaults and fields."""

    def test_default_fields(self):
        r = AgentProcessResult(
            agent_id="a1", state=AgentProcessState.COMPLETED,
        )
        assert r.agent_id == "a1"
        assert r.return_value is None
        assert r.error is None
        assert r.exit_code is None
        assert r.duration_seconds == 0.0
        assert r.terminated_by_signal is False

    def test_terminated_result(self):
        r = AgentProcessResult(
            agent_id="a2",
            state=AgentProcessState.TERMINATED,
            error="Killed by SIGKILL",
            terminated_by_signal=True,
        )
        assert r.terminated_by_signal is True
        assert r.state == AgentProcessState.TERMINATED


# ========== ProcessIsolationManager Tests ==========


class TestProcessIsolationManager:
    """Test the main ProcessIsolationManager."""

    def test_spawn_and_get_result(self):
        """Agent runs in a separate process and returns a result."""
        mgr = ProcessIsolationManager()
        h = mgr.spawn(simple_agent, agent_id="t-simple", args=("hello",))
        assert h.pid is not None
        assert h.pid != os.getpid()

        result = h.wait(timeout=10)
        assert result.state == AgentProcessState.COMPLETED
        assert result.return_value == "result:hello"
        assert result.duration_seconds < 10

    def test_process_runs_in_different_pid(self):
        """Verify agent runs in a truly separate OS process."""
        mgr = ProcessIsolationManager()
        h = mgr.spawn(simple_agent, agent_id="t-pid", args=("x",))
        assert h.pid != os.getpid()
        result = h.wait(timeout=10)
        assert result.state == AgentProcessState.COMPLETED

    def test_agent_crash_captured(self):
        """Agent exception is captured without crashing supervisor."""
        mgr = ProcessIsolationManager()
        h = mgr.spawn(crashing_agent, agent_id="t-crash")
        result = h.wait(timeout=10)
        assert result.state == AgentProcessState.FAILED
        assert "crashed intentionally" in (result.error or "")

    def test_kill_with_sigkill(self):
        """Agent can be forcefully killed by supervisor."""
        mgr = ProcessIsolationManager()
        h = mgr.spawn(infinite_agent, agent_id="t-kill")
        time.sleep(0.5)
        assert h.is_alive()

        ok = h.kill()
        assert ok
        assert not h.is_alive()
        assert h.state == AgentProcessState.TERMINATED

    @pytest.mark.skipif(
        platform.system() == "Windows",
        reason="SIGKILL signal semantics differ on Windows",
    )
    def test_kill_uncatchable_unix(self):
        """On Unix, even an agent catching BaseException cannot
        survive a real SIGKILL from os.kill().
        """
        mgr = ProcessIsolationManager()
        h = mgr.spawn(catching_agent, agent_id="t-uncatch-unix")
        time.sleep(0.5)
        assert h.is_alive()

        h.kill()
        assert not h.is_alive()
        result = h.wait(timeout=5)
        assert result.state == AgentProcessState.TERMINATED
        assert result.terminated_by_signal

    def test_kill_uncatchable_windows(self):
        """process.kill() (TerminateProcess) also cannot be caught."""
        mgr = ProcessIsolationManager()
        h = mgr.spawn(catching_agent, agent_id="t-uncatch-win")
        time.sleep(0.5)
        assert h.is_alive()

        ok = h.kill()
        assert ok
        assert not h.is_alive()

    def test_timeout_kills_agent(self):
        """Agent that exceeds spawn timeout is killed automatically."""
        mgr = ProcessIsolationManager()
        h = mgr.spawn(
            infinite_agent, agent_id="t-timeout", timeout=1.0,
        )
        result = h.wait(timeout=10)
        assert result.state == AgentProcessState.TERMINATED
        assert not h.is_alive()

    def test_kill_all(self):
        """Manager can kill all agents at once."""
        mgr = ProcessIsolationManager()
        for i in range(3):
            mgr.spawn(infinite_agent, agent_id=f"t-all-{i}")
        time.sleep(0.5)

        killed = mgr.kill_all(reason="mass kill test")
        assert killed == 3
        for h in mgr.list_agents():
            assert not h.is_alive()

    def test_terminate_graceful(self):
        """Graceful termination sends SIGTERM."""
        mgr = ProcessIsolationManager()
        h = mgr.spawn(infinite_agent, agent_id="t-term")
        time.sleep(0.5)
        assert h.is_alive()

        ok = h.terminate()
        assert ok
        # Give the OS time to deliver the signal.
        h._process.join(timeout=5)
        assert not h.is_alive()

    def test_get_handle(self):
        """Retrieve agent handle by ID."""
        mgr = ProcessIsolationManager()
        mgr.spawn(simple_agent, agent_id="t-gh", args=("v",))
        assert mgr.get_handle("t-gh") is not None
        assert mgr.get_handle("nonexistent") is None
        mgr.get_handle("t-gh").wait(timeout=5)

    def test_list_agents(self):
        """list_agents returns all tracked handles."""
        mgr = ProcessIsolationManager()
        mgr.spawn(simple_agent, agent_id="t-la-1", args=("a",))
        mgr.spawn(simple_agent, agent_id="t-la-2", args=("b",))
        agents = mgr.list_agents()
        assert len(agents) == 2
        ids = {a.agent_id for a in agents}
        assert ids == {"t-la-1", "t-la-2"}
        for a in agents:
            a.wait(timeout=5)

    def test_auto_agent_id(self):
        """Agent ID is auto-generated when not provided."""
        mgr = ProcessIsolationManager()
        h = mgr.spawn(simple_agent, args=("auto",))
        assert h.agent_id.startswith("agent-")
        result = h.wait(timeout=5)
        assert result.state == AgentProcessState.COMPLETED

    def test_sys_exit_captured(self):
        """sys.exit() in agent is captured as failure."""
        mgr = ProcessIsolationManager()
        h = mgr.spawn(exit_agent, agent_id="t-exit", args=(42,))
        result = h.wait(timeout=10)
        assert result.state == AgentProcessState.FAILED
        assert "SystemExit" in (result.error or "")

    def test_cleanup_completed(self):
        """cleanup() removes completed agents from tracking."""
        mgr = ProcessIsolationManager()
        h = mgr.spawn(simple_agent, agent_id="t-clean", args=("x",))
        h.wait(timeout=10)
        assert mgr.get_handle("t-clean") is not None

        mgr.cleanup()
        assert mgr.get_handle("t-clean") is None

    def test_multiple_agents_concurrent(self):
        """Multiple agents run concurrently in separate processes."""
        mgr = ProcessIsolationManager()
        handles = [
            mgr.spawn(
                simple_agent,
                agent_id=f"t-conc-{i}",
                args=(f"v{i}",),
            )
            for i in range(5)
        ]
        pids = {h.pid for h in handles}
        assert len(pids) == 5
        assert os.getpid() not in pids

        for h in handles:
            r = h.wait(timeout=10)
            assert r.state == AgentProcessState.COMPLETED

    def test_cooperative_isolation_raises(self):
        """Attempting cooperative isolation raises ValueError."""
        mgr = ProcessIsolationManager()
        with pytest.raises(ValueError, match="Cooperative"):
            mgr.spawn(simple_agent, isolation=IsolationLevel.COOPERATIVE)

    def test_manager_kill_by_id(self):
        """Manager can kill a specific agent by ID."""
        mgr = ProcessIsolationManager()
        mgr.spawn(infinite_agent, agent_id="mk-a")
        mgr.spawn(infinite_agent, agent_id="mk-b")
        time.sleep(0.5)

        assert mgr.kill("mk-a", reason="test")
        assert not mgr.get_handle("mk-a").is_alive()
        assert mgr.get_handle("mk-b").is_alive()

        mgr.kill_all()

    def test_numeric_return_value(self):
        """Agent returning a numeric value is captured correctly."""
        mgr = ProcessIsolationManager()
        h = mgr.spawn(returning_agent, agent_id="t-num", args=(21,))
        result = h.wait(timeout=10)
        assert result.state == AgentProcessState.COMPLETED
        assert result.return_value == 42

    def test_kill_returns_false_for_dead_process(self):
        """kill() returns False when process is already dead."""
        mgr = ProcessIsolationManager()
        h = mgr.spawn(simple_agent, agent_id="t-dead", args=("x",))
        h.wait(timeout=5)
        assert not h.is_alive()

        ok = h.kill()
        assert not ok


# ========== IsolatedSignalDispatcher Tests ==========


class TestIsolatedSignalDispatcher:
    """Test IsolatedSignalDispatcher cooperative/process routing."""

    def test_cooperative_fallback_non_sigkill(self):
        """Non-SIGKILL signals use the cooperative path."""
        dispatcher = IsolatedSignalDispatcher("agent-coop")
        dispatcher.signal(AgentSignal.SIGSTOP)
        assert dispatcher.is_stopped

        dispatcher.signal(AgentSignal.SIGCONT)
        assert not dispatcher.is_stopped

    def test_sigterm_remains_cooperative(self):
        """SIGTERM still goes through the cooperative handler."""
        dispatcher = IsolatedSignalDispatcher("agent-term")
        dispatcher.signal(AgentSignal.SIGTERM)
        assert dispatcher.is_terminated

    def test_sigkill_with_no_process_cooperative_fallback(self):
        """SIGKILL with no isolated process falls back to cooperative mode.

        The cooperative ``_handle_kill`` sets terminated/stopped state and
        raises ``AgentKernelPanic``, which is caught by ``_deliver()``.
        We verify the state transition occurred correctly.
        """
        dispatcher = IsolatedSignalDispatcher("agent-no-proc")
        # signal() returns False because the handler raises (caught by _deliver)
        result = dispatcher.signal(AgentSignal.SIGKILL, reason="test panic")
        assert result is False
        # But state WAS updated before the raise
        assert dispatcher.is_terminated
        assert dispatcher.is_stopped

    def test_sigkill_with_process_kills(self):
        """SIGKILL routes to real process kill when process exists."""
        mgr = ProcessIsolationManager()
        h = mgr.spawn(infinite_agent, agent_id="agent-iso-kill")
        time.sleep(0.5)
        assert h.is_alive()

        dispatcher = IsolatedSignalDispatcher(
            "agent-iso-kill", process_manager=mgr,
        )
        # Should NOT raise -- real kill instead of exception.
        dispatcher.signal(AgentSignal.SIGKILL, reason="policy violation")

        assert not h.is_alive()
        assert dispatcher.is_terminated

    def test_signal_history_recorded(self):
        """Signals are still recorded in history."""
        dispatcher = IsolatedSignalDispatcher("agent-history")
        dispatcher.signal(AgentSignal.SIGSTOP, reason="inspect")
        history = dispatcher.get_signal_history()
        assert len(history) >= 1
        assert history[-1]["signal"] == "SIGSTOP"


# ========== Factory Tests ==========


class TestCreateIsolatedSignalDispatcher:
    """Test the factory function."""

    def test_factory_returns_dispatcher(self):
        d = create_isolated_signal_dispatcher("agent-factory")
        assert isinstance(d, IsolatedSignalDispatcher)
        assert d.agent_id == "agent-factory"

    def test_factory_with_custom_manager(self):
        mgr = ProcessIsolationManager()
        d = create_isolated_signal_dispatcher(
            "agent-f2", process_manager=mgr,
        )
        assert d._process_manager is mgr


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
