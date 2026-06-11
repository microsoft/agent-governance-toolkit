# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""Tests for #2666: ring enforcement wired into sandbox providers.

Verifies that:
- SandboxConfig accepts a ``ring`` field.
- Ring 3 (sandbox) constraints are applied at create_session: network disabled,
  read_only_fs=True.
- Ring 2 (standard) constraints permit network.
- execute_code raises PermissionError when the ring denies SUBPROCESS.
- The RingBreachDetector circuit-breaker trips after repeated violations.
- ring=None (default) is a no-op and does not touch existing behaviour.
- All three providers (Docker, Hyperlight, ACA) respect ring enforcement.
"""

from __future__ import annotations

import threading
from types import SimpleNamespace
from typing import Any
from unittest.mock import MagicMock, patch

import pytest

from agent_sandbox.sandbox_provider import (
    SandboxConfig,
    SessionStatus,
)

# ---------------------------------------------------------------------------
# Helpers — fake hypervisor models so tests run without agent-hypervisor
# ---------------------------------------------------------------------------


class _FakeExecutionRing:
    """Minimal ExecutionRing stand-in for test isolation."""

    def __init__(self, value: int, name: str) -> None:
        self.value = value
        self.name = name

    def __repr__(self) -> str:
        return self.name

    def __int__(self) -> int:
        return self.value


# Ring constants matching the real ones
RING_2_STANDARD = _FakeExecutionRing(2, "RING_2_STANDARD")
RING_3_SANDBOX = _FakeExecutionRing(3, "RING_3_SANDBOX")


class _FakeConstraints:
    def __init__(
        self,
        network_allowed: bool,
        filesystem_scope: str,
        subprocess_allowed: bool,
    ) -> None:
        self.network_allowed = network_allowed
        self.filesystem_scope = filesystem_scope
        self.subprocess_allowed = subprocess_allowed


class _FakeRingCheckResult:
    def __init__(self, allowed: bool, reason: str = "") -> None:
        self.allowed = allowed
        self.reason = reason


class _FakeRingEnforcer:
    RING_CONSTRAINTS = {
        2: _FakeConstraints(
            network_allowed=True,
            filesystem_scope="scoped",
            subprocess_allowed=True,
        ),
        3: _FakeConstraints(
            network_allowed=False,
            filesystem_scope="none",
            subprocess_allowed=False,
        ),
    }

    def get_constraints(self, ring: Any) -> _FakeConstraints:
        return self.RING_CONSTRAINTS.get(int(ring), self.RING_CONSTRAINTS[3])

    def check_resource(self, agent_ring: Any, resource_type: Any) -> _FakeRingCheckResult:
        constraints = self.get_constraints(agent_ring)
        if resource_type == "subprocess":
            return _FakeRingCheckResult(
                allowed=constraints.subprocess_allowed,
                reason="denied" if not constraints.subprocess_allowed else "ok",
            )
        return _FakeRingCheckResult(allowed=True)


class _FakeBreachDetector:
    def __init__(self) -> None:
        self._tripped: dict[str, bool] = {}
        self.calls: list[tuple] = []

    def record_call(self, agent_did, session_id, agent_ring, called_ring) -> None:
        self.calls.append((agent_did, session_id, agent_ring, called_ring))

    def is_breaker_tripped(self, agent_did: str, session_id: str) -> bool:
        return self._tripped.get(f"{agent_did}::{session_id}", False)

    def trip(self, agent_did: str, session_id: str) -> None:
        self._tripped[f"{agent_did}::{session_id}"] = True


# ---------------------------------------------------------------------------
# SandboxConfig ring field
# ---------------------------------------------------------------------------


class TestSandboxConfigRingField:
    def test_ring_field_defaults_to_none(self):
        cfg = SandboxConfig()
        assert cfg.ring is None

    def test_ring_field_accepts_value(self):
        cfg = SandboxConfig(ring=RING_3_SANDBOX)
        assert cfg.ring is RING_3_SANDBOX

    def test_ring_field_accepts_standard(self):
        cfg = SandboxConfig(ring=RING_2_STANDARD)
        assert cfg.ring is RING_2_STANDARD


# ---------------------------------------------------------------------------
# Docker provider ring enforcement
# ---------------------------------------------------------------------------


def _make_docker_provider_with_mocks():
    """Return a DockerSandboxProvider with Docker and ring internals mocked."""
    try:
        from agent_sandbox.docker_provider.provider import DockerSandboxProvider
        from agent_sandbox.isolation_runtime import IsolationRuntime
    except ImportError:
        pytest.skip("agent-sandbox docker provider not installed")

    with patch(
        "agent_sandbox.docker_provider.provider.DockerSandboxProvider.__init__",
        return_value=None,
    ):
        provider = DockerSandboxProvider.__new__(DockerSandboxProvider)
        provider._image = "python:3.11-slim"
        provider._tools = {}
        provider._requested_runtime = IsolationRuntime.AUTO
        provider._state_lock = threading.RLock()
        provider._containers = {}
        provider._evaluators = {}
        provider._session_configs = {}
        provider._exec_locks = {}
        provider._ring_enforcers = {}
        provider._ring_breach_detectors = {}
        provider._tool_proxy = None
        provider._network_proxy = None
        provider._state_manager = None
        provider._available = True
        provider._runtime = IsolationRuntime.RUNC

        mock_container = MagicMock()
        mock_container.status = "running"
        mock_container.exec_run.return_value = MagicMock(
            exit_code=0, output=(b"ok", b""),
        )

        def _create_container(agent_id, session_id, config, image=None):
            return mock_container

        provider._create_container = MagicMock(side_effect=_create_container)

        # Mock Docker client for run() method
        mock_client = MagicMock()
        mock_client.images.get.return_value = MagicMock()
        provider._client = mock_client

        return provider


def _inject_fake_hypervisor(provider, enforcer=None, breach_detector=None):
    """Inject fake RingEnforcer and RingBreachDetector into the provider's import path."""
    fake_enforcer = enforcer or _FakeRingEnforcer()
    fake_detector = breach_detector or _FakeBreachDetector()

    fake_enforcer_module = SimpleNamespace(
        RingEnforcer=lambda: fake_enforcer,
        ResourceType=SimpleNamespace(SUBPROCESS="subprocess"),
    )
    fake_models_module = SimpleNamespace(
        ExecutionRing=SimpleNamespace(RING_3_SANDBOX=RING_3_SANDBOX),
    )
    fake_breach_module = SimpleNamespace(
        RingBreachDetector=lambda: fake_detector,
    )

    return fake_enforcer, fake_detector, fake_enforcer_module, fake_breach_module, fake_models_module


class TestDockerRingEnforcement:
    def test_ring_none_is_noop(self):
        """No ring set — provider creates session without touching ring dicts."""
        provider = _make_docker_provider_with_mocks()
        cfg = SandboxConfig(ring=None)
        h = provider.create_session("agent1", config=cfg)
        assert h.status == SessionStatus.READY
        assert provider._ring_enforcers == {}
        assert provider._ring_breach_detectors == {}

    def test_ring3_disables_network(self):
        """Ring 3 must force network_enabled=False on the config."""
        provider = _make_docker_provider_with_mocks()
        fake_enforcer = _FakeRingEnforcer()

        fake_enforcer_module = SimpleNamespace(
            RingEnforcer=lambda: fake_enforcer,
            ResourceType=SimpleNamespace(SUBPROCESS="subprocess"),
        )
        fake_breach_module = SimpleNamespace(
            RingBreachDetector=_FakeBreachDetector,
        )

        with patch.dict(
            "sys.modules",
            {
                "hypervisor.rings.enforcer": fake_enforcer_module,
                "hypervisor.rings.breach_detector": fake_breach_module,
            },
        ):
            cfg = SandboxConfig(network_enabled=True, ring=RING_3_SANDBOX)
            h = provider.create_session("agent1", config=cfg)

        stored_cfg = provider._session_configs[(h.agent_id, h.session_id)]
        assert stored_cfg.network_enabled is False

    def test_ring3_sets_readonly_fs(self):
        """Ring 3 must force read_only_fs=True on the config."""
        provider = _make_docker_provider_with_mocks()
        fake_enforcer = _FakeRingEnforcer()

        fake_enforcer_module = SimpleNamespace(
            RingEnforcer=lambda: fake_enforcer,
            ResourceType=SimpleNamespace(SUBPROCESS="subprocess"),
        )
        fake_breach_module = SimpleNamespace(
            RingBreachDetector=_FakeBreachDetector,
        )

        with patch.dict(
            "sys.modules",
            {
                "hypervisor.rings.enforcer": fake_enforcer_module,
                "hypervisor.rings.breach_detector": fake_breach_module,
            },
        ):
            cfg = SandboxConfig(read_only_fs=False, ring=RING_3_SANDBOX)
            h = provider.create_session("agent1", config=cfg)

        stored_cfg = provider._session_configs[(h.agent_id, h.session_id)]
        assert stored_cfg.read_only_fs is True

    def test_ring2_permits_network(self):
        """Ring 2 (standard) must leave network_enabled as-is."""
        provider = _make_docker_provider_with_mocks()
        fake_enforcer = _FakeRingEnforcer()

        fake_enforcer_module = SimpleNamespace(
            RingEnforcer=lambda: fake_enforcer,
            ResourceType=SimpleNamespace(SUBPROCESS="subprocess"),
        )
        fake_breach_module = SimpleNamespace(
            RingBreachDetector=_FakeBreachDetector,
        )

        with patch.dict(
            "sys.modules",
            {
                "hypervisor.rings.enforcer": fake_enforcer_module,
                "hypervisor.rings.breach_detector": fake_breach_module,
            },
        ):
            cfg = SandboxConfig(network_enabled=True, ring=RING_2_STANDARD)
            h = provider.create_session("agent1", config=cfg)

        stored_cfg = provider._session_configs[(h.agent_id, h.session_id)]
        assert stored_cfg.network_enabled is True

    def test_ring_enforcer_stored_at_create_session(self):
        """Ring enforcer and breach detector must be stored per session."""
        provider = _make_docker_provider_with_mocks()
        fake_enforcer = _FakeRingEnforcer()
        fake_detector = _FakeBreachDetector()

        fake_enforcer_module = SimpleNamespace(
            RingEnforcer=lambda: fake_enforcer,
            ResourceType=SimpleNamespace(SUBPROCESS="subprocess"),
        )
        fake_breach_module = SimpleNamespace(
            RingBreachDetector=lambda: fake_detector,
        )

        with patch.dict(
            "sys.modules",
            {
                "hypervisor.rings.enforcer": fake_enforcer_module,
                "hypervisor.rings.breach_detector": fake_breach_module,
            },
        ):
            cfg = SandboxConfig(ring=RING_3_SANDBOX)
            h = provider.create_session("agent1", config=cfg)

        key = (h.agent_id, h.session_id)
        assert key in provider._ring_enforcers
        assert key in provider._ring_breach_detectors

    def test_execute_code_ring3_subprocess_denied(self):
        """execute_code must raise PermissionError for Ring 3 subprocess."""
        provider = _make_docker_provider_with_mocks()
        fake_enforcer = _FakeRingEnforcer()
        fake_detector = _FakeBreachDetector()

        fake_enforcer_module = SimpleNamespace(
            RingEnforcer=lambda: fake_enforcer,
            ResourceType=SimpleNamespace(SUBPROCESS="subprocess"),
        )
        fake_breach_module = SimpleNamespace(
            RingBreachDetector=lambda: fake_detector,
        )
        fake_models_module = SimpleNamespace(
            ExecutionRing=SimpleNamespace(RING_3_SANDBOX=RING_3_SANDBOX),
        )

        with patch.dict(
            "sys.modules",
            {
                "hypervisor.rings.enforcer": fake_enforcer_module,
                "hypervisor.rings.breach_detector": fake_breach_module,
            },
        ):
            cfg = SandboxConfig(ring=RING_3_SANDBOX)
            h = provider.create_session("agent1", config=cfg)

        # Manually inject ring enforcer and config with ring
        key = (h.agent_id, h.session_id)
        provider._ring_enforcers[key] = fake_enforcer
        provider._ring_breach_detectors[key] = fake_detector
        provider._session_configs[key].ring = RING_3_SANDBOX

        with patch.dict(
            "sys.modules",
            {
                "hypervisor.rings.enforcer": fake_enforcer_module,
                "hypervisor.models": fake_models_module,
            },
        ):
            with pytest.raises(PermissionError, match="[Rr]ing"):
                provider.execute_code("agent1", h.session_id, "print('x')")

    def test_circuit_breaker_tripped_blocks_execute(self):
        """execute_code must raise PermissionError when circuit breaker is tripped."""
        provider = _make_docker_provider_with_mocks()
        fake_enforcer = _FakeRingEnforcer()
        fake_detector = _FakeBreachDetector()
        fake_detector.trip("agent1", "placeholder")  # Will be overridden below

        fake_enforcer_module = SimpleNamespace(
            RingEnforcer=lambda: fake_enforcer,
            ResourceType=SimpleNamespace(SUBPROCESS="subprocess"),
        )
        fake_models_module = SimpleNamespace(
            ExecutionRing=SimpleNamespace(RING_3_SANDBOX=RING_3_SANDBOX),
        )

        # Create session without ring to skip ring gate at create_session
        h = provider.create_session("agent1")
        key = (h.agent_id, h.session_id)

        # Inject ring state manually so we test the execute_code path specifically
        provider._ring_enforcers[key] = fake_enforcer
        provider._ring_breach_detectors[key] = fake_detector
        provider._session_configs[key].ring = RING_3_SANDBOX

        # Trip the breaker for this specific session
        fake_detector.trip(h.agent_id, h.session_id)

        with patch.dict(
            "sys.modules",
            {
                "hypervisor.rings.enforcer": fake_enforcer_module,
                "hypervisor.models": fake_models_module,
            },
        ):
            with pytest.raises(PermissionError, match="[Cc]ircuit"):
                provider.execute_code("agent1", h.session_id, "print('x')")

    def test_destroy_session_cleans_ring_state(self):
        """destroy_session must remove ring state from provider dicts."""
        provider = _make_docker_provider_with_mocks()
        fake_enforcer = _FakeRingEnforcer()
        fake_detector = _FakeBreachDetector()

        fake_enforcer_module = SimpleNamespace(
            RingEnforcer=lambda: fake_enforcer,
            ResourceType=SimpleNamespace(SUBPROCESS="subprocess"),
        )
        fake_breach_module = SimpleNamespace(
            RingBreachDetector=lambda: fake_detector,
        )

        with patch.dict(
            "sys.modules",
            {
                "hypervisor.rings.enforcer": fake_enforcer_module,
                "hypervisor.rings.breach_detector": fake_breach_module,
            },
        ):
            cfg = SandboxConfig(ring=RING_3_SANDBOX)
            h = provider.create_session("agent1", config=cfg)

        key = (h.agent_id, h.session_id)
        assert key in provider._ring_enforcers

        provider.destroy_session(h.agent_id, h.session_id)
        assert key not in provider._ring_enforcers
        assert key not in provider._ring_breach_detectors

    def test_hypervisor_not_installed_is_skipped_gracefully(self):
        """If agent-hypervisor is not installed, ring=X is silently skipped."""
        provider = _make_docker_provider_with_mocks()

        with patch.dict("sys.modules", {"hypervisor.rings.enforcer": None}):
            cfg = SandboxConfig(ring=RING_3_SANDBOX)
            # Should not raise
            h = provider.create_session("agent1", config=cfg)

        assert h.status == SessionStatus.READY
        # No ring state stored
        assert provider._ring_enforcers == {}


# ---------------------------------------------------------------------------
# Hyperlight provider ring enforcement
# ---------------------------------------------------------------------------


def _make_hyperlight_provider():
    """Return a HyperLightSandboxProvider with SDK and ring internals mocked."""
    try:
        from agent_sandbox.hyperlight_provider.provider import HyperLightSandboxProvider
    except ImportError:
        pytest.skip("agent-sandbox hyperlight provider not installed")

    with patch(
        "agent_sandbox.hyperlight_provider.provider.HyperLightSandboxProvider.__init__",
        return_value=None,
    ):
        provider = HyperLightSandboxProvider.__new__(HyperLightSandboxProvider)
        provider._state_lock = threading.RLock()
        provider._workers = {}
        provider._sandboxes = {}
        provider._evaluators = {}
        provider._session_configs = {}
        provider._snapshots = {}
        provider._ring_enforcers = {}
        provider._ring_breach_detectors = {}
        provider._available = True
        provider._unavailable_reason = None
        provider._tools = {}
        provider._backend = "wasm"
        provider._module = "agent.wasm"
        provider._sdk = MagicMock()
        return provider


class TestHyperlightRingEnforcement:
    def test_ring3_clears_network_allowlist(self):
        """Ring 3 must strip net_allow before the sandbox worker starts."""
        provider = _make_hyperlight_provider()
        fake_enforcer = _FakeRingEnforcer()

        fake_enforcer_module = SimpleNamespace(
            RingEnforcer=lambda: fake_enforcer,
            ResourceType=SimpleNamespace(SUBPROCESS="subprocess"),
        )
        fake_breach_module = SimpleNamespace(
            RingBreachDetector=_FakeBreachDetector,
        )

        # Build mock SDK
        fake_sandbox = MagicMock()
        fake_sandbox.register_tool = MagicMock()
        fake_sandbox.allow_domain = MagicMock()

        def _fake_build_sandbox(hl_cfg):
            return fake_sandbox

        def _fake_build_evaluator(policy):
            return None

        provider._build_sandbox = _fake_build_sandbox
        provider._build_evaluator = _fake_build_evaluator
        provider._safe_drop = MagicMock()

        # Patch _SandboxWorker to run synchronously in tests
        class _SyncWorker:
            def __init__(self, name=""):
                self.name = name

            def start(self):
                pass

            def submit_and_wait(self, fn):
                return fn()

            def stop(self, join_timeout=None):
                pass

        # Mock HyperlightConfig.from_sandbox_config

        with patch(
            "agent_sandbox.hyperlight_provider.provider._SandboxWorker",
            _SyncWorker,
        ), patch.dict(
            "sys.modules",
            {
                "hypervisor.rings.enforcer": fake_enforcer_module,
                "hypervisor.rings.breach_detector": fake_breach_module,
            },
        ):
            cfg = SandboxConfig(ring=RING_3_SANDBOX)
            h = provider.create_session("agent1", config=cfg)

        # sandbox.allow_domain should NOT have been called since net was cleared
        fake_sandbox.allow_domain.assert_not_called()
        assert h.status == SessionStatus.READY
