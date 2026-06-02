# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""Tests for the CaaS unauthenticated-surface startup gate.

The CaaS FastAPI app exposes routes without authentication. To prevent
accidental shared-network exposure, ``caas.api.server`` requires either
``AGENT_OS_ENV`` to be local/dev/development OR an explicit
``CAAS_UNSAFE_ALLOW_UNAUTH=1`` operator opt-in. Anything else must fail
closed on startup.
"""
from __future__ import annotations

import asyncio

import pytest


def _gate():
    from caas.api import server as srv
    return srv


class TestCaasUnauthGate:
    def test_local_env_satisfies_gate(self, monkeypatch):
        monkeypatch.setenv("AGENT_OS_ENV", "local")
        monkeypatch.delenv("CAAS_UNSAFE_ALLOW_UNAUTH", raising=False)
        allowed, _ = _gate()._caas_unauth_gate_satisfied()
        assert allowed is True

    @pytest.mark.parametrize("env", ["dev", "development", "LOCAL"])
    def test_dev_envs_satisfy_gate(self, monkeypatch, env):
        monkeypatch.setenv("AGENT_OS_ENV", env)
        monkeypatch.delenv("CAAS_UNSAFE_ALLOW_UNAUTH", raising=False)
        allowed, _ = _gate()._caas_unauth_gate_satisfied()
        assert allowed is True

    def test_explicit_opt_in_satisfies_gate(self, monkeypatch):
        monkeypatch.setenv("AGENT_OS_ENV", "production")
        monkeypatch.setenv("CAAS_UNSAFE_ALLOW_UNAUTH", "1")
        allowed, _ = _gate()._caas_unauth_gate_satisfied()
        assert allowed is True

    @pytest.mark.parametrize("val", ["true", "yes", "on"])
    def test_explicit_opt_in_truthy_values(self, monkeypatch, val):
        monkeypatch.setenv("AGENT_OS_ENV", "production")
        monkeypatch.setenv("CAAS_UNSAFE_ALLOW_UNAUTH", val)
        allowed, _ = _gate()._caas_unauth_gate_satisfied()
        assert allowed is True

    def test_production_env_without_opt_in_blocks(self, monkeypatch):
        monkeypatch.setenv("AGENT_OS_ENV", "production")
        monkeypatch.delenv("CAAS_UNSAFE_ALLOW_UNAUTH", raising=False)
        allowed, _ = _gate()._caas_unauth_gate_satisfied()
        assert allowed is False

    def test_unset_env_blocks(self, monkeypatch):
        monkeypatch.delenv("AGENT_OS_ENV", raising=False)
        monkeypatch.delenv("CAAS_UNSAFE_ALLOW_UNAUTH", raising=False)
        allowed, _ = _gate()._caas_unauth_gate_satisfied()
        assert allowed is False

    def test_falsy_opt_in_does_not_satisfy_gate(self, monkeypatch):
        monkeypatch.setenv("AGENT_OS_ENV", "production")
        monkeypatch.setenv("CAAS_UNSAFE_ALLOW_UNAUTH", "0")
        allowed, _ = _gate()._caas_unauth_gate_satisfied()
        assert allowed is False

    def test_startup_hook_raises_when_gate_fails(self, monkeypatch):
        monkeypatch.setenv("AGENT_OS_ENV", "production")
        monkeypatch.delenv("CAAS_UNSAFE_ALLOW_UNAUTH", raising=False)
        srv = _gate()
        with pytest.raises(RuntimeError, match="unauthenticated surface"):
            asyncio.run(srv._enforce_unauthenticated_surface_gate())

    def test_startup_hook_passes_when_gate_satisfied(self, monkeypatch):
        monkeypatch.setenv("AGENT_OS_ENV", "local")
        srv = _gate()
        # Should not raise
        asyncio.run(srv._enforce_unauthenticated_surface_gate())
