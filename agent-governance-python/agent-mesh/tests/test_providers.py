# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""Tests for the community fallbacks in agentmesh.providers."""

import pytest

from agentmesh import providers
from agentmesh.reward.trust_decay import NetworkTrustEngine
from agentmesh.trust.capability import CapabilityRegistry


@pytest.fixture(autouse=True)
def no_advanced_provider(monkeypatch):
    monkeypatch.setattr(providers, "_discover_provider", lambda group: None)


def test_get_trust_decay_falls_back_to_network_trust_engine():
    engine = providers.get_trust_decay(decay_rate=1.5)
    assert isinstance(engine, NetworkTrustEngine)
    assert engine.decay_rate == 1.5


def test_get_capability_engine_falls_back_to_capability_registry():
    assert isinstance(providers.get_capability_engine(), CapabilityRegistry)


@pytest.mark.parametrize(
    "getter, group, missing",
    [
        (
            "get_delegation_chain",
            "agentmesh.providers.delegation",
            "agentmesh.identity.delegation.DelegationChain",
        ),
        ("get_audit_logger", "agentmesh.providers.audit", "agentmesh.governance.audit.AuditLogger"),
    ],
)
def test_getter_without_community_implementation_raises_clear_error(getter, group, missing):
    with pytest.raises(NotImplementedError) as exc_info:
        getattr(providers, getter)()
    assert str(exc_info.value) == (
        f"{getter}() has no community implementation ({missing} does not exist). "
        f"Install a provider package that registers an entry point in the '{group}' group."
    )
