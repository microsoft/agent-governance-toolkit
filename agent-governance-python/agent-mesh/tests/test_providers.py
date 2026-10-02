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


def test_list_providers_marks_slots_without_community_implementation():
    assert providers.list_providers() == {
        "reward_engine": "community",
        "trust_bridge": "community",
        "delegation": "unavailable",
        "audit": "unavailable",
        "trust_decay": "community",
        "capability": "community",
    }


def test_list_providers_reports_advanced_provider_for_slot_without_community_implementation(
    monkeypatch,
):
    monkeypatch.setattr(
        providers,
        "_discover_provider",
        lambda group: object if group == "agentmesh.providers.delegation" else None,
    )
    assert providers.list_providers()["delegation"] == "advanced"


# Getter for each provider slot that has one.
_GETTERS = {
    "reward_engine": "get_reward_engine",
    "trust_bridge": "get_trust_bridge",
    "delegation": "get_delegation_chain",
    "audit": "get_audit_logger",
    "trust_decay": "get_trust_decay",
    "capability": "get_capability_engine",
}


def test_every_getter_is_mapped_to_a_slot():
    module_getters = {name for name in dir(providers) if name.startswith("get_")}
    assert module_getters == set(_GETTERS.values())
    assert set(_GETTERS) <= set(providers.PROVIDER_GROUPS)


@pytest.mark.parametrize("slot, getter", sorted(_GETTERS.items()))
def test_unavailable_slots_match_getters_that_raise(slot, getter):
    try:
        getattr(providers, getter)()
    except NotImplementedError:
        raised = True
    except Exception:
        raised = False
    else:
        raised = False
    assert raised == (slot in providers._NO_COMMUNITY_IMPLEMENTATION)
