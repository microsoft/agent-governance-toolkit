# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""Tests for the community fallbacks in agent_sre.providers."""

import pytest

from agent_sre import providers


@pytest.fixture(autouse=True)
def no_advanced_provider(monkeypatch):
    monkeypatch.setattr(providers, "_discover_provider", lambda group: None)


@pytest.mark.parametrize(
    "getter, group, missing",
    [
        (
            "get_slo_detector",
            "agent_sre.providers.slo_detection",
            "agent_sre.slo.detector.SLODetector",
        ),
        (
            "get_chaos_engine",
            "agent_sre.providers.chaos_engine",
            "agent_sre.chaos.engine.ChaosEngine",
        ),
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
        "slo_detection": "unavailable",
        "replay_engine": "community",
        "chaos_engine": "unavailable",
        "cost_optimizer": "community",
        "delivery": "community",
        "incident": "community",
    }


def test_list_providers_reports_advanced_provider_for_slot_without_community_implementation(
    monkeypatch,
):
    monkeypatch.setattr(
        providers,
        "_discover_provider",
        lambda group: object if group == "agent_sre.providers.chaos_engine" else None,
    )
    assert providers.list_providers()["chaos_engine"] == "advanced"


# Getter for each provider slot that has one.
_GETTERS = {
    "slo_detection": "get_slo_detector",
    "replay_engine": "get_replay_engine",
    "chaos_engine": "get_chaos_engine",
    "cost_optimizer": "get_cost_optimizer",
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
