# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""Tests for Entra Agent ID → AgentMesh registry synchronisation."""
from __future__ import annotations

from typing import Any

import httpx
import pytest

from agentmesh_agent365 import EntraRegistrySync, iter_agent_identities

entra = pytest.importorskip("agentmesh.identity.entra")

TENANT = "11111111-2222-3333-4444-555555555555"
DIDS = {"obj-1": "did:mesh:aaa", "obj-2": "did:mesh:bbb"}


def _identity(object_id: str, enabled: bool = True) -> dict[str, Any]:
    return {"id": object_id, "appId": f"app-{object_id}", "displayName": object_id, "accountEnabled": enabled}


def _sync(registry: Any, **kwargs: Any) -> EntraRegistrySync:
    return EntraRegistrySync(registry, did_for=lambda i: DIDS.get(i["id"]), **kwargs)


def test_disabled_identity_suspends_and_reenable_reactivates() -> None:
    registry = entra.EntraAgentRegistry(TENANT)
    registry.register("did:mesh:aaa", "a", "obj-1", "owner@contoso.com")
    syncer = _sync(registry)
    report = syncer.sync([_identity("obj-1", enabled=False)])
    assert report.suspended == ["did:mesh:aaa"]
    assert registry.get_by_did("did:mesh:aaa").is_active() is False
    report = syncer.sync([_identity("obj-1", enabled=True)])
    assert report.reactivated == ["did:mesh:aaa"]
    assert registry.get_by_did("did:mesh:aaa").is_active() is True


def test_sync_does_not_reactivate_agents_suspended_elsewhere() -> None:
    registry = entra.EntraAgentRegistry(TENANT)
    registry.register("did:mesh:aaa", "a", "obj-1", "owner@contoso.com")
    registry.suspend_agent("did:mesh:aaa", reason="anomaly")
    report = _sync(registry).sync([_identity("obj-1", enabled=True)])
    assert report.reactivated == []
    assert registry.get_by_did("did:mesh:aaa").is_active() is False


def test_unmapped_and_missing_are_reported_not_invented() -> None:
    registry = entra.EntraAgentRegistry(TENANT)
    registry.register("did:mesh:bbb", "b", "obj-2", "owner@contoso.com")
    report = _sync(registry, register_new=True).sync([_identity("obj-1"), _identity("obj-9")])
    assert report.unmapped == ["obj-1", "obj-9"]  # no sponsor_for → never registered
    assert report.missing_in_entra == ["did:mesh:bbb"]
    assert registry.get_by_entra_id("obj-1") is None


def test_register_new_with_sponsor() -> None:
    registry = entra.EntraAgentRegistry(TENANT)
    report = _sync(registry, register_new=True, sponsor_for=lambda i: "owner@contoso.com").sync([_identity("obj-1")])
    assert report.registered == ["did:mesh:aaa"]
    assert registry.get_by_entra_id("obj-1").entra_app_id == "app-obj-1"


def test_iter_agent_identities_pages_and_stays_on_graph() -> None:
    pages = {
        "/v1.0/servicePrincipals/microsoft.graph.agentIdentity": {
            "value": [_identity("obj-1")],
            "@odata.nextLink": "https://graph.microsoft.com/v1.0/servicePrincipals/microsoft.graph.agentIdentity?$skiptoken=2",
        },
    }

    def handler(request: httpx.Request) -> httpx.Response:
        if "skiptoken" in str(request.url):
            return httpx.Response(200, json={"value": [_identity("obj-2")]})
        return httpx.Response(200, json=pages[request.url.path])

    client = httpx.Client(transport=httpx.MockTransport(handler))
    assert [i["id"] for i in iter_agent_identities(client, lambda: "tok")] == ["obj-1", "obj-2"]

    def hostile(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json={"value": [], "@odata.nextLink": "https://evil.example/steal"})

    with pytest.raises(ValueError):
        list(iter_agent_identities(httpx.Client(transport=httpx.MockTransport(hostile)), lambda: "tok"))
