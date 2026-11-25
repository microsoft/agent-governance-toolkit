# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""Synchronise Microsoft Entra Agent ID state into an AgentMesh registry.

Agent 365 builds on Entra Agent ID: every governed agent has an
``agentIdentity`` service principal created from an
``agentIdentityBlueprint``. Microsoft Graph v1.0 lists them with::

    GET /servicePrincipals/microsoft.graph.agentIdentity

This module maps those objects onto
``agentmesh.identity.entra.EntraAgentRegistry`` so that an agent disabled in
Entra (``accountEnabled: false``) is suspended in AGT, and AGT bindings whose
Entra identity no longer exists are reported. AgentMesh DIDs derive from
agent keys, so the caller supplies ``did_for`` to map an Entra identity to its
DID; unmapped identities are reported rather than given invented DIDs.
"""

from __future__ import annotations

from collections.abc import Callable, Iterable, Iterator, Mapping
from dataclasses import dataclass, field
from typing import Any

GRAPH_BASE = "https://graph.microsoft.com/v1.0"
AGENT_IDENTITY_SELECT = "id,appId,displayName,accountEnabled,agentIdentityBlueprintId"


def iter_agent_identities(
    http: Any,
    token_provider: Callable[[], str],
    *,
    base_url: str = GRAPH_BASE,
    max_pages: int = 100,
) -> Iterator[dict[str, Any]]:
    """Yield agent identities from Microsoft Graph, following ``@odata.nextLink``."""
    url: str | None = (
        f"{base_url.rstrip('/')}/servicePrincipals/microsoft.graph.agentIdentity"
        f"?$select={AGENT_IDENTITY_SELECT}"
    )
    graph_root = base_url.rstrip("/").rsplit("/", 1)[0]
    pages = 0
    while url:
        if not url.startswith(graph_root + "/"):
            raise ValueError("refusing to follow nextLink outside Microsoft Graph")
        pages += 1
        if pages > max_pages:
            raise RuntimeError("agent identity pagination exceeded max_pages")
        response = http.get(url, headers={"Authorization": f"Bearer {token_provider()}"}, timeout=30.0)
        response.raise_for_status()
        body = response.json()
        for item in body.get("value", []):
            if isinstance(item, Mapping):
                yield dict(item)
        url = body.get("@odata.nextLink")


@dataclass
class SyncReport:
    """What an Entra → AgentMesh synchronisation changed or could not resolve."""

    registered: list[str] = field(default_factory=list)
    suspended: list[str] = field(default_factory=list)
    reactivated: list[str] = field(default_factory=list)
    unmapped: list[str] = field(default_factory=list)
    missing_in_entra: list[str] = field(default_factory=list)


class EntraRegistrySync:
    """Apply Entra agent identity state to an ``EntraAgentRegistry``.

    Args:
        registry: ``agentmesh.identity.entra.EntraAgentRegistry``.
        did_for: Returns the AgentMesh DID bound to an identity, or ``None``.
        sponsor_for: Returns the sponsor UPN for new registrations.
        register_new: Register mapped identities that the registry lacks.
            Requires ``sponsor_for``; identities without a DID or sponsor are
            skipped and reported as unmapped.

    The syncer only reactivates agents that it suspended itself, so an agent
    suspended in AGT for another reason (for example an anomaly) stays
    suspended when Entra still shows it enabled.
    """

    def __init__(
        self,
        registry: Any,
        *,
        did_for: Callable[[Mapping[str, Any]], str | None],
        sponsor_for: Callable[[Mapping[str, Any]], str] | None = None,
        register_new: bool = False,
    ) -> None:
        self.registry = registry
        self.did_for = did_for
        self.sponsor_for = sponsor_for
        self.register_new = register_new
        self._suspended_by_sync: set[str] = set()

    def sync(self, identities: Iterable[Mapping[str, Any]]) -> SyncReport:
        """Apply one snapshot of Entra agent identities."""
        report = SyncReport()
        seen: set[str] = set()
        for identity in identities:
            object_id = str(identity.get("id", ""))
            if not object_id:
                continue
            seen.add(object_id)
            enabled = identity.get("accountEnabled") is not False
            existing = self.registry.get_by_entra_id(object_id)
            if existing is None:
                did = self.did_for(identity)
                sponsor = self.sponsor_for(identity) if self.sponsor_for else ""
                if not did or not self.register_new or not sponsor:
                    report.unmapped.append(object_id)
                    continue
                existing = self.registry.register(
                    agent_did=did,
                    agent_name=str(identity.get("displayName") or did),
                    entra_object_id=object_id,
                    sponsor_email=sponsor,
                )
                existing.entra_app_id = str(identity.get("appId") or "")
                report.registered.append(did)
            did = existing.agent_did
            if not enabled and existing.is_active():
                self.registry.suspend_agent(did, reason="Entra agent identity disabled")
                self._suspended_by_sync.add(did)
                report.suspended.append(did)
            elif enabled and did in self._suspended_by_sync:
                if self.registry.reactivate_agent(did):
                    report.reactivated.append(did)
                self._suspended_by_sync.discard(did)

        for agent in self.registry.list_agents():
            if agent.entra_object_id not in seen:
                report.missing_in_entra.append(agent.agent_did)
        return report
