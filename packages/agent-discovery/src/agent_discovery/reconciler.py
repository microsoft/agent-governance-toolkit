"""Reconciler — compare discovered agents against governance registries.

The reconciler uses a `RegistryProvider` interface so it can work with
any governance registry (AgentMesh, custom CMDB, etc.) without hard coupling.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Any

from .models import AgentStatus, DiscoveredAgent, ShadowAgent
from .inventory import AgentInventory


class RegistryProvider(ABC):
    """Abstract interface for agent governance registries.

    Implement this to connect discovery reconciliation to your
    governance system (AgentMesh, custom CMDB, etc.).
    """

    @abstractmethod
    async def list_registered_agents(self) -> list[dict[str, Any]]:
        """Return all registered agents as dicts with at minimum:
        - 'did' or 'agent_id': unique identifier
        - 'name': agent name
        - 'owner': responsible party
        """

    @abstractmethod
    async def is_registered(self, agent: DiscoveredAgent) -> bool:
        """Check if a discovered agent matches any registered agent."""


class StaticRegistryProvider(RegistryProvider):
    """Simple registry provider backed by a static list.

    Useful for testing and for organizations that maintain agent
    inventories in spreadsheets or CMDBs.
    """

    def __init__(self, agents: list[dict[str, Any]] | None = None) -> None:
        self._agents = agents or []

    async def list_registered_agents(self) -> list[dict[str, Any]]:
        return self._agents

    async def is_registered(self, agent: DiscoveredAgent) -> bool:
        for reg in self._agents:
            # Match by DID
            if agent.did and reg.get("did") == agent.did:
                return True
            # Match by name (fuzzy)
            if reg.get("name") and reg["name"].lower() in agent.name.lower():
                return True
            # Match by fingerprint
            if reg.get("fingerprint") == agent.fingerprint:
                return True
        return False


class Reconciler:
    """Compare discovered agents against a governance registry.

    Identifies shadow agents (discovered but not registered) and
    updates inventory status accordingly.
    """

    def __init__(
        self,
        inventory: AgentInventory,
        registry_provider: RegistryProvider,
    ) -> None:
        self._inventory = inventory
        self._registry = registry_provider

    async def reconcile(self) -> list[ShadowAgent]:
        """Run reconciliation and return shadow agents.

        For each agent in the inventory:
        - If registered → mark as REGISTERED
        - If not registered → mark as SHADOW and return as ShadowAgent
        """
        shadow_agents: list[ShadowAgent] = []

        for agent in self._inventory.agents:
            is_reg = await self._registry.is_registered(agent)

            if is_reg:
                agent.status = AgentStatus.REGISTERED
            else:
                agent.status = AgentStatus.SHADOW
                shadow = ShadowAgent(
                    agent=agent,
                    recommended_actions=self._recommend_actions(agent),
                )
                shadow_agents.append(shadow)

        return shadow_agents

    def _recommend_actions(self, agent: DiscoveredAgent) -> list[str]:
        """Generate recommended actions for a shadow agent."""
        actions = []

        if agent.confidence >= 0.8:
            actions.append(
                "Register this agent with AgentMesh to establish governance identity"
            )
        else:
            actions.append(
                "Investigate to confirm this is an active AI agent"
            )

        if not agent.owner:
            actions.append("Assign an owner responsible for this agent's lifecycle")

        if agent.agent_type == "mcp-server":
            actions.append(
                "Run `agent-governance mcp-scan` to check for tool poisoning vulnerabilities"
            )

        actions.append("Apply least-privilege capability policies via Agent OS")

        return actions
