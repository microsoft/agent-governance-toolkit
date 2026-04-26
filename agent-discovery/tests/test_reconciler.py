"""Tests for reconciler and registry providers."""

import pytest

from agent_discovery.inventory import AgentInventory
from agent_discovery.models import (
    AgentStatus,
    DetectionBasis,
    DiscoveredAgent,
    Evidence,
    ScanResult,
)
from agent_discovery.reconciler import Reconciler, StaticRegistryProvider


def _make_agent(fp: str, name: str, did: str | None = None) -> DiscoveredAgent:
    agent = DiscoveredAgent(fingerprint=fp, name=name, did=did)
    agent.add_evidence(
        Evidence(
            scanner="test",
            basis=DetectionBasis.MANUAL,
            source="test",
            detail="test",
            confidence=0.8,
        )
    )
    return agent


class TestStaticRegistryProvider:
    @pytest.mark.asyncio
    async def test_empty_registry(self):
        provider = StaticRegistryProvider()
        agents = await provider.list_registered_agents()
        assert agents == []

    @pytest.mark.asyncio
    async def test_match_by_did(self):
        provider = StaticRegistryProvider([
            {"did": "did:agent:abc123", "name": "Known Agent"},
        ])
        agent = _make_agent("x", "Test", did="did:agent:abc123")
        assert await provider.is_registered(agent)

    @pytest.mark.asyncio
    async def test_no_match(self):
        provider = StaticRegistryProvider([
            {"did": "did:agent:other", "name": "Other Agent"},
        ])
        agent = _make_agent("x", "Unknown Agent")
        assert not await provider.is_registered(agent)

    @pytest.mark.asyncio
    async def test_match_by_fingerprint(self):
        provider = StaticRegistryProvider([
            {"fingerprint": "fp123", "name": "Known"},
        ])
        agent = _make_agent("fp123", "Test Agent")
        assert await provider.is_registered(agent)


class TestReconciler:
    @pytest.mark.asyncio
    async def test_all_registered(self):
        inv = AgentInventory()
        inv.ingest(ScanResult(
            scanner_name="test",
            agents=[_make_agent("a", "Agent A", did="did:agent:a")],
        ))
        provider = StaticRegistryProvider([
            {"did": "did:agent:a", "name": "Agent A"},
        ])
        reconciler = Reconciler(inv, provider)
        shadows = await reconciler.reconcile()
        assert len(shadows) == 0
        assert inv.get("a").status == AgentStatus.REGISTERED

    @pytest.mark.asyncio
    async def test_shadow_detected(self):
        inv = AgentInventory()
        inv.ingest(ScanResult(
            scanner_name="test",
            agents=[
                _make_agent("a", "Registered", did="did:agent:a"),
                _make_agent("b", "Shadow Agent"),
            ],
        ))
        provider = StaticRegistryProvider([
            {"did": "did:agent:a", "name": "Registered"},
        ])
        reconciler = Reconciler(inv, provider)
        shadows = await reconciler.reconcile()
        assert len(shadows) == 1
        assert shadows[0].agent.fingerprint == "b"
        assert shadows[0].agent.status == AgentStatus.SHADOW

    @pytest.mark.asyncio
    async def test_recommendations_generated(self):
        inv = AgentInventory()
        inv.ingest(ScanResult(
            scanner_name="test",
            agents=[_make_agent("x", "Unknown Agent")],
        ))
        provider = StaticRegistryProvider()
        reconciler = Reconciler(inv, provider)
        shadows = await reconciler.reconcile()
        assert len(shadows) == 1
        assert len(shadows[0].recommended_actions) > 0

    @pytest.mark.asyncio
    async def test_mcp_server_gets_scan_recommendation(self):
        inv = AgentInventory()
        agent = _make_agent("m", "MCP Server")
        agent.agent_type = "mcp-server"
        inv.ingest(ScanResult(scanner_name="test", agents=[agent]))
        provider = StaticRegistryProvider()
        reconciler = Reconciler(inv, provider)
        shadows = await reconciler.reconcile()
        actions = shadows[0].recommended_actions
        assert any("mcp-scan" in a for a in actions)
