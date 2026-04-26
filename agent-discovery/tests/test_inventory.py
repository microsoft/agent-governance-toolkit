"""Tests for agent inventory with deduplication."""

import json
import tempfile
from pathlib import Path

import pytest

from agent_discovery.inventory import AgentInventory
from agent_discovery.models import (
    AgentStatus,
    DetectionBasis,
    DiscoveredAgent,
    Evidence,
    ScanResult,
)


def _make_agent(fp: str, name: str, agent_type: str = "test") -> DiscoveredAgent:
    agent = DiscoveredAgent(fingerprint=fp, name=name, agent_type=agent_type)
    agent.add_evidence(
        Evidence(
            scanner="test",
            basis=DetectionBasis.MANUAL,
            source="test",
            detail="test evidence",
            confidence=0.8,
        )
    )
    return agent


class TestAgentInventory:
    def test_ingest_new_agents(self):
        inv = AgentInventory()
        result = ScanResult(
            scanner_name="test",
            agents=[_make_agent("a", "Agent A"), _make_agent("b", "Agent B")],
        )
        stats = inv.ingest(result)
        assert stats["new"] == 2
        assert stats["updated"] == 0
        assert inv.count == 2

    def test_deduplication(self):
        inv = AgentInventory()
        result1 = ScanResult(scanner_name="s1", agents=[_make_agent("a", "Agent A")])
        result2 = ScanResult(scanner_name="s2", agents=[_make_agent("a", "Agent A v2")])
        inv.ingest(result1)
        stats = inv.ingest(result2)
        assert stats["new"] == 0
        assert stats["updated"] == 1
        assert inv.count == 1
        # Evidence should be merged
        agent = inv.get("a")
        assert agent is not None
        assert len(agent.evidence) == 2

    def test_search_by_type(self):
        inv = AgentInventory()
        inv.ingest(
            ScanResult(
                scanner_name="test",
                agents=[
                    _make_agent("a", "LangChain A", "langchain"),
                    _make_agent("b", "MCP Server", "mcp-server"),
                    _make_agent("c", "LangChain B", "langchain"),
                ],
            )
        )
        results = inv.search(agent_type="langchain")
        assert len(results) == 2

    def test_search_by_status(self):
        inv = AgentInventory()
        agent = _make_agent("a", "Shadow")
        agent.status = AgentStatus.SHADOW
        inv.ingest(ScanResult(scanner_name="test", agents=[agent]))
        results = inv.search(status=AgentStatus.SHADOW)
        assert len(results) == 1

    def test_search_by_confidence(self):
        inv = AgentInventory()
        inv.ingest(
            ScanResult(
                scanner_name="test",
                agents=[_make_agent("a", "High"), _make_agent("b", "Low")],
            )
        )
        # Both have 0.8 confidence from _make_agent
        results = inv.search(min_confidence=0.9)
        assert len(results) == 0
        results = inv.search(min_confidence=0.7)
        assert len(results) == 2

    def test_remove(self):
        inv = AgentInventory()
        inv.ingest(ScanResult(scanner_name="test", agents=[_make_agent("a", "Agent")]))
        assert inv.remove("a")
        assert inv.count == 0
        assert not inv.remove("nonexistent")

    def test_clear(self):
        inv = AgentInventory()
        inv.ingest(
            ScanResult(scanner_name="test", agents=[_make_agent("a", "A"), _make_agent("b", "B")])
        )
        inv.clear()
        assert inv.count == 0

    def test_persistence(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            path = Path(tmpdir) / "inventory.json"

            # Create and save
            inv1 = AgentInventory(storage_path=path)
            inv1.ingest(ScanResult(scanner_name="test", agents=[_make_agent("a", "Persistent")]))
            assert path.exists()

            # Load in new instance
            inv2 = AgentInventory(storage_path=path)
            assert inv2.count == 1
            assert inv2.get("a") is not None
            assert inv2.get("a").name == "Persistent"

    def test_export_json(self):
        inv = AgentInventory()
        inv.ingest(ScanResult(scanner_name="test", agents=[_make_agent("a", "JSON Agent")]))
        exported = inv.export_json()
        data = json.loads(exported)
        assert len(data) == 1
        assert data[0]["name"] == "JSON Agent"

    def test_summary(self):
        inv = AgentInventory()
        inv.ingest(
            ScanResult(
                scanner_name="test",
                agents=[
                    _make_agent("a", "A", "langchain"),
                    _make_agent("b", "B", "mcp-server"),
                    _make_agent("c", "C", "langchain"),
                ],
            )
        )
        summary = inv.summary()
        assert summary["total_agents"] == 3
        assert summary["by_type"]["langchain"] == 2
        assert summary["by_type"]["mcp-server"] == 1
