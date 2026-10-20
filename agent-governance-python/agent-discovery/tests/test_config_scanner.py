# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""Tests for the filesystem config scanner."""

import pytest

from agent_discovery.risk import RiskScorer
from agent_discovery.scanners.config import ConfigScanner


async def _scan_dockerfile(tmp_path, content: str):
    (tmp_path / "Dockerfile").write_text(content, encoding="utf-8")
    result = await ConfigScanner().scan(paths=[str(tmp_path)])
    assert result.errors == []
    assert len(result.agents) == 1
    return result.agents[0]


class TestDockerAgentType:
    @pytest.mark.parametrize(
        ("content", "expected_type"),
        [
            ("RUN pip install langgraph", "langchain"),
            ("RUN pip install LangChain", "langchain"),
            ("RUN pip install crewai", "crewai"),
            ("RUN pip install autogen-agentchat", "autogen"),
            ("RUN pip install agent_governance", "agt"),
            ("CMD python -m my_mcp_server", "mcp-server"),
            ("RUN pip install semantic_kernel", "semantic-kernel"),
        ],
    )
    async def test_reports_the_canonical_agent_type(self, tmp_path, content, expected_type):
        agent = await _scan_dockerfile(tmp_path, content)
        assert agent.agent_type == expected_type

    async def test_container_agent_type_drives_risk_scoring(self, tmp_path):
        agent = await _scan_dockerfile(tmp_path, "RUN pip install semantic_kernel")
        risk = RiskScorer().score(agent)
        assert "Medium-risk agent type: semantic-kernel" in risk.factors

    async def test_fingerprint_keeps_the_matched_pattern(self, tmp_path):
        agent = await _scan_dockerfile(tmp_path, "RUN pip install langgraph")
        assert agent.merge_keys["pattern"] == "langchain|langgraph"
