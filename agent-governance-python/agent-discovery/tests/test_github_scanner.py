# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""Tests for GitHub scanner dependency detection."""

import base64

import pytest

from agent_discovery.scanners.github import GitHubScanner


class _FakeResponse:
    def __init__(self, payload: dict) -> None:
        self.status_code = 200
        self.headers: dict[str, str] = {}
        self._payload = payload

    def json(self) -> dict:
        return self._payload


class _FakeClient:
    """Serves one repository whose only file is ``requirements.txt``."""

    def __init__(self, requirements: str) -> None:
        self._requirements = requirements

    async def get(self, url: str, **kwargs) -> _FakeResponse:
        if url.endswith("/git/trees/HEAD"):
            return _FakeResponse({"tree": [{"path": "requirements.txt"}]})
        if url.endswith("/contents/requirements.txt"):
            content = base64.b64encode(self._requirements.encode()).decode()
            return _FakeResponse({"content": content})
        raise AssertionError(f"unexpected request: {url}")


async def _dependency_types(requirements: str) -> list[str]:
    agents = await GitHubScanner()._scan_repo(_FakeClient(requirements), "org/repo")
    return sorted(agent.agent_type for agent in agents)


class TestDependencyDetection:
    @pytest.mark.parametrize(
        ("requirements", "expected_type"),
        [
            ("llama-index==0.12.0\n", "llamaindex"),
            ("llama-index-core>=0.12\n", "llamaindex"),
            ("pyautogen==0.2.35\n", "autogen"),
            ("semantic_kernel==1.20.0\n", "semantic-kernel"),
            ("pydantic_ai>=0.1\n", "pydantic-ai"),
            ("llama_index_core>=0.12\n", "llamaindex"),
            ("autogen_agentchat==0.4.0\n", "autogen"),
            ("langchain_core==0.3.0\n", "langchain"),
        ],
    )
    async def test_detects_published_package_names(self, requirements, expected_type):
        assert await _dependency_types(requirements) == [expected_type]

    @pytest.mark.parametrize(
        ("requirements", "expected_type"),
        [
            ("langchain-core==0.3.0\n", "langchain"),
            ("autogen-agentchat==0.4.0\n", "autogen"),
            ("semantic-kernel==1.20.0\n", "semantic-kernel"),
            ("mcp==1.2.0\n", "mcp-server"),
        ],
    )
    async def test_existing_names_still_match(self, requirements, expected_type):
        assert await _dependency_types(requirements) == [expected_type]

    @pytest.mark.parametrize(
        "requirements",
        [
            "mcpython==1.0\n",
            "fastmcp==2.0\n",
            "cautogen-fork==1.0\n",
            "autogenerate==1.0\n",
            "llamaindexer==1.0\n",
            "llama-cpp-python==0.3\n",
            "ollama==0.4\n",
        ],
    )
    async def test_name_fragments_do_not_match(self, requirements):
        assert await _dependency_types(requirements) == []

    async def test_aliases_report_one_agent_per_framework(self):
        requirements = "llama-index==0.12.0\nllamaindex-extras==1.0\n"
        assert await _dependency_types(requirements) == ["llamaindex"]
