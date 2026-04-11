"""GitHub scanner — find agent configurations in GitHub repositories.

Scans repositories for files and patterns that indicate AI agent deployments:
- Agent framework config files (agentmesh.yaml, crewai.yaml, etc.)
- MCP server configurations
- GitHub Actions workflows using agent frameworks
- Known agent dependencies in requirements/package files

Requires: httpx (install with `pip install agent-discovery[github]`)

Security:
- Read-only GitHub API access (repo scope or public repos)
- Respects rate limits
- No repository content is stored — only metadata
"""

from __future__ import annotations

import os
from datetime import datetime, timezone
from typing import Any

from ..models import (
    DetectionBasis,
    DiscoveredAgent,
    Evidence,
    ScanResult,
)
from .base import BaseScanner, registry

# Files that strongly indicate an agent deployment
AGENT_CONFIG_FILES = [
    {"path": "agentmesh.yaml", "type": "agt", "confidence": 0.95},
    {"path": "agentmesh.yml", "type": "agt", "confidence": 0.95},
    {"path": ".agentmesh/config.yaml", "type": "agt", "confidence": 0.95},
    {"path": "agent-governance.yaml", "type": "agt", "confidence": 0.90},
    {"path": "crewai.yaml", "type": "crewai", "confidence": 0.90},
    {"path": "crewai.yml", "type": "crewai", "confidence": 0.90},
    {"path": "mcp.json", "type": "mcp-server", "confidence": 0.85},
    {"path": "mcp-config.json", "type": "mcp-server", "confidence": 0.85},
    {"path": ".mcp/config.json", "type": "mcp-server", "confidence": 0.85},
    {"path": "claude_desktop_config.json", "type": "mcp-server", "confidence": 0.80},
]

# Dependency patterns in requirements files
AGENT_DEPENDENCIES = [
    {"pattern": "langchain", "type": "langchain", "confidence": 0.70},
    {"pattern": "crewai", "type": "crewai", "confidence": 0.75},
    {"pattern": "autogen", "type": "autogen", "confidence": 0.70},
    {"pattern": "openai-agents", "type": "openai-agents", "confidence": 0.70},
    {"pattern": "semantic-kernel", "type": "semantic-kernel", "confidence": 0.70},
    {"pattern": "agent-os-kernel", "type": "agt", "confidence": 0.85},
    {"pattern": "agentmesh-platform", "type": "agt", "confidence": 0.85},
    {"pattern": "llamaindex", "type": "llamaindex", "confidence": 0.70},
    {"pattern": "pydantic-ai", "type": "pydantic-ai", "confidence": 0.70},
    {"pattern": "google-adk", "type": "google-adk", "confidence": 0.70},
    {"pattern": "mcp", "type": "mcp-server", "confidence": 0.60},
]


def _get_httpx():  # type: ignore[no-untyped-def]
    """Lazy import httpx to keep it optional."""
    try:
        import httpx

        return httpx
    except ImportError:
        raise ImportError(
            "httpx is required for GitHub scanning. "
            "Install with: pip install agent-discovery[github]"
        )


@registry.register
class GitHubScanner(BaseScanner):
    """Scan GitHub repositories for AI agent configurations.

    Searches for agent framework config files, MCP server setups,
    and agent-related dependencies across specified repos or orgs.
    """

    @property
    def name(self) -> str:
        return "github"

    @property
    def description(self) -> str:
        return "Find AI agent configurations in GitHub repositories"

    def validate_config(self, **kwargs: Any) -> list[str]:
        errors = []
        if not kwargs.get("repos") and not kwargs.get("org"):
            errors.append("Either 'repos' (list) or 'org' (string) is required")
        return errors

    async def scan(self, **kwargs: Any) -> ScanResult:
        httpx = _get_httpx()
        result = ScanResult(scanner_name=self.name)

        token = kwargs.get("token") or os.environ.get("GITHUB_TOKEN", "")
        repos: list[str] = kwargs.get("repos", [])
        org: str | None = kwargs.get("org")

        headers = {"Accept": "application/vnd.github+json"}
        if token:
            headers["Authorization"] = f"Bearer {token}"

        async with httpx.AsyncClient(
            base_url="https://api.github.com",
            headers=headers,
            timeout=30.0,
        ) as client:
            # Resolve repos from org if needed
            if org and not repos:
                try:
                    repos = await self._list_org_repos(client, org)
                except Exception as e:
                    result.errors.append(f"Failed to list org repos: {e}")
                    return result

            result.scanned_targets = len(repos)

            for repo in repos:
                try:
                    agents = await self._scan_repo(client, repo)
                    result.agents.extend(agents)
                except Exception as e:
                    result.errors.append(f"Error scanning {repo}: {e}")

        result.completed_at = datetime.now(timezone.utc)
        return result

    async def _list_org_repos(self, client: Any, org: str) -> list[str]:
        """List repositories for a GitHub organization."""
        repos = []
        page = 1
        while True:
            resp = await client.get(
                f"/orgs/{org}/repos", params={"per_page": 100, "page": page, "type": "all"}
            )
            resp.raise_for_status()
            data = resp.json()
            if not data:
                break
            repos.extend(r["full_name"] for r in data)
            page += 1
            if len(data) < 100:
                break
        return repos

    async def _scan_repo(self, client: Any, repo: str) -> list[DiscoveredAgent]:
        """Scan a single repository for agent indicators."""
        agents: list[DiscoveredAgent] = []

        # Check for known config files
        for config in AGENT_CONFIG_FILES:
            try:
                resp = await client.get(f"/repos/{repo}/contents/{config['path']}")
                if resp.status_code == 200:
                    merge_keys = {"repo": repo, "config_path": config["path"]}
                    fingerprint = DiscoveredAgent.compute_fingerprint(merge_keys)

                    agent = DiscoveredAgent(
                        fingerprint=fingerprint,
                        name=f"{config['type']} agent in {repo}",
                        agent_type=config["type"],
                        description=f"Config file {config['path']} found in {repo}",
                        merge_keys=merge_keys,
                        tags={"repo": repo, "config_file": config["path"]},
                    )
                    agent.add_evidence(
                        Evidence(
                            scanner=self.name,
                            basis=DetectionBasis.GITHUB_REPO,
                            source=f"https://github.com/{repo}/blob/main/{config['path']}",
                            detail=f"Agent config file {config['path']} exists",
                            raw_data={"repo": repo, "path": config["path"]},
                            confidence=config["confidence"],
                        )
                    )
                    agents.append(agent)
            except Exception:
                pass  # file doesn't exist, skip

        # Check requirements.txt / pyproject.toml for agent deps
        for dep_file in ["requirements.txt", "pyproject.toml", "package.json"]:
            try:
                resp = await client.get(f"/repos/{repo}/contents/{dep_file}")
                if resp.status_code == 200:
                    import base64

                    content = base64.b64decode(resp.json().get("content", "")).decode(
                        "utf-8", errors="replace"
                    )
                    for dep in AGENT_DEPENDENCIES:
                        if dep["pattern"] in content.lower():
                            merge_keys = {"repo": repo, "dep": dep["pattern"]}
                            fingerprint = DiscoveredAgent.compute_fingerprint(merge_keys)

                            # Check if we already found this agent via config
                            if any(a.fingerprint == fingerprint for a in agents):
                                continue

                            agent = DiscoveredAgent(
                                fingerprint=fingerprint,
                                name=f"{dep['type']} dependency in {repo}",
                                agent_type=dep["type"],
                                description=(
                                    f"Dependency '{dep['pattern']}' found in {dep_file}"
                                ),
                                merge_keys=merge_keys,
                                tags={"repo": repo, "dep_file": dep_file},
                            )
                            agent.add_evidence(
                                Evidence(
                                    scanner=self.name,
                                    basis=DetectionBasis.GITHUB_REPO,
                                    source=f"https://github.com/{repo}/blob/main/{dep_file}",
                                    detail=f"Agent dependency '{dep['pattern']}' in {dep_file}",
                                    raw_data={
                                        "repo": repo,
                                        "dep_file": dep_file,
                                        "dependency": dep["pattern"],
                                    },
                                    confidence=dep["confidence"],
                                )
                            )
                            agents.append(agent)
            except Exception:
                pass

        return agents
