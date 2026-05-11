# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""GitHub scanner -- find agent configurations in GitHub repositories.

Scans repositories for files and patterns that indicate AI agent deployments:
- Agent framework config files (agentmesh.yaml, crewai.yaml, etc.)
- MCP server configurations
- GitHub Actions workflows using agent frameworks
- Known agent dependencies in requirements/package files

Requires: httpx (install with `pip install agent-discovery[github]`)

Security:
- Read-only GitHub API access (repo scope or public repos)
- Respects rate limits with automatic backoff
- No repository content is stored -- only metadata
"""

from __future__ import annotations

import asyncio
import base64
import logging
import os
import re
import time
from datetime import datetime, timezone
from typing import Any

from ..models import (
    DetectionBasis,
    DiscoveredAgent,
    Evidence,
    ScanResult,
)
from .base import BaseScanner, registry

logger = logging.getLogger(__name__)

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

# Set of config file paths for fast lookup
_CONFIG_PATHS = {c["path"] for c in AGENT_CONFIG_FILES}
_CONFIG_BY_PATH = {c["path"]: c for c in AGENT_CONFIG_FILES}

# Dependency files to check for agent framework imports
_DEP_FILES = {"requirements.txt", "pyproject.toml", "package.json"}

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

# Rate limit safety margin: pause when remaining requests drop below this
_RATE_LIMIT_FLOOR = 50
_BACKOFF_BASE = 1.0
_BACKOFF_MAX = 60.0


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


async def _rate_limit_wait(resp: Any) -> None:
    """Sleep if the response indicates we are close to the rate limit."""
    remaining = resp.headers.get("x-ratelimit-remaining")
    reset = resp.headers.get("x-ratelimit-reset")
    if remaining is not None and int(remaining) < _RATE_LIMIT_FLOOR and reset:
        wait = max(0, int(reset) - int(time.time())) + 1
        wait = min(wait, _BACKOFF_MAX)
        logger.warning("GitHub API rate limit low (%s remaining), pausing %ds", remaining, wait)
        await asyncio.sleep(wait)


async def _request_with_backoff(client: Any, method: str, url: str, **kwargs: Any) -> Any:
    """Make an HTTP request with exponential backoff on rate limit errors.

    Honors `method` as the HTTP verb name (e.g. "get", "post"). The
    previous implementation had two dead-code lines that pre-computed
    a bound method handle then immediately re-issued a hardcoded
    client.get() — `post` and any other verb silently fell back to
    GET. Dispatch via getattr matches the documented contract.
    """
    delay = _BACKOFF_BASE
    resp = None
    for attempt in range(4):
        verb = getattr(client, method)
        resp = await verb(url, **kwargs)

        if resp.status_code == 403 or resp.status_code == 429:
            retry_after = resp.headers.get("retry-after")
            reset = resp.headers.get("x-ratelimit-reset")
            if retry_after:
                wait = int(retry_after)
            elif reset:
                wait = max(0, int(reset) - int(time.time())) + 1
            else:
                wait = delay

            wait = min(wait, _BACKOFF_MAX)
            if attempt < 3:
                logger.warning(
                    "Rate limited (HTTP %d) on %s, retrying in %ds (attempt %d/4)",
                    resp.status_code, url, wait, attempt + 1,
                )
                await asyncio.sleep(wait)
                delay = min(delay * 2, _BACKOFF_MAX)
                continue
            else:
                logger.error("Rate limited on %s after 4 attempts, giving up", url)

        await _rate_limit_wait(resp)
        return resp

    return resp


@registry.register
class GitHubScanner(BaseScanner):
    """Scan GitHub repositories for AI agent configurations.

    Searches for agent framework config files, MCP server setups,
    and agent-related dependencies across specified repos or orgs.

    Uses the Git Tree API to minimize API calls (1 call per repo
    instead of 13+). Includes automatic rate limit detection and
    exponential backoff.
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

        if not token:
            logger.warning(
                "No GITHUB_TOKEN set. Unauthenticated requests are limited to "
                "60/hour. Set GITHUB_TOKEN for 5,000/hour."
            )

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
            resp = await _request_with_backoff(
                client, "get",
                f"/orgs/{org}/repos",
                params={"per_page": 100, "page": page, "type": "all"},
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
        """Scan a single repository for agent indicators.

        Uses the Git Tree API to fetch the full file tree in a single
        request, then checks locally for config files and fetches only
        the dependency files that exist. This reduces API calls from
        13+ per repo down to 1-4.
        """
        agents: list[DiscoveredAgent] = []

        # Fetch repo file tree in one call (recursive)
        resp = await _request_with_backoff(
            client, "get",
            f"/repos/{repo}/git/trees/HEAD",
            params={"recursive": "1"},
        )

        if resp.status_code != 200:
            logger.debug("Could not fetch tree for %s (HTTP %d)", repo, resp.status_code)
            return agents

        tree = resp.json().get("tree", [])
        tree_paths = {item["path"] for item in tree}

        # Check for known config files using the tree (no extra API calls)
        for config in AGENT_CONFIG_FILES:
            if config["path"] in tree_paths:
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
                        source=f"https://github.com/{repo}/blob/HEAD/{config['path']}",
                        detail=f"Agent config file {config['path']} exists",
                        raw_data={"repo": repo, "path": config["path"]},
                        confidence=config["confidence"],
                    )
                )
                agents.append(agent)

        # Only fetch dependency files that actually exist in the tree
        for dep_file in _DEP_FILES:
            if dep_file not in tree_paths:
                continue
            try:
                resp = await _request_with_backoff(
                    client, "get", f"/repos/{repo}/contents/{dep_file}"
                )
                if resp.status_code != 200:
                    continue

                content = base64.b64decode(resp.json().get("content", "")).decode(
                    "utf-8", errors="replace"
                )
                lowered = content.lower()
                for dep in AGENT_DEPENDENCIES:
                    pattern = dep["pattern"]
                    # Use a word-boundary regex so `"mcp"` doesn't
                    # match `mcpython`, `"autogen"` doesn't match
                    # `cautogen-fork`, etc. Substring matching of
                    # short package names against arbitrary file
                    # content produces false positives at scale; the
                    # \b anchors prevent name-fragment collisions
                    # without committing to a full manifest parser
                    # (which would be the structurally-correct fix).
                    if re.search(rf"\b{re.escape(pattern)}\b", lowered):
                        merge_keys = {"repo": repo, "dep": dep["pattern"]}
                        fingerprint = DiscoveredAgent.compute_fingerprint(merge_keys)

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
                                source=f"https://github.com/{repo}/blob/HEAD/{dep_file}",
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
            except Exception:  # noqa: S110
                pass

        return agents
