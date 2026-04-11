"""Config/artifact scanner — find agent configurations on the filesystem.

Scans directories for files that indicate AI agent deployments:
- Agent framework configs (agentmesh.yaml, crewai.yaml, etc.)
- MCP server configurations
- Docker/Compose/Helm files with agent images
- Known agent framework patterns in Python/JS source

Security:
- Read-only filesystem access
- Scoped to explicitly provided directories
- No file contents stored — only metadata and path
"""

from __future__ import annotations

import os
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from ..models import (
    DetectionBasis,
    DiscoveredAgent,
    Evidence,
    ScanResult,
)
from .base import BaseScanner, registry

# Config files that indicate agent deployments
CONFIG_PATTERNS: list[dict[str, Any]] = [
    {"glob": "agentmesh.yaml", "type": "agt", "confidence": 0.95},
    {"glob": "agentmesh.yml", "type": "agt", "confidence": 0.95},
    {"glob": ".agentmesh/config.yaml", "type": "agt", "confidence": 0.95},
    {"glob": "agent-governance.yaml", "type": "agt", "confidence": 0.90},
    {"glob": "crewai.yaml", "type": "crewai", "confidence": 0.90},
    {"glob": "crewai.yml", "type": "crewai", "confidence": 0.90},
    {"glob": "mcp.json", "type": "mcp-server", "confidence": 0.85},
    {"glob": "mcp-config.json", "type": "mcp-server", "confidence": 0.85},
    {"glob": ".mcp/config.json", "type": "mcp-server", "confidence": 0.85},
    {"glob": "claude_desktop_config.json", "type": "mcp-server", "confidence": 0.80},
    {"glob": ".copilot-setup-steps.yml", "type": "copilot-agent", "confidence": 0.80},
    {"glob": "copilot-setup-steps.yml", "type": "copilot-agent", "confidence": 0.80},
]

# Patterns in Docker/Compose files that suggest agent containers
DOCKER_AGENT_PATTERNS = [
    re.compile(r"langchain|langgraph", re.IGNORECASE),
    re.compile(r"crewai", re.IGNORECASE),
    re.compile(r"autogen", re.IGNORECASE),
    re.compile(r"agentmesh|agent.governance", re.IGNORECASE),
    re.compile(r"mcp[_-]server", re.IGNORECASE),
    re.compile(r"semantic[_-]kernel", re.IGNORECASE),
]

# Directories to skip (safe default excludes)
SKIP_DIRS = {
    ".git",
    "node_modules",
    "__pycache__",
    ".venv",
    "venv",
    ".tox",
    ".mypy_cache",
    ".pytest_cache",
    "dist",
    "build",
    ".eggs",
}

MAX_FILE_READ_BYTES = 64 * 1024  # 64KB max for content inspection


@registry.register
class ConfigScanner(BaseScanner):
    """Scan filesystem directories for AI agent config artifacts.

    Walks directories looking for agent framework configuration files,
    MCP server setups, and Docker/Compose files referencing agent images.
    """

    @property
    def name(self) -> str:
        return "config"

    @property
    def description(self) -> str:
        return "Find AI agent configuration files on the filesystem"

    def validate_config(self, **kwargs: Any) -> list[str]:
        errors = []
        paths = kwargs.get("paths", [])
        if not paths:
            errors.append("'paths' (list of directories to scan) is required")
        for p in paths:
            if not os.path.isdir(p):
                errors.append(f"'{p}' is not a valid directory")
        return errors

    async def scan(self, **kwargs: Any) -> ScanResult:
        result = ScanResult(scanner_name=self.name)
        paths: list[str] = kwargs.get("paths", ["."])
        max_depth: int = kwargs.get("max_depth", 10)

        for scan_root in paths:
            scan_root_path = Path(scan_root).resolve()
            if not scan_root_path.is_dir():
                result.errors.append(f"Not a directory: {scan_root}")
                continue

            try:
                agents = self._walk_directory(scan_root_path, max_depth)
                result.agents.extend(agents)
            except PermissionError as e:
                result.errors.append(f"Permission denied: {e}")

        result.scanned_targets = len(paths)
        result.completed_at = datetime.now(timezone.utc)
        return result

    def _walk_directory(self, root: Path, max_depth: int) -> list[DiscoveredAgent]:
        """Walk a directory tree looking for agent artifacts."""
        agents: list[DiscoveredAgent] = []

        for dirpath, dirnames, filenames in os.walk(root):
            # Respect max depth
            depth = len(Path(dirpath).relative_to(root).parts)
            if depth > max_depth:
                dirnames.clear()
                continue

            # Skip excluded directories
            dirnames[:] = [d for d in dirnames if d not in SKIP_DIRS]

            rel_dir = Path(dirpath).relative_to(root)

            # Check for known config files
            for filename in filenames:
                rel_path = str(rel_dir / filename)
                for config in CONFIG_PATTERNS:
                    if filename == config["glob"] or rel_path.endswith(config["glob"]):
                        full_path = Path(dirpath) / filename
                        merge_keys = {"config_path": str(full_path)}
                        fingerprint = DiscoveredAgent.compute_fingerprint(merge_keys)

                        agent = DiscoveredAgent(
                            fingerprint=fingerprint,
                            name=f"{config['type']} agent at {rel_path}",
                            agent_type=config["type"],
                            description=f"Config file found: {rel_path}",
                            merge_keys=merge_keys,
                            tags={"root": str(root), "config_file": rel_path},
                        )
                        agent.add_evidence(
                            Evidence(
                                scanner=self.name,
                                basis=DetectionBasis.CONFIG_FILE,
                                source=str(full_path),
                                detail=f"Agent config file: {filename}",
                                raw_data={"path": str(full_path), "type": config["type"]},
                                confidence=config["confidence"],
                            )
                        )
                        agents.append(agent)

            # Check Docker/Compose files for agent references
            for filename in filenames:
                if filename in ("Dockerfile", "docker-compose.yml", "docker-compose.yaml"):
                    full_path = Path(dirpath) / filename
                    try:
                        content = full_path.read_text(
                            encoding="utf-8", errors="replace"
                        )[:MAX_FILE_READ_BYTES]
                        for pattern in DOCKER_AGENT_PATTERNS:
                            match = pattern.search(content)
                            if match:
                                merge_keys = {
                                    "docker_path": str(full_path),
                                    "pattern": pattern.pattern,
                                }
                                fingerprint = DiscoveredAgent.compute_fingerprint(merge_keys)

                                agent = DiscoveredAgent(
                                    fingerprint=fingerprint,
                                    name=f"Containerized agent at {rel_dir / filename}",
                                    agent_type=match.group(0).lower(),
                                    description=(
                                        f"Agent reference in {filename}: "
                                        f"'{match.group(0)}'"
                                    ),
                                    merge_keys=merge_keys,
                                    tags={
                                        "root": str(root),
                                        "docker_file": str(rel_dir / filename),
                                    },
                                )
                                agent.add_evidence(
                                    Evidence(
                                        scanner=self.name,
                                        basis=DetectionBasis.CONFIG_FILE,
                                        source=str(full_path),
                                        detail=(
                                            f"Agent pattern '{match.group(0)}' in {filename}"
                                        ),
                                        raw_data={"file": str(full_path)},
                                        confidence=0.70,
                                    )
                                )
                                agents.append(agent)
                                break
                    except (PermissionError, OSError):
                        pass

        return agents
