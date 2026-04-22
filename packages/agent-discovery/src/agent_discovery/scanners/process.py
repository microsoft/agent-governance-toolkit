# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""Process scanner — detect AI agent processes on the local host.

Scans running processes for signatures of known AI agent frameworks.
Redacts secrets from command-line arguments and environment variables.

Security: Read-only, passive. Uses psutil-free approach (subprocess only)
to minimize dependencies. Redacts tokens/keys from process args.
"""

from __future__ import annotations

import os
import platform
import re
import subprocess
from datetime import datetime, timezone
from typing import Any

from ..models import (
    DetectionBasis,
    DiscoveredAgent,
    Evidence,
    ScanResult,
)
from .base import BaseScanner, registry

# Patterns that indicate an AI agent process
AGENT_SIGNATURES: list[dict[str, Any]] = [
    {
        "pattern": r"langchain|langgraph|langserve",
        "type": "langchain",
        "name_hint": "LangChain Agent",
        "confidence": 0.85,
    },
    {
        "pattern": r"crewai|crew\.run",
        "type": "crewai",
        "name_hint": "CrewAI Agent",
        "confidence": 0.85,
    },
    {
        "pattern": r"autogen|groupchat",
        "type": "autogen",
        "name_hint": "AutoGen Agent",
        "confidence": 0.80,
    },
    {
        "pattern": r"openai.*agents|swarm",
        "type": "openai-agents",
        "name_hint": "OpenAI Agents SDK",
        "confidence": 0.80,
    },
    {
        "pattern": r"semantic.kernel|sk_agent",
        "type": "semantic-kernel",
        "name_hint": "Semantic Kernel Agent",
        "confidence": 0.85,
    },
    {
        "pattern": r"agentmesh|agent.os|agent.governance",
        "type": "agt",
        "name_hint": "AGT Governed Agent",
        "confidence": 0.95,
    },
    {
        "pattern": r"mcp.server|mcp_server|model.context.protocol",
        "type": "mcp-server",
        "name_hint": "MCP Server",
        "confidence": 0.90,
    },
    {
        "pattern": r"llamaindex|llama.index",
        "type": "llamaindex",
        "name_hint": "LlamaIndex Agent",
        "confidence": 0.80,
    },
    {
        "pattern": r"haystack|haystack\.agents",
        "type": "haystack",
        "name_hint": "Haystack Agent",
        "confidence": 0.80,
    },
    {
        "pattern": r"pydantic.ai|pydanticai",
        "type": "pydantic-ai",
        "name_hint": "PydanticAI Agent",
        "confidence": 0.80,
    },
    {
        "pattern": r"google.*adk|genai.*agent",
        "type": "google-adk",
        "name_hint": "Google ADK Agent",
        "confidence": 0.75,
    },
]

# Regex for secrets we must redact in process args
SECRET_PATTERNS = [
    re.compile(r"((?:api[_-]?key|token|secret|password|credential|auth)[=:\s]+)\S+", re.IGNORECASE),
    re.compile(r"(sk-[a-zA-Z0-9]{20,})"),
    re.compile(r"(ghp_[a-zA-Z0-9]{36,})"),
    re.compile(r"(gho_[a-zA-Z0-9]{36,})"),
    re.compile(r"(xox[bpors]-[a-zA-Z0-9\-]+)"),
    re.compile(r"(eyJ[a-zA-Z0-9\-_]+\.eyJ[a-zA-Z0-9\-_]+)"),  # JWT
]


def _redact_secrets(text: str) -> str:
    """Replace potential secrets in text with [REDACTED]."""
    result = text
    for pattern in SECRET_PATTERNS:
        result = pattern.sub("[REDACTED]", result)
    return result


def _get_processes_windows() -> list[dict[str, str]]:
    """Get process info on Windows using WMIC."""
    try:
        result = subprocess.run(
            ["wmic", "process", "get", "ProcessId,CommandLine", "/format:csv"],  # noqa: S607 — known CLI tool path in process scanner
            capture_output=True,
            text=True,
            timeout=30,
        )
        processes = []
        for line in result.stdout.strip().splitlines()[1:]:
            parts = line.strip().split(",", 2)
            if len(parts) >= 3:
                cmdline = _redact_secrets(parts[1])
                pid = parts[2].strip()
                if cmdline and pid.isdigit():
                    processes.append({"pid": pid, "cmdline": cmdline})
        return processes
    except (subprocess.TimeoutExpired, FileNotFoundError, OSError):
        return []


def _get_processes_unix() -> list[dict[str, str]]:
    """Get process info on Unix using ps."""
    try:
        result = subprocess.run(
            ["ps", "aux"],  # noqa: S607 — known CLI tool path in process scanner
            capture_output=True,
            text=True,
            timeout=30,
        )
        processes = []
        for line in result.stdout.strip().splitlines()[1:]:
            parts = line.split(None, 10)
            if len(parts) >= 11:
                pid = parts[1]
                cmdline = _redact_secrets(parts[10])
                processes.append({"pid": pid, "cmdline": cmdline})
        return processes
    except (subprocess.TimeoutExpired, FileNotFoundError, OSError):
        return []


def _get_processes() -> list[dict[str, str]]:
    """Get running processes, platform-appropriate."""
    if platform.system() == "Windows":
        return _get_processes_windows()
    return _get_processes_unix()


@registry.register
class ProcessScanner(BaseScanner):
    """Scan local processes for AI agent signatures.

    This scanner inspects running process command lines for patterns
    matching known AI agent frameworks. It is passive and read-only.

    Security:
    - Secrets in command-line args are automatically redacted
    - No environment variables are captured
    - No process memory is inspected
    """

    @property
    def name(self) -> str:
        return "process"

    @property
    def description(self) -> str:
        return "Detect AI agent processes running on the local host"

    async def scan(self, **kwargs: Any) -> ScanResult:
        result = ScanResult(scanner_name=self.name)
        processes = _get_processes()
        result.scanned_targets = len(processes)

        for proc in processes:
            cmdline = proc["cmdline"].lower()
            pid = proc["pid"]

            for sig in AGENT_SIGNATURES:
                if re.search(sig["pattern"], cmdline, re.IGNORECASE):
                    merge_keys = {
                        "exe_fingerprint": f"pid:{pid}",
                        "cmdline_hash": DiscoveredAgent.compute_fingerprint(
                            {"cmdline": proc["cmdline"][:200]}
                        ),
                    }
                    fingerprint = DiscoveredAgent.compute_fingerprint(merge_keys)

                    agent = DiscoveredAgent(
                        fingerprint=fingerprint,
                        name=f"{sig['name_hint']} (PID {pid})",
                        agent_type=sig["type"],
                        description=f"Detected via process matching: {sig['pattern']}",
                        merge_keys=merge_keys,
                        tags={"pid": pid, "host": os.environ.get("COMPUTERNAME", "localhost")},
                    )
                    agent.add_evidence(
                        Evidence(
                            scanner=self.name,
                            basis=DetectionBasis.PROCESS,
                            source=f"PID {pid}",
                            detail=f"Command line matches {sig['type']} pattern",
                            raw_data={"cmdline_redacted": _redact_secrets(proc["cmdline"][:500])},
                            confidence=sig["confidence"],
                        )
                    )
                    result.agents.append(agent)
                    break  # one match per process

        result.completed_at = datetime.now(timezone.utc)
        return result
