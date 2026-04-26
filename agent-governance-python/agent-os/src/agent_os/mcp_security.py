# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""MCP Security — defense against tool poisoning, rug pulls, and protocol attacks.

Screens MCP tool definitions for adversarial manipulation where attackers
embed hidden instructions in tool descriptions/metadata that are invisible
to users but executed by LLMs.

Public Preview protections:
    - **Tool poisoning detection**: Catches hidden instructions, invisible
      unicode, markdown/HTML comments, and encoded payloads in tool
      descriptions.
    - **Description injection**: Detects prompt injection patterns
      embedded within MCP tool metadata.
    - **Schema abuse**: Flags overly permissive schemas, hidden required
      fields, and instruction-bearing default values.
    - **Rug pull detection**: Fingerprints registered tools and alerts
      when descriptions or schemas change silently between sessions.
    - **Cross-server attacks**: Detects tool impersonation and
      typosquatting across MCP server boundaries.
    - **Audit trail**: Logs every scan with timestamp and tool identity
      for forensic review.

Architecture:
    MCPSecurityScanner
        ├─ scan_tool()       — scan a single tool definition
        ├─ scan_server()     — batch-scan all tools from a server
        ├─ register_tool()   — fingerprint a tool for rug-pull detection
        ├─ check_rug_pull()  — compare current definition to fingerprint
        └─ audit_log         — inspection trail
"""

from __future__ import annotations

import base64
import hashlib
import json
import logging
import os
import re
import time
import warnings
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Callable

from agent_os._mcp_metrics import MCPMetrics, MCPMetricsRecorder
from agent_os.mcp_protocols import InMemoryAuditSink, MCPAuditSink
from agent_os.prompt_injection import PromptInjectionDetector

logger = logging.getLogger(__name__)

_SAMPLE_DISCLAIMER = (
    "\u26a0\ufe0f  These are SAMPLE MCP security rules provided as a starting point. "
    "You MUST review, customise, and extend them for your specific use case "
    "before deploying to production."
)


# ---------------------------------------------------------------------------
# Data models
# ---------------------------------------------------------------------------


class MCPThreatType(Enum):
    """Classification of an MCP-layer threat."""

    TOOL_POISONING = "tool_poisoning"
    RUG_PULL = "rug_pull"
    CROSS_SERVER_ATTACK = "cross_server_attack"
    CONFUSED_DEPUTY = "confused_deputy"
    HIDDEN_INSTRUCTION = "hidden_instruction"
    DESCRIPTION_INJECTION = "description_injection"


class MCPSeverity(Enum):
    """Severity of an MCP threat."""

    INFO = "info"
    WARNING = "warning"
    CRITICAL = "critical"


@dataclass
class MCPThreat:
    """A single threat finding from an MCP tool scan."""

    threat_type: MCPThreatType
    severity: MCPSeverity
    tool_name: str
    server_name: str
    message: str
    matched_pattern: str | None = None
    details: dict[str, Any] = field(default_factory=dict)


@dataclass
class ToolFingerprint:
    """Cryptographic fingerprint of a tool definition."""

    tool_name: str
    server_name: str
    description_hash: str
    schema_hash: str
    first_seen: float
    last_seen: float
    version: int


@dataclass
class ScanResult:
    """Aggregate outcome of scanning one or more tools."""

    safe: bool
    threats: list[MCPThreat]
    tools_scanned: int
    tools_flagged: int


# ---------------------------------------------------------------------------
# Detection patterns (compiled at import time, following memory_guard.py style)
# ---------------------------------------------------------------------------

# Invisible unicode characters used to hide instructions
_INVISIBLE_UNICODE_PATTERNS: list[re.Pattern[str]] = [
    re.compile(r"[\u200b\u200c\u200d\ufeff]"),  # zero-width spaces/joiners/BOM
    re.compile(r"[\u202a-\u202e]"),  # bidi embedding/override
    re.compile(r"[\u2066-\u2069]"),  # bidi isolates
    re.compile(r"[\u00ad]"),  # soft hyphen
    re.compile(r"[\u2060\u180e]"),  # word joiner, mongolian vowel separator
]

# Markdown/HTML comments that hide text from users
_HIDDEN_COMMENT_PATTERNS: list[re.Pattern[str]] = [
    re.compile(r"<!--.*?-->", re.DOTALL),  # HTML comments
    re.compile(r"\[//\]:\s*#\s*\(.*?\)", re.DOTALL),  # Markdown reference comments
    re.compile(r"\[comment\]:\s*<>\s*\(.*?\)", re.DOTALL),  # alternative MD comment
]

# Instruction-like patterns hidden in descriptions
_HIDDEN_INSTRUCTION_PATTERNS: list[re.Pattern[str]] = [
    re.compile(r"ignore\s+(all\s+)?previous", re.IGNORECASE),
    re.compile(r"override\s+(the\s+)?(previous|above|original)", re.IGNORECASE),
    re.compile(r"instead\s+of\s+(the\s+)?(above|previous|described)", re.IGNORECASE),
    re.compile(r"actually\s+do", re.IGNORECASE),
    re.compile(r"\bsystem\s*:", re.IGNORECASE),
    re.compile(r"\bassistant\s*:", re.IGNORECASE),
    re.compile(r"do\s+not\s+follow", re.IGNORECASE),
    re.compile(r"disregard\s+(all\s+)?(above|prior|previous)", re.IGNORECASE),
]

# Encoded payload patterns
_ENCODED_PAYLOAD_PATTERNS: list[re.Pattern[str]] = [
    re.compile(r"[A-Za-z0-9+/]{40,}={0,2}"),  # long base64 strings
    re.compile(r"(?:\\x[0-9a-fA-F]{2}){4,}"),  # hex sequences
]

# Data exfiltration patterns
_EXFILTRATION_PATTERNS: list[re.Pattern[str]] = [
    re.compile(r"\bcurl\b", re.IGNORECASE),
    re.compile(r"\bwget\b", re.IGNORECASE),
    re.compile(r"\bfetch\s*\(", re.IGNORECASE),
    re.compile(r"https?://", re.IGNORECASE),
    re.compile(r"\bsend\s+email\b", re.IGNORECASE),
    re.compile(r"\bsend\s+to\b", re.IGNORECASE),
    re.compile(r"\bpost\s+to\b", re.IGNORECASE),
    re.compile(r"include\s+the\s+contents?\s+of\b", re.IGNORECASE),
]

# Privilege escalation in descriptions
_PRIVILEGE_ESCALATION_PATTERNS: list[re.Pattern[str]] = [
    re.compile(r"\bsudo\b", re.IGNORECASE),
    re.compile(r"\badmin\s+access\b", re.IGNORECASE),
    re.compile(r"\broot\s+access\b", re.IGNORECASE),
    re.compile(r"\belevate\s+privile", re.IGNORECASE),
    re.compile(r"\bexec\s*\(", re.IGNORECASE),
    re.compile(r"\beval\s*\(", re.IGNORECASE),
]

# Role override patterns
_ROLE_OVERRIDE_PATTERNS: list[re.Pattern[str]] = [
    re.compile(r"you\s+are\b", re.IGNORECASE),
    re.compile(r"your\s+task\s+is\b", re.IGNORECASE),
    re.compile(r"respond\s+with\b", re.IGNORECASE),
    re.compile(r"always\s+return\b", re.IGNORECASE),
    re.compile(r"you\s+must\b", re.IGNORECASE),
    re.compile(r"your\s+role\s+is\b", re.IGNORECASE),
]

# Content after excessive whitespace (hidden instructions at the end)
_EXCESSIVE_WHITESPACE_PATTERN: re.Pattern[str] = re.compile(r"\n{5,}.+", re.DOTALL)

# Suspicious keywords in decoded base64
_SUSPICIOUS_DECODED_KEYWORDS: list[str] = [
    "ignore",
    "override",
    "system",
    "password",
    "secret",
    "admin",
    "root",
    "exec",
    "eval",
    "import os",
    "send",
    "curl",
    "fetch",
]


# ---------------------------------------------------------------------------
# Externalised configuration dataclass
# ---------------------------------------------------------------------------


@dataclass
class MCPSecurityConfig:
    """Structured configuration for MCP security scanning, loadable from YAML.

    Attributes:
        invisible_unicode_patterns: Regex strings for invisible unicode detection.
        hidden_comment_patterns: Regex strings for hidden comments.
        hidden_instruction_patterns: Regex strings for instruction-like text.
        encoded_payload_patterns: Regex strings for encoded payloads.
        exfiltration_patterns: Regex strings for data exfiltration.
        privilege_escalation_patterns: Regex strings for privilege escalation.
        role_override_patterns: Regex strings for role overrides.
        excessive_whitespace_pattern: Regex string for excessive whitespace.
        suspicious_decoded_keywords: Keywords to check in decoded payloads.
        disclaimer: Disclaimer text shown in logs.
    """

    invisible_unicode_patterns: list[str] = field(
        default_factory=lambda: [p.pattern for p in _INVISIBLE_UNICODE_PATTERNS]
    )
    hidden_comment_patterns: list[str] = field(
        default_factory=lambda: [p.pattern for p in _HIDDEN_COMMENT_PATTERNS]
    )
    hidden_instruction_patterns: list[str] = field(
        default_factory=lambda: [p.pattern for p in _HIDDEN_INSTRUCTION_PATTERNS]
    )
    encoded_payload_patterns: list[str] = field(
        default_factory=lambda: [p.pattern for p in _ENCODED_PAYLOAD_PATTERNS]
    )
    exfiltration_patterns: list[str] = field(
        default_factory=lambda: [p.pattern for p in _EXFILTRATION_PATTERNS]
    )
    privilege_escalation_patterns: list[str] = field(
        default_factory=lambda: [p.pattern for p in _PRIVILEGE_ESCALATION_PATTERNS]
    )
    role_override_patterns: list[str] = field(
        default_factory=lambda: [p.pattern for p in _ROLE_OVERRIDE_PATTERNS]
    )
    excessive_whitespace_pattern: str = field(
        default_factory=lambda: _EXCESSIVE_WHITESPACE_PATTERN.pattern
    )
    suspicious_decoded_keywords: list[str] = field(
        default_factory=lambda: list(_SUSPICIOUS_DECODED_KEYWORDS)
    )
    disclaimer: str = ""


def load_mcp_security_config(path: str) -> MCPSecurityConfig:
    """Load MCP security configuration from a YAML file.

    Args:
        path: Path to a YAML file with a ``detection_patterns`` section.

    Returns:
        MCPSecurityConfig populated from the YAML data.

    Raises:
        FileNotFoundError: If the config file does not exist.
        ValueError: If the YAML is missing the ``detection_patterns`` section.
    """
    import yaml

    if not os.path.exists(path):
        raise FileNotFoundError(f"MCP security config not found: {path}")

    with open(path, "r", encoding="utf-8") as fh:
        data = yaml.safe_load(fh.read())

    if not isinstance(data, dict) or "detection_patterns" not in data:
        raise ValueError(f"YAML file must contain a 'detection_patterns' section: {path}")

    dp = data["detection_patterns"]
    return MCPSecurityConfig(
        invisible_unicode_patterns=dp.get(
            "invisible_unicode", [p.pattern for p in _INVISIBLE_UNICODE_PATTERNS]
        ),
        hidden_comment_patterns=dp.get(
            "hidden_comments", [p.pattern for p in _HIDDEN_COMMENT_PATTERNS]
        ),
        hidden_instruction_patterns=dp.get(
            "hidden_instructions", [p.pattern for p in _HIDDEN_INSTRUCTION_PATTERNS]
        ),
        encoded_payload_patterns=dp.get(
            "encoded_payloads", [p.pattern for p in _ENCODED_PAYLOAD_PATTERNS]
        ),
        exfiltration_patterns=dp.get("exfiltration", [p.pattern for p in _EXFILTRATION_PATTERNS]),
        privilege_escalation_patterns=dp.get(
            "privilege_escalation", [p.pattern for p in _PRIVILEGE_ESCALATION_PATTERNS]
        ),
        role_override_patterns=dp.get(
            "role_override", [p.pattern for p in _ROLE_OVERRIDE_PATTERNS]
        ),
        excessive_whitespace_pattern=dp.get(
            "excessive_whitespace", _EXCESSIVE_WHITESPACE_PATTERN.pattern
        ),
        suspicious_decoded_keywords=data.get(
            "suspicious_decoded_keywords", list(_SUSPICIOUS_DECODED_KEYWORDS)
        ),
        disclaimer=data.get("disclaimer", ""),
    )


# ---------------------------------------------------------------------------
# MCPSecurityScanner
# ---------------------------------------------------------------------------


class MCPSecurityScanner:
    """Scans MCP tool definitions for poisoning, rug pulls, and protocol attacks.

    Usage::

        scanner = MCPSecurityScanner()
        threats = scanner.scan_tool(
            "search", "Search the web for information",
            server_name="web-tools"
        )
        if threats:
            print(f"Found {len(threats)} threat(s)")
    """

    def __init__(
        self,
        metrics: MCPMetricsRecorder | None = None,
        *,
        audit_sink: MCPAuditSink | None = None,
        clock: Callable[[], float] = time.time,
    ) -> None:
        warnings.warn(
            "MCPSecurityScanner() uses built-in sample rules that may not "
            "cover all MCP tool poisoning techniques. For production use, load an "
            "explicit config with load_mcp_security_config(). "
            "See examples/policies/mcp-security.yaml for a sample configuration.",
            stacklevel=2,
        )
        self._tool_registry: dict[str, ToolFingerprint] = {}
        self._audit_log: list[dict[str, Any]] = []
        self._injection_detector = PromptInjectionDetector()
        self._metrics = metrics or MCPMetrics()
        self._audit_sink = audit_sink or InMemoryAuditSink()
        self._clock = clock

    # -- public API ---------------------------------------------------------

    def scan_tool(
        self,
        tool_name: str,
        description: str,
        schema: dict[str, Any] | None = None,
        server_name: str = "unknown",
    ) -> list[MCPThreat]:
        """Scan a single MCP tool definition for threats.

        Args:
            tool_name: Name of the tool.
            description: Tool description (primary attack surface).
            schema: Optional JSON Schema for tool inputs.
            server_name: Name of the MCP server providing this tool.

        Returns:
            List of ``MCPThreat`` findings (empty if clean).
        """
        try:
            threats: list[MCPThreat] = []

            threats.extend(self._check_hidden_instructions(description, tool_name, server_name))
            threats.extend(self._check_description_injection(description, tool_name, server_name))
            if schema is not None:
                threats.extend(self._check_schema_abuse(schema, tool_name, server_name))
            threats.extend(self._check_cross_server(tool_name, server_name))

            rug_pull = self.check_rug_pull(tool_name, description, schema, server_name)
            if rug_pull is not None:
                threats.append(rug_pull)

            self._record_audit("scan_tool", tool_name, server_name, threats)
            self._metrics.record_scan(
                operation="scan_tool",
                tool_name=tool_name,
                server_name=server_name,
            )
            self._metrics.record_threats_detected(
                len(threats),
                tool_name=tool_name,
                server_name=server_name,
            )
            return threats
        except Exception:
            logger.error(
                "MCP tool scan failed closed | tool=%s server=%s",
                tool_name,
                server_name,
                exc_info=True,
            )
            return [
                MCPThreat(
                    threat_type=MCPThreatType.TOOL_POISONING,
                    severity=MCPSeverity.CRITICAL,
                    tool_name=tool_name,
                    server_name=server_name,
                    message="Scan error \u2014 fail closed",
                )
            ]

    def scan_server(
        self,
        server_name: str,
        tools: list[dict[str, Any]],
    ) -> ScanResult:
        """Scan all tools from an MCP server.

        Args:
            server_name: Name of the MCP server.
            tools: List of tool dicts with keys: ``name``, ``description``,
                and optionally ``inputSchema``.

        Returns:
            Aggregate ``ScanResult``.
        """
        all_threats: list[MCPThreat] = []
        flagged_tools: set[str] = set()

        for tool in tools:
            name = tool.get("name", "unknown")
            description = tool.get("description", "")
            schema = tool.get("inputSchema")
            tool_threats = self.scan_tool(name, description, schema, server_name)
            if tool_threats:
                flagged_tools.add(name)
                all_threats.extend(tool_threats)

        self._metrics.record_scan(
            operation="scan_server",
            tool_name="*",
            server_name=server_name,
        )
        return ScanResult(
            safe=len(all_threats) == 0,
            threats=all_threats,
            tools_scanned=len(tools),
            tools_flagged=len(flagged_tools),
        )

    def register_tool(
        self,
        tool_name: str,
        description: str,
        schema: dict[str, Any] | None,
        server_name: str,
    ) -> ToolFingerprint:
        """Register a tool with a cryptographic fingerprint.

        If already registered, updates last_seen and increments version
        only when the definition changed.

        Returns:
            The ``ToolFingerprint`` for this tool.
        """
        key = f"{server_name}::{tool_name}"
        now = self._clock()
        desc_hash = hashlib.sha256(description.encode("utf-8")).hexdigest()
        schema_hash = hashlib.sha256(
            json.dumps(schema, sort_keys=True, default=str).encode("utf-8") if schema else b""
        ).hexdigest()

        existing = self._tool_registry.get(key)
        if existing is not None:
            if existing.description_hash != desc_hash or existing.schema_hash != schema_hash:
                existing.description_hash = desc_hash
                existing.schema_hash = schema_hash
                existing.last_seen = now
                existing.version += 1
            else:
                existing.last_seen = now
            return existing

        fp = ToolFingerprint(
            tool_name=tool_name,
            server_name=server_name,
            description_hash=desc_hash,
            schema_hash=schema_hash,
            first_seen=now,
            last_seen=now,
            version=1,
        )
        self._tool_registry[key] = fp
        return fp

    def check_rug_pull(
        self,
        tool_name: str,
        description: str,
        schema: dict[str, Any] | None,
        server_name: str,
    ) -> MCPThreat | None:
        """Check if a tool definition changed since registration (rug pull).

        Returns:
            An ``MCPThreat`` if a rug pull is detected, else ``None``.
        """
        key = f"{server_name}::{tool_name}"
        existing = self._tool_registry.get(key)
        if existing is None:
            return None

        desc_hash = hashlib.sha256(description.encode("utf-8")).hexdigest()
        schema_hash = hashlib.sha256(
            json.dumps(schema, sort_keys=True, default=str).encode("utf-8") if schema else b""
        ).hexdigest()

        changes: list[str] = []
        if existing.description_hash != desc_hash:
            changes.append("description")
        if existing.schema_hash != schema_hash:
            changes.append("schema")

        if changes:
            return MCPThreat(
                threat_type=MCPThreatType.RUG_PULL,
                severity=MCPSeverity.CRITICAL,
                tool_name=tool_name,
                server_name=server_name,
                message=(
                    f"Tool definition changed since registration: "
                    f"{', '.join(changes)} modified (version {existing.version})"
                ),
                details={"changed_fields": changes, "version": existing.version},
            )
        return None

    @property
    def audit_log(self) -> list[dict[str, Any]]:
        """Return a copy of the scan audit history."""
        return list(self._audit_log)

    # -- private detection methods ------------------------------------------

    def _check_hidden_instructions(
        self,
        description: str,
        tool_name: str,
        server_name: str,
    ) -> list[MCPThreat]:
        """Detect hidden instructions in tool descriptions."""
        threats: list[MCPThreat] = []

        # 1. Invisible unicode characters
        for pattern in _INVISIBLE_UNICODE_PATTERNS:
            match = pattern.search(description)
            if match:
                threats.append(
                    MCPThreat(
                        threat_type=MCPThreatType.HIDDEN_INSTRUCTION,
                        severity=MCPSeverity.CRITICAL,
                        tool_name=tool_name,
                        server_name=server_name,
                        message="Invisible unicode characters detected in tool description",
                        matched_pattern=pattern.pattern,
                        details={"char_ord": ord(match.group()[0])},
                    )
                )
                break  # one finding per category is enough

        # 2. Markdown/HTML comments hiding text
        for pattern in _HIDDEN_COMMENT_PATTERNS:
            match = pattern.search(description)
            if match:
                threats.append(
                    MCPThreat(
                        threat_type=MCPThreatType.HIDDEN_INSTRUCTION,
                        severity=MCPSeverity.CRITICAL,
                        tool_name=tool_name,
                        server_name=server_name,
                        message="Hidden comment detected in tool description",
                        matched_pattern=pattern.pattern,
                        details={"comment_preview": match.group()[:80]},
                    )
                )

        # 3. Encoded instructions (base64, hex)
        for pattern in _ENCODED_PAYLOAD_PATTERNS:
            match = pattern.search(description)
            if match:
                candidate = match.group()
                # For base64, try to decode and check for suspicious content
                is_suspicious = False
                if len(candidate) >= 40 and not candidate.startswith("\\x"):
                    try:
                        decoded = base64.b64decode(candidate).decode("utf-8", errors="ignore")
                        decoded_lower = decoded.lower()
                        for keyword in _SUSPICIOUS_DECODED_KEYWORDS:
                            if keyword in decoded_lower:
                                is_suspicious = True
                                break
                    except Exception:  # noqa: S110 — best-effort base64 decode check
                        pass
                    if not is_suspicious:
                        # Long base64 in a tool description is suspicious regardless
                        is_suspicious = True

                if is_suspicious or candidate.startswith("\\x"):
                    threats.append(
                        MCPThreat(
                            threat_type=MCPThreatType.HIDDEN_INSTRUCTION,
                            severity=MCPSeverity.WARNING,
                            tool_name=tool_name,
                            server_name=server_name,
                            message="Encoded payload detected in tool description",
                            matched_pattern=pattern.pattern,
                        )
                    )

        # 4. Hidden instructions after excessive whitespace/newlines
        if _EXCESSIVE_WHITESPACE_PATTERN.search(description):
            threats.append(
                MCPThreat(
                    threat_type=MCPThreatType.HIDDEN_INSTRUCTION,
                    severity=MCPSeverity.WARNING,
                    tool_name=tool_name,
                    server_name=server_name,
                    message="Instructions hidden after excessive whitespace",
                    matched_pattern=_EXCESSIVE_WHITESPACE_PATTERN.pattern,
                )
            )

        # 5. Instruction-like patterns
        for pattern in _HIDDEN_INSTRUCTION_PATTERNS:
            if pattern.search(description):
                threats.append(
                    MCPThreat(
                        threat_type=MCPThreatType.HIDDEN_INSTRUCTION,
                        severity=MCPSeverity.CRITICAL,
                        tool_name=tool_name,
                        server_name=server_name,
                        message=f"Instruction-like pattern in tool description: {pattern.pattern}",
                        matched_pattern=pattern.pattern,
                    )
                )

        return threats

    def _check_description_injection(
        self,
        description: str,
        tool_name: str,
        server_name: str,
    ) -> list[MCPThreat]:
        """Detect prompt injection patterns in tool descriptions."""
        threats: list[MCPThreat] = []

        # Reuse prompt_injection.py detector
        result = self._injection_detector.detect(
            description, source=f"mcp:{server_name}:{tool_name}"
        )
        if result.is_injection:
            threats.append(
                MCPThreat(
                    threat_type=MCPThreatType.DESCRIPTION_INJECTION,
                    severity=MCPSeverity.CRITICAL,
                    tool_name=tool_name,
                    server_name=server_name,
                    message=f"Prompt injection detected in description: {result.explanation}",
                    matched_pattern=result.matched_patterns[0] if result.matched_patterns else None,
                    details={
                        "injection_type": result.injection_type.value
                        if result.injection_type
                        else None
                    },
                )
            )

        # Role assignment patterns
        for pattern in _ROLE_OVERRIDE_PATTERNS:
            if pattern.search(description):
                threats.append(
                    MCPThreat(
                        threat_type=MCPThreatType.DESCRIPTION_INJECTION,
                        severity=MCPSeverity.WARNING,
                        tool_name=tool_name,
                        server_name=server_name,
                        message=f"Role override pattern in description: {pattern.pattern}",
                        matched_pattern=pattern.pattern,
                    )
                )

        # Data exfiltration patterns
        for pattern in _EXFILTRATION_PATTERNS:
            if pattern.search(description):
                threats.append(
                    MCPThreat(
                        threat_type=MCPThreatType.DESCRIPTION_INJECTION,
                        severity=MCPSeverity.CRITICAL,
                        tool_name=tool_name,
                        server_name=server_name,
                        message=f"Data exfiltration pattern in description: {pattern.pattern}",
                        matched_pattern=pattern.pattern,
                    )
                )

        return threats

    def _check_schema_abuse(
        self,
        schema: dict[str, Any],
        tool_name: str,
        server_name: str,
    ) -> list[MCPThreat]:
        """Check tool input schemas for suspicious patterns."""
        threats: list[MCPThreat] = []

        # 1. Overly permissive: top-level type is "object" with no properties
        if schema.get("type") == "object" and not schema.get("properties"):
            if schema.get("additionalProperties") is not False:
                threats.append(
                    MCPThreat(
                        threat_type=MCPThreatType.TOOL_POISONING,
                        severity=MCPSeverity.WARNING,
                        tool_name=tool_name,
                        server_name=server_name,
                        message="Overly permissive schema: object type with no defined properties",
                    )
                )

        properties = schema.get("properties", {})
        required = schema.get("required", [])

        for prop_name, prop_def in properties.items():
            if not isinstance(prop_def, dict):
                continue

            # 2. Hidden required fields with suspicious names
            suspicious_field_names = [
                "system_prompt",
                "instructions",
                "override",
                "command",
                "exec",
                "eval",
                "callback_url",
                "webhook",
                "target_url",
            ]
            if prop_name in required:
                for sus_name in suspicious_field_names:
                    if sus_name in prop_name.lower():
                        threats.append(
                            MCPThreat(
                                threat_type=MCPThreatType.TOOL_POISONING,
                                severity=MCPSeverity.CRITICAL,
                                tool_name=tool_name,
                                server_name=server_name,
                                message=f"Suspicious required field: '{prop_name}'",
                                details={"field_name": prop_name},
                            )
                        )

            # 3. Default values containing instructions
            default_val = prop_def.get("default")
            if isinstance(default_val, str) and len(default_val) > 10:
                for pattern in _HIDDEN_INSTRUCTION_PATTERNS:
                    if pattern.search(default_val):
                        threats.append(
                            MCPThreat(
                                threat_type=MCPThreatType.TOOL_POISONING,
                                severity=MCPSeverity.CRITICAL,
                                tool_name=tool_name,
                                server_name=server_name,
                                message=f"Instruction in default value for field '{prop_name}'",
                                matched_pattern=pattern.pattern,
                                details={"field_name": prop_name},
                            )
                        )
                        break

            # 4. Hidden instructions in property descriptions
            prop_desc = prop_def.get("description", "")
            if isinstance(prop_desc, str):
                for pattern in _HIDDEN_INSTRUCTION_PATTERNS:
                    if pattern.search(prop_desc):
                        threats.append(
                            MCPThreat(
                                threat_type=MCPThreatType.TOOL_POISONING,
                                severity=MCPSeverity.CRITICAL,
                                tool_name=tool_name,
                                server_name=server_name,
                                message=f"Hidden instruction in property '{prop_name}' description",
                                matched_pattern=pattern.pattern,
                                details={"field_name": prop_name},
                            )
                        )
                        break

        return threats

    def _check_cross_server(
        self,
        tool_name: str,
        server_name: str,
    ) -> list[MCPThreat]:
        """Check for cross-server attack patterns."""
        threats: list[MCPThreat] = []

        for _key, fp in self._tool_registry.items():
            # Same tool name from a different server
            if fp.tool_name == tool_name and fp.server_name != server_name:
                threats.append(
                    MCPThreat(
                        threat_type=MCPThreatType.CROSS_SERVER_ATTACK,
                        severity=MCPSeverity.CRITICAL,
                        tool_name=tool_name,
                        server_name=server_name,
                        message=(
                            f"Tool '{tool_name}' already registered from server "
                            f"'{fp.server_name}' — potential impersonation"
                        ),
                        details={"original_server": fp.server_name},
                    )
                )

            # Typosquatting: similar name from a different server
            if fp.server_name != server_name and fp.tool_name != tool_name:
                if self._is_typosquat(tool_name, fp.tool_name):
                    threats.append(
                        MCPThreat(
                            threat_type=MCPThreatType.CROSS_SERVER_ATTACK,
                            severity=MCPSeverity.WARNING,
                            tool_name=tool_name,
                            server_name=server_name,
                            message=(
                                f"Tool name '{tool_name}' resembles "
                                f"'{fp.tool_name}' from server '{fp.server_name}' "
                                f"— potential typosquatting"
                            ),
                            details={
                                "similar_tool": fp.tool_name,
                                "similar_server": fp.server_name,
                            },
                        )
                    )

        return threats

    # -- helpers ------------------------------------------------------------

    @staticmethod
    def _is_typosquat(name_a: str, name_b: str) -> bool:
        """Check if two tool names are suspiciously similar (edit distance ≤ 2)."""
        if name_a == name_b:
            return False
        # Simple Levenshtein check for short names
        la, lb = name_a.lower(), name_b.lower()
        if abs(len(la) - len(lb)) > 2:
            return False
        # Compute Levenshtein distance
        dist = _levenshtein(la, lb)
        # Typosquat if 1-2 edits on names of length ≥ 4
        return 1 <= dist <= 2 and min(len(la), len(lb)) >= 4

    def _record_audit(
        self,
        action: str,
        tool_name: str,
        server_name: str,
        threats: list[MCPThreat],
    ) -> None:
        record = {
            "timestamp": datetime.fromtimestamp(
                self._clock(),
                timezone.utc,
            ).isoformat(),
            "action": action,
            "tool_name": tool_name,
            "server_name": server_name,
            "threats_found": len(threats),
            "threat_types": [t.threat_type.value for t in threats],
        }
        self._audit_log.append(record)
        self._audit_sink.record(record)

        if threats:
            logger.warning(
                "MCP scan found %d threat(s) | tool=%s server=%s",
                len(threats),
                tool_name,
                server_name,
            )
        else:
            logger.debug(
                "MCP scan clean | tool=%s server=%s",
                tool_name,
                server_name,
            )


def _levenshtein(s: str, t: str) -> int:
    """Compute Levenshtein edit distance between two strings."""
    if len(s) < len(t):
        return _levenshtein(t, s)
    if len(t) == 0:
        return len(s)
    prev = list(range(len(t) + 1))
    for i, cs in enumerate(s):
        curr = [i + 1]
        for j, ct in enumerate(t):
            cost = 0 if cs == ct else 1
            curr.append(min(curr[j] + 1, prev[j + 1] + 1, prev[j] + cost))
        prev = curr
    return prev[-1]
