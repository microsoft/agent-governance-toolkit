# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""Mute Agent — post-execution gate for output filtering.

The mute agent sits between the execution engine and the caller, inspecting
and sanitising execution results before they leave the kernel.  It removes
or redacts sensitive data (PII, credentials, internal metadata) according to
configurable ``MutePolicy`` rules.

Architecture:
    ExecutionEngine ──▶ MuteAgent.mute(result) ──▶ sanitised result ──▶ Caller

Built-in pattern categories:
    - **email**: RFC-5322-style email addresses
    - **phone**: North-American and international phone numbers
    - **ssn**: US Social Security Numbers
    - **credit_card**: Major card number formats (Visa, MC, Amex, Discover)
    - **api_key**: Common API-key / secret-key patterns
"""

from __future__ import annotations

import logging
import os
import re
import warnings
from dataclasses import dataclass, field
from typing import Any

logger = logging.getLogger(__name__)

_SAMPLE_DISCLAIMER = (
    "\u26a0\ufe0f  These are SAMPLE PII detection patterns provided as a starting "
    "point. You MUST review, customise, and extend them for your specific use "
    "case before deploying to production."
)


# ---------------------------------------------------------------------------
# Built-in PII / sensitive-data patterns
# ---------------------------------------------------------------------------

BUILTIN_PATTERNS: dict[str, str] = {
    "email": r"[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+",
    "phone": r"(?:\+?1[-.\s]?)?\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}",
    "ssn": r"\b\d{3}-\d{2}-\d{4}\b",
    "credit_card": r"\b(?:\d[ -]*?){13,19}\b",
    "api_key": (
        r"(?:api[_-]?key|secret[_-]?key|access[_-]?token|bearer)"
        r"[\s:=]+['\"]?[A-Za-z0-9_\-]{16,}['\"]?"
    ),
}

# Pre-compiled versions for performance
_COMPILED: dict[str, re.Pattern[str]] = {
    name: re.compile(pattern, re.IGNORECASE)
    for name, pattern in BUILTIN_PATTERNS.items()
}


# ---------------------------------------------------------------------------
# Externalised configuration dataclass
# ---------------------------------------------------------------------------

@dataclass
class PIIDetectionConfig:
    """Structured configuration for PII detection patterns, loadable from YAML.

    Attributes:
        builtin_patterns: Mapping of pattern name to regex string.
        disclaimer: Disclaimer text shown in logs.
    """

    builtin_patterns: dict[str, str] = field(default_factory=lambda: dict(BUILTIN_PATTERNS))
    disclaimer: str = ""


def load_pii_config(path: str) -> PIIDetectionConfig:
    """Load PII detection configuration from a YAML file.

    Args:
        path: Path to a YAML file with a ``builtin_patterns`` section.

    Returns:
        PIIDetectionConfig populated from the YAML data.

    Raises:
        FileNotFoundError: If the config file does not exist.
        ValueError: If the YAML is missing the ``builtin_patterns`` section.
    """
    import yaml

    if not os.path.exists(path):
        raise FileNotFoundError(f"PII detection config not found: {path}")

    with open(path, "r", encoding="utf-8") as fh:
        data = yaml.safe_load(fh.read())

    if not isinstance(data, dict) or "builtin_patterns" not in data:
        raise ValueError(f"YAML file must contain a 'builtin_patterns' section: {path}")

    return PIIDetectionConfig(
        builtin_patterns=data["builtin_patterns"],
        disclaimer=data.get("disclaimer", ""),
    )


# ---------------------------------------------------------------------------
# Data models
# ---------------------------------------------------------------------------

@dataclass
class MutePolicy:
    """Rules for what to mute/redact in execution output.

    Attributes:
        enabled_builtins: Names of built-in patterns to apply
            (e.g. ``["email", "ssn"]``).  An empty list disables builtins.
        custom_patterns: Additional regex patterns (raw strings).
        sensitive_keywords: Exact substring keywords to redact.
        replacement: The string used to replace redacted content.
    """
    enabled_builtins: list[str] = field(default_factory=lambda: list(BUILTIN_PATTERNS.keys()))
    custom_patterns: list[str] = field(default_factory=list)
    sensitive_keywords: list[str] = field(default_factory=list)
    replacement: str = "[REDACTED]"


# ---------------------------------------------------------------------------
# Mute Agent
# ---------------------------------------------------------------------------

class MuteAgent:
    """Post-execution gate that redacts sensitive content from results.

    Args:
        policy: A ``MutePolicy`` describing what to redact.
    """

    def __init__(self, policy: MutePolicy | None = None) -> None:
        if policy is None:
            warnings.warn(
                "MuteAgent() uses built-in sample rules that may not "
                "cover all PII patterns. For production use, load an "
                "explicit config with load_pii_config(). "
                "See examples/policies/pii-detection.yaml for a sample configuration.",
                stacklevel=2,
            )
        self.policy = policy or MutePolicy()
        self._custom_compiled: list[re.Pattern[str]] = [
            re.compile(p, re.IGNORECASE) for p in self.policy.custom_patterns
        ]

    # -- public API ---------------------------------------------------------

    def mute(self, result: Any) -> Any:
        """Filter *result*, redacting sensitive content in-place.

        Accepts an ``ExecutionResult`` (from ``agent_os.stateless``) or any
        object with a ``data`` attribute.  The ``data`` field is walked
        recursively and string values are scrubbed.

        Returns:
            The same result object with sensitive strings replaced.
        """
        if hasattr(result, "data") and result.data is not None:
            result.data = self._scrub(result.data)

        if hasattr(result, "metadata") and isinstance(result.metadata, dict):
            result.metadata = self._scrub(result.metadata)

        return result

    def scrub_text(self, text: str) -> str:
        """Redact sensitive content from a plain string."""
        return self._scrub_string(text)

    # -- internals ----------------------------------------------------------

    def _scrub(self, value: Any) -> Any:
        """Recursively scrub strings inside dicts, lists, and scalars."""
        if isinstance(value, str):
            return self._scrub_string(value)
        if isinstance(value, dict):
            return {k: self._scrub(v) for k, v in value.items()}
        if isinstance(value, (list, tuple)):
            scrubbed = [self._scrub(item) for item in value]
            return type(value)(scrubbed)
        return value

    def _scrub_string(self, text: str) -> str:
        replacement = self.policy.replacement

        # Built-in patterns
        for name in self.policy.enabled_builtins:
            compiled = _COMPILED.get(name)
            if compiled:
                text = compiled.sub(replacement, text)

        # Custom regex patterns
        for pattern in self._custom_compiled:
            text = pattern.sub(replacement, text)

        # Keyword substring replacement
        for keyword in self.policy.sensitive_keywords:
            if keyword in text:
                text = text.replace(keyword, replacement)

        return text
