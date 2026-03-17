# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""
Semantic Policy Engine — Intent-based policy enforcement.

Classifies action+params into semantic intent categories and enforces
policies based on intent rather than brittle string patterns.

This is a heuristic classifier (no ML dependency). It can be upgraded
to a fine-tuned model later while keeping the same API.

Example:
    >>> from agent_os.semantic_policy import SemanticPolicyEngine, IntentCategory
    >>>
    >>> engine = SemanticPolicyEngine()
    >>> result = engine.classify("database_query", {"query": "DROP TABLE users"})
    >>> result.category  # IntentCategory.DESTRUCTIVE_DATA
    >>> result.confidence  # 0.95
    >>>
    >>> engine.check("database_query", {"query": "DROP TABLE users"}, deny=[IntentCategory.DESTRUCTIVE_DATA])
    >>> # raises PolicyDenied
"""

from __future__ import annotations

import os
import re
import warnings
from dataclasses import dataclass, field
from enum import Enum
from typing import Any

# =============================================================================
# Disclaimer
# =============================================================================

_SAMPLE_DISCLAIMER = (
    "\u26a0\ufe0f  These are SAMPLE semantic policy signals provided as a starting "
    "point. You MUST review, customise, and extend them for your specific use "
    "case before deploying to production."
)

# =============================================================================
# Intent Categories
# =============================================================================


class IntentCategory(str, Enum):
    """Semantic intent categories for agent actions."""
    DESTRUCTIVE_DATA = "destructive_data"       # DROP, DELETE, TRUNCATE, wipe
    DATA_EXFILTRATION = "data_exfiltration"     # bulk export, dump, copy-to-external
    PRIVILEGE_ESCALATION = "privilege_escalation"  # grant, sudo, chmod, admin
    SYSTEM_MODIFICATION = "system_modification"  # rm, shutdown, reboot, kill
    CODE_EXECUTION = "code_execution"           # exec, eval, subprocess, shell
    NETWORK_ACCESS = "network_access"           # fetch, curl, http, connect
    DATA_READ = "data_read"                     # SELECT, get, read, list
    DATA_WRITE = "data_write"                   # INSERT, UPDATE, create, write
    BENIGN = "benign"                           # no risk signals detected


# =============================================================================
# Classification Result
# =============================================================================


@dataclass(frozen=True)
class IntentClassification:
    """Result of semantic intent classification."""
    category: IntentCategory
    confidence: float  # 0.0 to 1.0
    matched_signals: tuple  # signal keywords that matched
    explanation: str = ""

    @property
    def is_dangerous(self) -> bool:
        """True if intent is in a dangerous category with high confidence."""
        return (
            self.category
            in {
                IntentCategory.DESTRUCTIVE_DATA,
                IntentCategory.DATA_EXFILTRATION,
                IntentCategory.PRIVILEGE_ESCALATION,
                IntentCategory.SYSTEM_MODIFICATION,
                IntentCategory.CODE_EXECUTION,
            }
            and self.confidence >= 0.5
        )


# =============================================================================
# Policy Denied Exception
# =============================================================================


class PolicyDenied(Exception):
    """Raised when an action is denied by semantic policy."""

    def __init__(self, classification: IntentClassification, policy_name: str = ""):
        self.classification = classification
        self.policy_name = policy_name
        super().__init__(
            f"Denied by {policy_name or 'semantic policy'}: "
            f"intent={classification.category.value} "
            f"confidence={classification.confidence:.0%} "
            f"signals={classification.matched_signals}"
        )


# =============================================================================
# Signal Definitions
# =============================================================================

# Each signal: (pattern_regex, weight, explanation)
_SIGNALS: dict[IntentCategory, list[tuple]] = {
    IntentCategory.DESTRUCTIVE_DATA: [
        (r"\bDROP\s+(TABLE|DATABASE|INDEX|VIEW|SCHEMA)\b", 0.9, "SQL DROP statement"),
        (r"\bTRUNCATE\s+TABLE\b", 0.9, "SQL TRUNCATE"),
        (r"\bDELETE\s+FROM\b.*\bWHERE\s+1\s*=\s*1\b", 0.95, "DELETE all rows"),
        (r"\bDELETE\s+FROM\b(?!.*\bWHERE\b)", 0.85, "DELETE without WHERE"),
        (r"\bDELETE\s+FROM\b", 0.4, "DELETE with filter"),
        (r"\b(wipe|purge|destroy|erase|nuke)\b", 0.7, "destructive verb"),
        (r"\bremove\s+(all|every|entire)\b", 0.75, "remove-all pattern"),
        (r"\bformat\s+(disk|drive|partition)\b", 0.9, "disk format"),
        (r"\bALTER\s+TABLE\b.*\bDROP\b", 0.8, "ALTER TABLE DROP column"),
    ],
    IntentCategory.DATA_EXFILTRATION: [
        (r"\bSELECT\s+\*\s+FROM\b.*\bINTO\s+OUTFILE\b", 0.9, "SQL dump to file"),
        (r"\bCOPY\s+.*\bTO\s+STDOUT\b", 0.8, "Postgres COPY to stdout"),
        (r"\b(dump|export|backup)\s+(all|entire|full|complete)\b", 0.75, "full data export"),
        (r"\b(upload|send|transmit)\s+.*\b(external|remote|s3|bucket)\b", 0.8, "external transfer"),
        (r"\bpg_dump\b", 0.7, "database dump tool"),
        (r"\bmysqldump\b", 0.7, "MySQL dump tool"),
        (r"\b(wget|curl)\s+.*\|\s*", 0.6, "piped download"),
    ],
    IntentCategory.PRIVILEGE_ESCALATION: [
        (r"\bGRANT\s+(ALL|SUPERUSER|ADMIN)\b", 0.9, "SQL GRANT elevated"),
        (r"\bGRANT\b", 0.4, "SQL GRANT"),
        (r"\bsudo\b", 0.7, "sudo invocation"),
        (r"\bchmod\s+777\b", 0.8, "world-writable permissions"),
        (r"\bchmod\s+[0-7]*[67][0-7]{2}\b", 0.5, "permissive chmod"),
        (r"\b(escalat|elevat)\w*\s*(privilege|permission|access)\b", 0.8, "escalation language"),
        (r"\bALTER\s+USER\b.*\bSUPERUSER\b", 0.9, "make superuser"),
        (r"\bsu\s+-\b", 0.7, "switch user root"),
        (r"\bpasswd\b", 0.5, "password change"),
    ],
    IntentCategory.SYSTEM_MODIFICATION: [
        (r"\brm\s+-rf\b", 0.95, "recursive force delete"),
        (r"\brm\s+-r\b", 0.7, "recursive delete"),
        (r"\b(shutdown|reboot|halt|poweroff)\b", 0.8, "system power"),
        (r"\bkill\s+-9\b", 0.7, "force kill process"),
        (r"\bsystemctl\s+(stop|disable|mask)\b", 0.7, "stop system service"),
        (r"\biptables\s+.*\bDROP\b", 0.8, "firewall drop rule"),
        (r"\bregistry\s*(delete|modify)\b", 0.7, "Windows registry modification"),
        (r"\bformat\s+[A-Z]:\b", 0.9, "format drive"),
    ],
    IntentCategory.CODE_EXECUTION: [
        (r"\b(exec|eval)\s*\(", 0.8, "dynamic code execution"),
        (r"\bsubprocess\b", 0.5, "subprocess call"),
        (r"\bos\.system\b", 0.7, "os.system call"),
        (r"\b__import__\b", 0.7, "dynamic import"),
        (r"\bcompile\s*\(", 0.5, "compile code"),
        (r"\bpickle\.loads\b", 0.7, "unsafe deserialization"),
    ],
    IntentCategory.NETWORK_ACCESS: [
        (r"\b(fetch|requests\.get|requests\.post|urllib)\b", 0.4, "HTTP request"),
        (r"\b(curl|wget)\s+http", 0.5, "command-line HTTP"),
        (r"\bsocket\.connect\b", 0.6, "raw socket connection"),
        (r"\bsmtplib\b", 0.5, "SMTP email"),
    ],
    IntentCategory.DATA_READ: [
        (r"\bSELECT\b(?!.*\bINTO\b)", 0.6, "SQL SELECT"),
        (r"\b(read|get|fetch|list|show|describe)\b", 0.3, "read verb"),
    ],
    IntentCategory.DATA_WRITE: [
        (r"\b(INSERT|UPDATE)\b", 0.5, "SQL write"),
        (r"\b(write|create|put|post|append)\b", 0.3, "write verb"),
    ],
}


# =============================================================================
# Externalised configuration dataclass
# =============================================================================


@dataclass
class SemanticPolicyConfig:
    """Structured configuration for semantic policy signals, loadable from YAML.

    Attributes:
        signals: Mapping of IntentCategory names to lists of
            ``(pattern, weight, explanation)`` tuples.
        disclaimer: Disclaimer text shown in logs.
    """

    signals: dict[str, list[tuple[str, float, str]]] = field(
        default_factory=lambda: {
            cat.value: [(p, w, e) for p, w, e in sigs]
            for cat, sigs in _SIGNALS.items()
        }
    )
    disclaimer: str = ""


def load_semantic_policy_config(path: str) -> SemanticPolicyConfig:
    """Load semantic policy configuration from a YAML file.

    Args:
        path: Path to a YAML file with a ``signals`` section.

    Returns:
        SemanticPolicyConfig populated from the YAML data.

    Raises:
        FileNotFoundError: If the config file does not exist.
        ValueError: If the YAML is missing the ``signals`` section.
    """
    import yaml

    if not os.path.exists(path):
        raise FileNotFoundError(f"Semantic policy config not found: {path}")

    with open(path, "r", encoding="utf-8") as fh:
        data = yaml.safe_load(fh.read())

    if not isinstance(data, dict) or "signals" not in data:
        raise ValueError(f"YAML file must contain a 'signals' section: {path}")

    raw_signals = data["signals"]
    signals: dict[str, list[tuple[str, float, str]]] = {}
    for category_name, entries in raw_signals.items():
        signals[category_name] = [
            (entry["pattern"], float(entry["weight"]), entry.get("explanation", ""))
            for entry in entries
        ]

    return SemanticPolicyConfig(
        signals=signals,
        disclaimer=data.get("disclaimer", ""),
    )


# =============================================================================
# Semantic Policy Engine
# =============================================================================


class SemanticPolicyEngine:
    """
    Intent-based policy enforcement engine.

    Classifies action+params into semantic intent categories using
    weighted keyword signals, then enforces deny/allow policies.

    This is a zero-dependency heuristic classifier designed to run in <1ms.
    The API is stable — swap in an ML classifier later without changing callers.
    """

    def __init__(
        self,
        deny: list[IntentCategory] | None = None,
        confidence_threshold: float = 0.5,
        custom_signals: dict[IntentCategory, list[tuple]] | None = None,
        config: SemanticPolicyConfig | None = None,
    ):
        """
        Args:
            deny: Intent categories to deny (default: all dangerous categories)
            confidence_threshold: Minimum confidence to trigger deny (0.0-1.0)
            custom_signals: Additional signal patterns to merge with defaults
            config: Optional externalized configuration loaded via
                ``load_semantic_policy_config()``.
        """
        if config is None and custom_signals is None:
            warnings.warn(
                "SemanticPolicyEngine() uses built-in sample rules that may not "
                "cover all malicious intent patterns. For production use, load an "
                "explicit config with load_semantic_policy_config(). "
                "See examples/policies/semantic-policy.yaml for a sample configuration.",
                stacklevel=2,
            )
        self.deny_categories: set[IntentCategory] = set(deny) if deny else {
            IntentCategory.DESTRUCTIVE_DATA,
            IntentCategory.DATA_EXFILTRATION,
            IntentCategory.PRIVILEGE_ESCALATION,
            IntentCategory.SYSTEM_MODIFICATION,
            IntentCategory.CODE_EXECUTION,
        }
        self.confidence_threshold = confidence_threshold

        # Build signals from config or defaults
        if config is not None:
            self.signals: dict[IntentCategory, list[tuple]] = {}
            for cat_name, sigs in config.signals.items():
                try:
                    cat = IntentCategory(cat_name)
                except ValueError:
                    continue
                self.signals[cat] = list(sigs)
        else:
            self.signals = {k: list(v) for k, v in _SIGNALS.items()}

        if custom_signals:
            for cat, sigs in custom_signals.items():
                self.signals.setdefault(cat, []).extend(sigs)
        # Pre-compile regexes for performance
        self._compiled: dict[IntentCategory, list[tuple]] = {}
        for cat, sigs in self.signals.items():
            self._compiled[cat] = [
                (re.compile(pattern, re.IGNORECASE), weight, explanation)
                for pattern, weight, explanation in sigs
            ]

    def classify(
        self, action: str, params: dict[str, Any]
    ) -> IntentClassification:
        """
        Classify the semantic intent of an action+params.

        Args:
            action: Action name (e.g. "database_query")
            params: Action parameters (e.g. {"query": "DROP TABLE users"})

        Returns:
            IntentClassification with category, confidence, and matched signals
        """
        # Build the text corpus to scan
        text = self._build_text(action, params)

        best_category = IntentCategory.BENIGN
        best_confidence = 0.0
        best_signals: list = []

        for category, compiled_sigs in self._compiled.items():
            matched = []
            total_weight = 0.0

            for regex, weight, explanation in compiled_sigs:
                if regex.search(text):
                    matched.append(explanation)
                    total_weight = max(total_weight, weight)

            if matched and total_weight > best_confidence:
                best_category = category
                best_confidence = total_weight
                best_signals = matched

        return IntentClassification(
            category=best_category,
            confidence=round(best_confidence, 3),
            matched_signals=tuple(best_signals),
            explanation=(
                f"Detected {best_category.value} intent "
                f"({best_confidence:.0%} confidence) "
                f"from {len(best_signals)} signal(s)"
                if best_signals
                else "No risk signals detected"
            ),
        )

    def check(
        self,
        action: str,
        params: dict[str, Any],
        *,
        deny: list[IntentCategory] | None = None,
        policy_name: str = "",
    ) -> IntentClassification:
        """
        Classify and enforce — raises PolicyDenied if intent is denied.

        Args:
            action: Action name
            params: Action parameters
            deny: Override deny categories (uses engine defaults if None)
            policy_name: Name for error messages

        Returns:
            IntentClassification if allowed

        Raises:
            PolicyDenied: If classified intent is in deny set above threshold
        """
        classification = self.classify(action, params)
        deny_set = set(deny) if deny else self.deny_categories

        if (
            classification.category in deny_set
            and classification.confidence >= self.confidence_threshold
        ):
            raise PolicyDenied(classification, policy_name)

        return classification

    @staticmethod
    def _build_text(action: str, params: dict[str, Any]) -> str:
        """Flatten action + params into a single searchable string."""
        parts = [action]
        for value in params.values():
            if isinstance(value, str):
                parts.append(value)
            elif isinstance(value, (list, tuple)):
                parts.extend(str(v) for v in value)
            elif isinstance(value, dict):
                parts.extend(str(v) for v in value.values())
            else:
                parts.append(str(value))
        return " ".join(parts)


# =============================================================================
# Public API
# =============================================================================

__all__ = [
    "IntentCategory",
    "IntentClassification",
    "PolicyDenied",
    "SemanticPolicyConfig",
    "SemanticPolicyEngine",
    "load_semantic_policy_config",
]
