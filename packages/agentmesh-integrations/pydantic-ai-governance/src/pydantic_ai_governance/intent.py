"""Semantic intent classification for tool calls.

Basic classifier that categorizes tool call intent into threat categories.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from enum import Enum
from typing import Dict, List, Optional


class SemanticIntent(Enum):
    """Threat categories for tool call classification."""

    DESTRUCTIVE_DATA = "destructive_data"
    DATA_EXFILTRATION = "data_exfiltration"
    PRIVILEGE_ESCALATION = "privilege_escalation"
    SYSTEM_MODIFICATION = "system_modification"
    CODE_EXECUTION = "code_execution"
    NETWORK_ACCESS = "network_access"
    DATA_READ = "data_read"
    DATA_WRITE = "data_write"
    BENIGN = "benign"


@dataclass
class IntentClassification:
    """Result of semantic intent classification."""

    intent: SemanticIntent
    confidence: float
    signals: List[str] = field(default_factory=list)


# Basic threat keywords
_THREAT_KEYWORDS: Dict[SemanticIntent, List[str]] = {
    SemanticIntent.DESTRUCTIVE_DATA: ["drop table", "delete from", "truncate", "rm -rf", "format"],
    SemanticIntent.DATA_EXFILTRATION: ["curl", "wget", "scp", "rsync", "ftp"],
    SemanticIntent.PRIVILEGE_ESCALATION: ["sudo", "chmod", "chown", "su root"],
    SemanticIntent.CODE_EXECUTION: ["eval(", "exec(", "__import__", "subprocess"],
}


def classify_intent(
    text: str,
    tool_name: str = "",
    arguments: Optional[Dict[str, str]] = None,
) -> IntentClassification:
    """Classify the semantic intent of a tool call using keyword matching."""
    combined = text.lower()
    if tool_name:
        combined = f"{tool_name} {combined}"
    if arguments:
        combined = f"{combined} {' '.join(str(v) for v in arguments.values())}"

    for intent, keywords in _THREAT_KEYWORDS.items():
        for keyword in keywords:
            if keyword.lower() in combined:
                return IntentClassification(
                    intent=intent, confidence=0.8, signals=[keyword],
                )

    return IntentClassification(
        intent=SemanticIntent.BENIGN, confidence=1.0,
        signals=["no threat signals detected"],
    )
