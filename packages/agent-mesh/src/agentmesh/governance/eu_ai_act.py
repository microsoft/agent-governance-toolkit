# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""
EU AI Act Risk Classifier (Regulation 2024/1689)

Structured risk classification per Article 6 and Annex III with:
- Art. 5 prohibited practices detection
- Art. 6(1) Annex I safety-component path
- Art. 6(3) exemptions for narrow procedural tasks
- Profiling override per GDPR Art. 4(4)
- Configurable risk categories via external YAML/JSON

Promoted from examples/06-eu-ai-act-compliance per issue #756.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Any, Dict, List, Optional, Set

import yaml


# ---------------------------------------------------------------------------
# Risk levels
# ---------------------------------------------------------------------------

class RiskLevel(Enum):
    """EU AI Act risk tiers (Article 6)."""
    UNACCEPTABLE = "unacceptable"
    HIGH = "high"
    LIMITED = "limited"
    MINIMAL = "minimal"


# ---------------------------------------------------------------------------
# Agent profile
# ---------------------------------------------------------------------------

@dataclass
class AgentRiskProfile:
    """Describes an AI system for risk classification.

    Attributes:
        name: Human-readable system name.
        description: Free-text description of the system's purpose.
        domain: Primary domain / use-case identifier.
        capabilities: List of capability identifiers.
        is_safety_component: Whether the system is a safety component
            under EU harmonisation legislation (Annex I).
        harmonisation_legislation: Specific Annex I legislation if applicable.
        involves_profiling: Whether the system profiles natural persons
            per GDPR Art. 4(4).
        exemption_tags: Art. 6(3) exemption identifiers, if any.
    """
    name: str
    description: str = ""
    domain: str = ""
    capabilities: List[str] = field(default_factory=list)
    is_safety_component: bool = False
    harmonisation_legislation: Optional[str] = None
    involves_profiling: bool = False
    exemption_tags: List[str] = field(default_factory=list)


# ---------------------------------------------------------------------------
# Classification result
# ---------------------------------------------------------------------------

@dataclass
class ClassificationResult:
    """Result of a risk classification."""
    risk_level: RiskLevel
    triggers: List[str]
    exemptions_applied: List[str]
    profiling_override: bool = False


# ---------------------------------------------------------------------------
# Configuration loader
# ---------------------------------------------------------------------------

def _normalize(value: str) -> str:
    """Lowercase and replace spaces/hyphens with underscores."""
    return value.lower().replace(" ", "_").replace("-", "_")


def _load_config(path: Optional[Path] = None) -> Dict[str, Any]:
    """Load risk classification config from YAML or JSON.

    Falls back to the bundled ``eu_ai_act_defaults.yaml``.
    """
    if path is None:
        path = Path(__file__).parent / "eu_ai_act_defaults.yaml"

    with open(path) as f:
        if path.suffix in (".yaml", ".yml"):
            return yaml.safe_load(f)
        return json.load(f)


# ---------------------------------------------------------------------------
# Risk Classifier
# ---------------------------------------------------------------------------

class EUAIActRiskClassifier:
    """Classify an AI system's risk level per Article 6 and Annex III.

    Supports external configuration so classification rules can be updated
    when the regulation is amended (e.g. Annex III changes).

    Parameters:
        config_path: Optional path to a YAML or JSON config file.
            When ``None``, uses the bundled defaults.
    """

    def __init__(self, config_path: Optional[Path] = None) -> None:
        cfg = _load_config(config_path)
        self._unacceptable: Set[str] = set(cfg.get("unacceptable_domains", []))
        self._high_risk_domains: Set[str] = set(cfg.get("high_risk_domains", []))
        self._high_risk_caps: Set[str] = set(cfg.get("high_risk_capabilities", []))
        self._annex_i: Set[str] = set(cfg.get("annex_i_legislation", []))
        self._limited: Set[str] = set(cfg.get("limited_risk_indicators", []))
        self._exemptions: Set[str] = set(cfg.get("article_6_3_exemptions", []))

    # ---- public API ----

    def classify(self, profile: AgentRiskProfile) -> ClassificationResult:
        """Classify the risk level for an agent profile."""
        domain = _normalize(profile.domain)
        caps = {_normalize(c) for c in profile.capabilities}
        exemption_tags = {_normalize(t) for t in profile.exemption_tags}

        triggers: List[str] = []
        exemptions_applied: List[str] = []

        # 1. Article 5 -- Prohibited practices (always checked first)
        if domain in self._unacceptable:
            triggers.append(
                f"Domain '{profile.domain}' is prohibited under Article 5"
            )
            return ClassificationResult(
                risk_level=RiskLevel.UNACCEPTABLE,
                triggers=triggers,
                exemptions_applied=[],
            )

        # 2. Article 6(1) -- Safety component under Annex I legislation
        if profile.is_safety_component:
            legislation = _normalize(profile.harmonisation_legislation or "")
            if legislation in self._annex_i:
                triggers.append(
                    f"Safety component under Annex I legislation: "
                    f"{profile.harmonisation_legislation}"
                )
                return ClassificationResult(
                    risk_level=RiskLevel.HIGH,
                    triggers=triggers,
                    exemptions_applied=[],
                )

        # 3. Article 6(2) -- Annex III domain check
        is_annex_iii = domain in self._high_risk_domains

        if is_annex_iii:
            # 3a. Check Art. 6(3) exemptions
            valid_exemptions = exemption_tags & self._exemptions
            if valid_exemptions:
                # 3b. Profiling override: exemptions do NOT apply when profiling
                if profile.involves_profiling:
                    triggers.append(
                        f"Domain '{profile.domain}' listed in Annex III"
                    )
                    triggers.append(
                        "Art. 6(3) exemptions overridden: system involves "
                        "profiling of natural persons (GDPR Art. 4(4))"
                    )
                    return ClassificationResult(
                        risk_level=RiskLevel.HIGH,
                        triggers=triggers,
                        exemptions_applied=[],
                        profiling_override=True,
                    )
                else:
                    # Exemptions apply -- downgrade from HIGH
                    exemptions_applied = sorted(valid_exemptions)
                    triggers.append(
                        f"Domain '{profile.domain}' listed in Annex III "
                        f"but exempted under Art. 6(3)"
                    )
            else:
                triggers.append(
                    f"Domain '{profile.domain}' listed in Annex III (high-risk)"
                )
                return ClassificationResult(
                    risk_level=RiskLevel.HIGH,
                    triggers=triggers,
                    exemptions_applied=[],
                )

        # 4. Capability-based escalation
        matched_caps = caps & self._high_risk_caps
        if matched_caps and not exemptions_applied:
            triggers.append(
                f"High-risk capabilities: {', '.join(sorted(matched_caps))}"
            )
            return ClassificationResult(
                risk_level=RiskLevel.HIGH,
                triggers=triggers,
                exemptions_applied=[],
            )

        # 5. Article 50 -- LIMITED transparency obligations
        if domain in self._limited or caps & self._limited:
            triggers.append(
                "Transparency obligations under Article 50"
            )
            return ClassificationResult(
                risk_level=RiskLevel.LIMITED,
                triggers=triggers,
                exemptions_applied=exemptions_applied,
            )

        # 6. MINIMAL
        return ClassificationResult(
            risk_level=RiskLevel.MINIMAL,
            triggers=triggers or ["No elevated-risk triggers detected"],
            exemptions_applied=exemptions_applied,
        )
