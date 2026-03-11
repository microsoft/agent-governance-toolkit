"""Compliance validation component for Langflow flows.

Validates agent actions against compliance frameworks:
- EU AI Act: transparency, risk classification, human oversight
- SOC2: access control, audit logging, change management
- HIPAA: PHI protection, access logging, minimum necessary
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional


class ComplianceFramework(Enum):
    """Supported compliance frameworks."""

    EU_AI_ACT = "eu_ai_act"
    SOC2 = "soc2"
    HIPAA = "hipaa"


class RiskLevel(Enum):
    """EU AI Act risk classification."""

    UNACCEPTABLE = "unacceptable"
    HIGH = "high"
    LIMITED = "limited"
    MINIMAL = "minimal"


class ComplianceStatus(Enum):
    """Overall compliance status."""

    COMPLIANT = "compliant"
    NON_COMPLIANT = "non_compliant"
    REQUIRES_REVIEW = "requires_review"


@dataclass
class ComplianceViolation:
    """A single compliance violation."""

    framework: ComplianceFramework
    rule: str
    description: str
    severity: str = "medium"
    required_action: str = ""

    def to_dict(self) -> Dict[str, Any]:
        """Serialize to dictionary."""
        return {
            "framework": self.framework.value,
            "rule": self.rule,
            "description": self.description,
            "severity": self.severity,
            "required_action": self.required_action,
        }


@dataclass
class ComplianceResult:
    """Result of compliance validation."""

    compliance_status: ComplianceStatus
    frameworks_checked: List[str] = field(default_factory=list)
    violations: List[ComplianceViolation] = field(default_factory=list)
    required_actions: List[str] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        """Serialize to dictionary."""
        return {
            "compliance_status": self.compliance_status.value,
            "frameworks_checked": self.frameworks_checked,
            "violations": [v.to_dict() for v in self.violations],
            "required_actions": self.required_actions,
            "metadata": self.metadata,
        }


def _json_dumps_safe(obj: Any) -> str:
    """Safe JSON serialization for parameter scanning."""
    try:
        return json.dumps(obj, default=str)
    except (TypeError, ValueError):
        return str(obj)


# PHI detection patterns (SSN, MRN, phone, email, DOB patterns)
_PHI_PATTERNS = [
    (r"\b\d{3}-\d{2}-\d{4}\b", "SSN detected"),
    (r"\bMRN\s*[:#]?\s*\d+\b", "Medical Record Number detected"),
    (r"\b(?:DOB|date of birth)\s*[:#]?\s*\d{1,2}[/\-]\d{1,2}[/\-]\d{2,4}\b", "Date of Birth detected"),
    (r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b", "Email address detected"),
]

# High-risk AI domains per EU AI Act
_HIGH_RISK_DOMAINS = {
    "biometric", "law_enforcement", "migration", "justice",
    "employment", "education", "critical_infrastructure",
    "credit_scoring", "insurance",
}

# Unacceptable risk keywords
_UNACCEPTABLE_KEYWORDS = [
    "social_scoring", "subliminal_manipulation", "exploitation_vulnerability",
    "real_time_biometric", "emotion_recognition_workplace",
]


class ComplianceChecker:
    """Validates actions against compliance frameworks.

    Langflow component metadata:
    - display_name: "Compliance Checker"
    - description: "Validates actions against EU AI Act, SOC2, HIPAA"
    - icon: "check-square"
    """

    display_name = "Compliance Checker"
    description = "Validates actions against EU AI Act, SOC2, HIPAA"
    icon = "check-square"

    def __init__(
        self,
        frameworks: Optional[List[ComplianceFramework]] = None,
    ) -> None:
        self.frameworks: List[ComplianceFramework] = frameworks or [
            ComplianceFramework.EU_AI_ACT,
            ComplianceFramework.SOC2,
            ComplianceFramework.HIPAA,
        ]
        self._compiled_phi = [
            (re.compile(p, re.IGNORECASE), desc) for p, desc in _PHI_PATTERNS
        ]

    def check(
        self,
        action: str,
        parameters: Optional[Dict[str, Any]] = None,
        agent_id: Optional[str] = None,
        context: Optional[Dict[str, Any]] = None,
    ) -> ComplianceResult:
        """Validate an action against all configured frameworks."""
        params = parameters or {}
        ctx = context or {}
        violations: List[ComplianceViolation] = []
        required_actions: List[str] = []
        frameworks_checked: List[str] = []

        for framework in self.frameworks:
            frameworks_checked.append(framework.value)

            if framework == ComplianceFramework.EU_AI_ACT:
                v, a = self._check_eu_ai_act(action, params, ctx)
                violations.extend(v)
                required_actions.extend(a)

            elif framework == ComplianceFramework.SOC2:
                v, a = self._check_soc2(action, params, agent_id, ctx)
                violations.extend(v)
                required_actions.extend(a)

            elif framework == ComplianceFramework.HIPAA:
                v, a = self._check_hipaa(action, params, ctx)
                violations.extend(v)
                required_actions.extend(a)

        if not violations:
            status = ComplianceStatus.COMPLIANT
        elif any(v.severity == "critical" for v in violations):
            status = ComplianceStatus.NON_COMPLIANT
        else:
            status = ComplianceStatus.REQUIRES_REVIEW

        return ComplianceResult(
            compliance_status=status,
            frameworks_checked=frameworks_checked,
            violations=violations,
            required_actions=list(dict.fromkeys(required_actions)),
            metadata={"agent_id": agent_id, "action": action},
        )

    def _check_eu_ai_act(
        self,
        action: str,
        parameters: Dict[str, Any],
        context: Dict[str, Any],
    ) -> tuple:
        """EU AI Act checks: transparency, risk classification, human oversight."""
        violations: List[ComplianceViolation] = []
        actions: List[str] = []

        domain = context.get("domain", "")
        risk_level = self._classify_risk(action, domain)

        if risk_level == RiskLevel.UNACCEPTABLE:
            violations.append(ComplianceViolation(
                framework=ComplianceFramework.EU_AI_ACT,
                rule="Article 5 - Prohibited AI Practices",
                description=f"Action '{action}' classified as unacceptable risk",
                severity="critical",
                required_action="Block action — prohibited under EU AI Act",
            ))
            actions.append("Block action — prohibited under EU AI Act")

        if risk_level == RiskLevel.HIGH:
            if not context.get("transparency_notice"):
                violations.append(ComplianceViolation(
                    framework=ComplianceFramework.EU_AI_ACT,
                    rule="Article 13 - Transparency",
                    description="High-risk AI system requires transparency notice",
                    severity="high",
                    required_action="Add transparency notice for high-risk AI action",
                ))
                actions.append("Add transparency notice for high-risk AI action")

            if not context.get("human_oversight"):
                violations.append(ComplianceViolation(
                    framework=ComplianceFramework.EU_AI_ACT,
                    rule="Article 14 - Human Oversight",
                    description="High-risk AI system requires human oversight",
                    severity="high",
                    required_action="Enable human oversight for high-risk AI action",
                ))
                actions.append("Enable human oversight for high-risk AI action")

        return violations, actions

    def _check_soc2(
        self,
        action: str,
        parameters: Dict[str, Any],
        agent_id: Optional[str],
        context: Dict[str, Any],
    ) -> tuple:
        """SOC2 checks: access control, audit logging, change management."""
        violations: List[ComplianceViolation] = []
        actions: List[str] = []

        if not agent_id:
            violations.append(ComplianceViolation(
                framework=ComplianceFramework.SOC2,
                rule="CC6.1 - Logical Access",
                description="Agent identity required for access control",
                severity="high",
                required_action="Provide agent_id for audit trail",
            ))
            actions.append("Provide agent_id for audit trail")

        if not context.get("audit_enabled", False):
            violations.append(ComplianceViolation(
                framework=ComplianceFramework.SOC2,
                rule="CC7.2 - System Monitoring",
                description="Audit logging must be enabled for compliance",
                severity="medium",
                required_action="Enable audit logging",
            ))
            actions.append("Enable audit logging")

        sensitive_actions = context.get("sensitive_actions", [
            "delete", "modify", "deploy", "configure",
        ])
        if action.lower() in [a.lower() for a in sensitive_actions]:
            if not context.get("change_approved", False):
                violations.append(ComplianceViolation(
                    framework=ComplianceFramework.SOC2,
                    rule="CC8.1 - Change Management",
                    description=f"Sensitive action '{action}' requires change approval",
                    severity="medium",
                    required_action=f"Obtain approval for sensitive action '{action}'",
                ))
                actions.append(f"Obtain approval for sensitive action '{action}'")

        return violations, actions

    def _check_hipaa(
        self,
        action: str,
        parameters: Dict[str, Any],
        context: Dict[str, Any],
    ) -> tuple:
        """HIPAA checks: PHI protection, access logging, minimum necessary."""
        violations: List[ComplianceViolation] = []
        actions: List[str] = []

        all_text = f"{action} {_json_dumps_safe(parameters)}"
        phi_found = self._detect_phi(all_text)
        if phi_found:
            violations.append(ComplianceViolation(
                framework=ComplianceFramework.HIPAA,
                rule="§164.502 - PHI Protection",
                description=f"Protected Health Information detected: {', '.join(phi_found)}",
                severity="critical",
                required_action="Remove or encrypt PHI before processing",
            ))
            actions.append("Remove or encrypt PHI before processing")

        if context.get("data_scope") == "full" and not context.get("minimum_necessary_justified"):
            violations.append(ComplianceViolation(
                framework=ComplianceFramework.HIPAA,
                rule="§164.502(b) - Minimum Necessary",
                description="Full data scope requested without minimum necessary justification",
                severity="medium",
                required_action="Justify full data scope or limit to minimum necessary",
            ))
            actions.append("Justify full data scope or limit to minimum necessary")

        if not context.get("access_logged", False):
            violations.append(ComplianceViolation(
                framework=ComplianceFramework.HIPAA,
                rule="§164.312(b) - Audit Controls",
                description="PHI access must be logged",
                severity="medium",
                required_action="Enable access logging for PHI operations",
            ))
            actions.append("Enable access logging for PHI operations")

        return violations, actions

    def _classify_risk(self, action: str, domain: str) -> RiskLevel:
        """Classify AI risk level per EU AI Act."""
        combined = f"{action} {domain}".lower()

        for keyword in _UNACCEPTABLE_KEYWORDS:
            if keyword in combined:
                return RiskLevel.UNACCEPTABLE

        if domain.lower() in _HIGH_RISK_DOMAINS:
            return RiskLevel.HIGH

        for hr_domain in _HIGH_RISK_DOMAINS:
            if hr_domain in combined:
                return RiskLevel.HIGH

        return RiskLevel.MINIMAL

    def _detect_phi(self, text: str) -> List[str]:
        """Detect PHI patterns in text."""
        found: List[str] = []
        for compiled, description in self._compiled_phi:
            if compiled.search(text):
                found.append(description)
        return found
