# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""
EU AI Act Compliance Checker for AgentMesh

Implements compliance checks per the EU AI Act (Regulation 2024/1689):
- Article 6:  Risk classification (Unacceptable → High → Limited → Minimal)
- Article 13: Transparency requirements
- Article 14: Human oversight obligations
- Article 15: Accuracy, robustness, cybersecurity
- Article 17: Quality management system
- Article 50: Transparency for general-purpose AI

Runnable without API keys — uses self-contained logic and sample data.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, List, Optional


# ---------------------------------------------------------------------------
# Risk Classification (Article 6)
# ---------------------------------------------------------------------------

class RiskLevel(Enum):
    """EU AI Act risk tiers."""
    UNACCEPTABLE = "unacceptable"
    HIGH = "high"
    LIMITED = "limited"
    MINIMAL = "minimal"


# Domains that automatically trigger UNACCEPTABLE risk (Article 5)
UNACCEPTABLE_DOMAINS = {
    "social_scoring",
    "real_time_biometric_identification",
    "subliminal_manipulation",
    "exploitation_of_vulnerabilities",
    "predictive_policing_individual",
    "emotion_recognition_workplace",
    "emotion_recognition_education",
    "untargeted_facial_scraping",
}

# Domains / use-cases mapped to HIGH risk (Annex III)
HIGH_RISK_DOMAINS = {
    "biometric_identification",
    "critical_infrastructure",
    "education_training",
    "employment_recruitment",
    "essential_services",
    "law_enforcement",
    "migration_border",
    "justice_democracy",
    "medical_diagnosis",
    "credit_scoring",
    "insurance_pricing",
    "safety_components",
}

# Capabilities that elevate risk when present
HIGH_RISK_CAPABILITIES = {
    "autonomous_decision_making",
    "personal_data_processing",
    "safety_critical_control",
    "law_enforcement_support",
    "biometric_processing",
    "financial_decisioning",
}

# Use-cases that require LIMITED transparency (Article 50)
LIMITED_RISK_INDICATORS = {
    "chatbot",
    "content_generation",
    "deepfake_generation",
    "emotion_detection",
    "text_generation",
    "image_generation",
}


@dataclass
class AgentProfile:
    """Describes an AI agent for compliance assessment."""
    name: str
    description: str
    domain: str
    capabilities: List[str] = field(default_factory=list)
    has_human_oversight: bool = False
    transparency_disclosure: bool = False
    logs_decisions: bool = False
    tested_for_bias: bool = False
    has_documentation: bool = False
    has_risk_assessment: bool = False
    has_quality_management: bool = False
    cybersecurity_measures: bool = False
    accuracy_metrics_available: bool = False
    intended_users: str = "general_public"
    data_governance: bool = False
    version: str = "1.0.0"
    deployer: str = ""
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class ComplianceIssue:
    """A single compliance finding."""
    article: str
    requirement: str
    status: str  # "pass", "fail", "warning"
    detail: str
    severity: str  # "critical", "high", "medium", "low"


@dataclass
class ComplianceReport:
    """Full compliance assessment report."""
    agent_name: str
    risk_level: RiskLevel
    compliant: bool
    issues: List[ComplianceIssue]
    generated_at: str
    summary: str
    recommendations: List[str]


# ---------------------------------------------------------------------------
# Risk Classifier
# ---------------------------------------------------------------------------

class RiskClassifier:
    """Classify an agent's risk level per Article 6 and Annex III."""

    def classify(self, profile: AgentProfile) -> RiskLevel:
        domain = profile.domain.lower().replace(" ", "_").replace("-", "_")

        if domain in UNACCEPTABLE_DOMAINS:
            return RiskLevel.UNACCEPTABLE

        if domain in HIGH_RISK_DOMAINS:
            return RiskLevel.HIGH

        # Capability-based escalation
        agent_caps = {c.lower().replace(" ", "_").replace("-", "_") for c in profile.capabilities}
        if agent_caps & HIGH_RISK_CAPABILITIES:
            return RiskLevel.HIGH

        if domain in LIMITED_RISK_INDICATORS or agent_caps & LIMITED_RISK_INDICATORS:
            return RiskLevel.LIMITED

        return RiskLevel.MINIMAL

    def explain(self, profile: AgentProfile) -> Dict[str, Any]:
        level = self.classify(profile)
        domain = profile.domain.lower().replace(" ", "_").replace("-", "_")

        triggers: List[str] = []
        if domain in UNACCEPTABLE_DOMAINS:
            triggers.append(f"Domain '{profile.domain}' is prohibited under Article 5")
        elif domain in HIGH_RISK_DOMAINS:
            triggers.append(f"Domain '{profile.domain}' is listed in Annex III (high-risk)")

        agent_caps = {c.lower().replace(" ", "_").replace("-", "_") for c in profile.capabilities}
        matched = agent_caps & HIGH_RISK_CAPABILITIES
        if matched:
            triggers.append(f"High-risk capabilities: {', '.join(sorted(matched))}")

        if domain in LIMITED_RISK_INDICATORS:
            triggers.append(f"Domain '{profile.domain}' requires transparency disclosure")

        return {
            "risk_level": level.value,
            "triggers": triggers or ["No elevated-risk triggers detected"],
        }


# ---------------------------------------------------------------------------
# Article-specific checkers
# ---------------------------------------------------------------------------

class TransparencyChecker:
    """Check transparency requirements (Articles 13 & 50)."""

    def check(self, profile: AgentProfile, risk_level: RiskLevel) -> List[ComplianceIssue]:
        issues: List[ComplianceIssue] = []

        # Article 50 — users must know they interact with AI
        if not profile.transparency_disclosure:
            severity = "critical" if risk_level in (RiskLevel.HIGH, RiskLevel.LIMITED) else "medium"
            issues.append(ComplianceIssue(
                article="Article 50",
                requirement="AI system disclosure to users",
                status="fail",
                detail="Users are not informed they are interacting with an AI system.",
                severity=severity,
            ))
        else:
            issues.append(ComplianceIssue(
                article="Article 50",
                requirement="AI system disclosure to users",
                status="pass",
                detail="Users are informed they are interacting with an AI system.",
                severity="low",
            ))

        # Article 13 — high-risk systems need full transparency documentation
        if risk_level == RiskLevel.HIGH:
            if not profile.has_documentation:
                issues.append(ComplianceIssue(
                    article="Article 13",
                    requirement="Transparency for high-risk AI",
                    status="fail",
                    detail="High-risk system lacks required technical documentation "
                           "describing its capabilities, limitations, and intended purpose.",
                    severity="critical",
                ))
            else:
                issues.append(ComplianceIssue(
                    article="Article 13",
                    requirement="Transparency for high-risk AI",
                    status="pass",
                    detail="Technical documentation is available.",
                    severity="low",
                ))

        return issues


class HumanOversightChecker:
    """Check human oversight requirements (Article 14)."""

    def check(self, profile: AgentProfile, risk_level: RiskLevel) -> List[ComplianceIssue]:
        issues: List[ComplianceIssue] = []

        if risk_level in (RiskLevel.HIGH, RiskLevel.UNACCEPTABLE):
            if not profile.has_human_oversight:
                issues.append(ComplianceIssue(
                    article="Article 14",
                    requirement="Human oversight for high-risk AI",
                    status="fail",
                    detail="No human oversight mechanism. High-risk AI systems must allow "
                           "meaningful human control including the ability to override, "
                           "interrupt, or shut down the system.",
                    severity="critical",
                ))
            else:
                issues.append(ComplianceIssue(
                    article="Article 14",
                    requirement="Human oversight for high-risk AI",
                    status="pass",
                    detail="Human oversight mechanism is in place.",
                    severity="low",
                ))

        return issues


class RecordKeepingChecker:
    """Check record-keeping / logging obligations (Article 12)."""

    def check(self, profile: AgentProfile, risk_level: RiskLevel) -> List[ComplianceIssue]:
        issues: List[ComplianceIssue] = []

        if risk_level == RiskLevel.HIGH:
            if not profile.logs_decisions:
                issues.append(ComplianceIssue(
                    article="Article 12",
                    requirement="Automatic logging for high-risk AI",
                    status="fail",
                    detail="High-risk system does not log decisions. Automatic logging "
                           "of events is required for traceability throughout the system's "
                           "lifecycle.",
                    severity="high",
                ))
            else:
                issues.append(ComplianceIssue(
                    article="Article 12",
                    requirement="Automatic logging for high-risk AI",
                    status="pass",
                    detail="Decision logging is enabled.",
                    severity="low",
                ))

        return issues


class AccuracyRobustnessChecker:
    """Check accuracy, robustness, and cybersecurity (Article 15)."""

    def check(self, profile: AgentProfile, risk_level: RiskLevel) -> List[ComplianceIssue]:
        issues: List[ComplianceIssue] = []

        if risk_level == RiskLevel.HIGH:
            if not profile.accuracy_metrics_available:
                issues.append(ComplianceIssue(
                    article="Article 15",
                    requirement="Accuracy metrics for high-risk AI",
                    status="fail",
                    detail="No accuracy metrics documented. High-risk AI systems must "
                           "achieve appropriate levels of accuracy for their intended purpose.",
                    severity="high",
                ))

            if not profile.cybersecurity_measures:
                issues.append(ComplianceIssue(
                    article="Article 15",
                    requirement="Cybersecurity measures",
                    status="fail",
                    detail="Cybersecurity measures not documented. High-risk AI systems "
                           "must be resilient against unauthorized access and manipulation.",
                    severity="high",
                ))

            if not profile.tested_for_bias:
                issues.append(ComplianceIssue(
                    article="Article 15",
                    requirement="Robustness and bias testing",
                    status="fail",
                    detail="System has not been tested for bias. High-risk AI must be "
                           "robust and not produce discriminatory outcomes.",
                    severity="high",
                ))

        return issues


class QualityManagementChecker:
    """Check quality management system (Article 17)."""

    def check(self, profile: AgentProfile, risk_level: RiskLevel) -> List[ComplianceIssue]:
        issues: List[ComplianceIssue] = []

        if risk_level == RiskLevel.HIGH:
            if not profile.has_quality_management:
                issues.append(ComplianceIssue(
                    article="Article 17",
                    requirement="Quality management system",
                    status="fail",
                    detail="No quality management system. Providers of high-risk AI must "
                           "establish a QMS covering risk management, data governance, "
                           "post-market monitoring, and incident reporting.",
                    severity="high",
                ))
            else:
                issues.append(ComplianceIssue(
                    article="Article 17",
                    requirement="Quality management system",
                    status="pass",
                    detail="Quality management system is in place.",
                    severity="low",
                ))

            if not profile.data_governance:
                issues.append(ComplianceIssue(
                    article="Article 17",
                    requirement="Data governance practices",
                    status="fail",
                    detail="Data governance practices are not documented as part of the "
                           "quality management system.",
                    severity="medium",
                ))

            if not profile.has_risk_assessment:
                issues.append(ComplianceIssue(
                    article="Article 17",
                    requirement="Risk management procedures",
                    status="fail",
                    detail="No documented risk assessment. The QMS must include a risk "
                           "management process.",
                    severity="high",
                ))

        return issues


# ---------------------------------------------------------------------------
# Compliance Engine — ties everything together
# ---------------------------------------------------------------------------

class EUAIActComplianceChecker:
    """Orchestrates a full EU AI Act compliance assessment for an agent."""

    def __init__(self) -> None:
        self.risk_classifier = RiskClassifier()
        self.transparency = TransparencyChecker()
        self.human_oversight = HumanOversightChecker()
        self.record_keeping = RecordKeepingChecker()
        self.accuracy_robustness = AccuracyRobustnessChecker()
        self.quality_management = QualityManagementChecker()

    # ----- public API -----

    def classify_risk(self, profile: AgentProfile) -> RiskLevel:
        return self.risk_classifier.classify(profile)

    def explain_risk(self, profile: AgentProfile) -> Dict[str, Any]:
        return self.risk_classifier.explain(profile)

    def check_compliance(self, profile: AgentProfile) -> ComplianceReport:
        risk_level = self.classify_risk(profile)

        # Unacceptable-risk systems are outright prohibited
        if risk_level == RiskLevel.UNACCEPTABLE:
            return ComplianceReport(
                agent_name=profile.name,
                risk_level=risk_level,
                compliant=False,
                issues=[ComplianceIssue(
                    article="Article 5",
                    requirement="Prohibited AI practices",
                    status="fail",
                    detail=f"AI system in domain '{profile.domain}' is classified as "
                           f"UNACCEPTABLE risk and is PROHIBITED under the EU AI Act.",
                    severity="critical",
                )],
                generated_at=datetime.now(timezone.utc).isoformat(),
                summary="DEPLOYMENT BLOCKED — system falls under prohibited AI practices.",
                recommendations=["Do not deploy this system in the EU."],
            )

        # Collect issues from each checker
        issues: List[ComplianceIssue] = []
        issues.extend(self.transparency.check(profile, risk_level))
        issues.extend(self.human_oversight.check(profile, risk_level))
        issues.extend(self.record_keeping.check(profile, risk_level))
        issues.extend(self.accuracy_robustness.check(profile, risk_level))
        issues.extend(self.quality_management.check(profile, risk_level))

        failures = [i for i in issues if i.status == "fail"]
        critical = [i for i in failures if i.severity == "critical"]
        compliant = len(critical) == 0

        recommendations = _build_recommendations(failures)

        if compliant and failures:
            summary = (
                f"Conditionally compliant — {len(failures)} non-critical issue(s) "
                f"should be addressed before production deployment."
            )
        elif compliant:
            summary = "Fully compliant with all assessed EU AI Act requirements."
        else:
            summary = (
                f"NOT COMPLIANT — {len(critical)} critical issue(s) must be resolved "
                f"before deployment."
            )

        return ComplianceReport(
            agent_name=profile.name,
            risk_level=risk_level,
            compliant=compliant,
            issues=issues,
            generated_at=datetime.now(timezone.utc).isoformat(),
            summary=summary,
            recommendations=recommendations,
        )

    def can_deploy(self, profile: AgentProfile) -> bool:
        """Return True only if the agent passes all critical compliance checks."""
        report = self.check_compliance(profile)
        return report.compliant

    def format_report(self, report: ComplianceReport) -> str:
        """Return a human-readable compliance report."""
        lines: List[str] = []

        lines.append("=" * 70)
        lines.append("EU AI ACT COMPLIANCE REPORT")
        lines.append("=" * 70)
        lines.append(f"Agent:        {report.agent_name}")
        lines.append(f"Risk Level:   {report.risk_level.value.upper()}")
        lines.append(f"Compliant:    {'Yes' if report.compliant else 'NO'}")
        lines.append(f"Generated:    {report.generated_at}")
        lines.append("")
        lines.append(f"Summary: {report.summary}")
        lines.append("")

        # Group by article
        lines.append("-" * 70)
        lines.append("DETAILED FINDINGS")
        lines.append("-" * 70)

        for issue in report.issues:
            icon = {"pass": "✅", "fail": "❌", "warning": "⚠️"}.get(issue.status, "•")
            lines.append(f"\n{icon}  [{issue.article}] {issue.requirement}")
            lines.append(f"   Status:   {issue.status.upper()}")
            lines.append(f"   Severity: {issue.severity}")
            lines.append(f"   Detail:   {issue.detail}")

        if report.recommendations:
            lines.append("")
            lines.append("-" * 70)
            lines.append("RECOMMENDATIONS")
            lines.append("-" * 70)
            for idx, rec in enumerate(report.recommendations, 1):
                lines.append(f"  {idx}. {rec}")

        lines.append("")
        lines.append("=" * 70)
        return "\n".join(lines)

    def to_json(self, report: ComplianceReport) -> str:
        """Serialize a report to JSON."""
        return json.dumps({
            "agent_name": report.agent_name,
            "risk_level": report.risk_level.value,
            "compliant": report.compliant,
            "generated_at": report.generated_at,
            "summary": report.summary,
            "issues": [
                {
                    "article": i.article,
                    "requirement": i.requirement,
                    "status": i.status,
                    "detail": i.detail,
                    "severity": i.severity,
                }
                for i in report.issues
            ],
            "recommendations": report.recommendations,
        }, indent=2)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

_RECOMMENDATION_MAP: Dict[str, str] = {
    "Article 50": "Add a clear disclosure informing users they are interacting with AI.",
    "Article 13": "Create technical documentation covering capabilities, limitations, and intended purpose.",
    "Article 14": "Implement human oversight controls (override, interrupt, shutdown).",
    "Article 12": "Enable automatic decision logging for traceability.",
    "Article 15": "Document accuracy metrics, bias testing results, and cybersecurity measures.",
    "Article 17": "Establish a quality management system with risk management, data governance, and monitoring.",
}


def _build_recommendations(failures: List[ComplianceIssue]) -> List[str]:
    seen_articles: set[str] = set()
    recs: List[str] = []
    for issue in failures:
        if issue.article not in seen_articles:
            seen_articles.add(issue.article)
            rec = _RECOMMENDATION_MAP.get(issue.article)
            if rec:
                recs.append(rec)
            else:
                recs.append(f"Address {issue.article}: {issue.requirement}")
    return recs
