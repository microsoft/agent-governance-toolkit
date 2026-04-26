# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""
EU AI Act Annex IV — Technical Documentation Exporter

Assembles existing governance artifacts (ComplianceReport, Policy,
AuditLog entries) into the structured format required by EU AI Act
Article 11 and Annex IV for high-risk AI system conformity assessment.

References:
    - EU AI Act (Regulation 2024/1689), Article 11 & Annex IV
    - docs/compliance/eu-ai-act-checklist.md
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

from pydantic import BaseModel, Field

from .audit import AuditEntry
from .compliance import ComplianceFramework, ComplianceReport
from .policy import Policy

# ---------------------------------------------------------------------------
# Annex IV section models
# ---------------------------------------------------------------------------

_PLACEHOLDER = (
    "<!-- DEPLOYER ACTION REQUIRED: " "This section requires deployer-provided content. -->"
)


class AnnexIVSection(BaseModel):
    """A single section of the Annex IV technical documentation.

    Attributes:
        number: Section number (e.g. ``"1"``, ``"2.1"``).
        title: Section heading.
        content: Auto-generated content from toolkit artifacts.
        placeholder: Content the deployer must fill in manually.
        source_artifacts: Names of toolkit artifacts used to populate this section.
    """

    number: str
    title: str
    content: str = ""
    placeholder: str = ""
    source_artifacts: list[str] = Field(default_factory=list)


class AnnexIVDocument(BaseModel):
    """Complete Annex IV technical documentation dossier.

    Attributes:
        title: Document title.
        generated_at: ISO-8601 timestamp of generation.
        system_name: Name of the AI system being documented.
        provider: Organisation providing the AI system.
        sections: Ordered list of Annex IV sections.
        metadata: Additional key-value metadata.
    """

    title: str = "EU AI Act — Annex IV Technical Documentation"
    generated_at: str = Field(default_factory=lambda: datetime.now(UTC).isoformat())
    system_name: str = ""
    provider: str = ""
    sections: list[AnnexIVSection] = Field(default_factory=list)
    metadata: dict[str, Any] = Field(default_factory=dict)


# ---------------------------------------------------------------------------
# Exporter
# ---------------------------------------------------------------------------


class TechnicalDocumentationExporter:
    """Assemble governance artifacts into an Annex IV conformity dossier.

    Usage::

        exporter = TechnicalDocumentationExporter(
            system_name="OptimusAI Trading Agent",
            provider="Acme Energy Corp",
        )
        exporter.add_compliance_report(report)
        exporter.add_policies([policy_a, policy_b])
        exporter.add_audit_entries(entries)

        doc = exporter.export()
        print(doc.to_markdown())

    Args:
        system_name: Name of the AI system.
        provider: Organisation name of the AI system provider.
        system_description: Free-text description of the system's
            intended purpose.  When omitted a placeholder is generated.
        system_version: Version string for the system.
    """

    def __init__(
        self,
        system_name: str,
        provider: str,
        system_description: str = "",
        system_version: str = "",
    ) -> None:
        self._system_name = system_name
        self._provider = provider
        self._system_description = system_description
        self._system_version = system_version

        self._compliance_reports: list[ComplianceReport] = []
        self._policies: list[Policy] = []
        self._audit_entries: list[AuditEntry] = []
        self._slo_data: dict[str, Any] = {}

    # ----- data ingestion -----

    def add_compliance_report(self, report: ComplianceReport) -> None:
        """Add a compliance report to the dossier.

        Args:
            report: A ``ComplianceReport`` from the compliance engine.
        """
        self._compliance_reports.append(report)

    def add_policies(self, policies: list[Policy]) -> None:
        """Add governance policies to the dossier.

        Args:
            policies: List of ``Policy`` objects to include.
        """
        self._policies.extend(policies)

    def add_audit_entries(self, entries: list[AuditEntry]) -> None:
        """Add audit log entries to the dossier.

        Args:
            entries: List of ``AuditEntry`` records to include.
        """
        self._audit_entries.extend(entries)

    def add_slo_data(self, data: dict[str, Any]) -> None:
        """Add SLO/SLI metrics data to the dossier.

        Args:
            data: Dictionary of SLO metric names to values.
        """
        self._slo_data.update(data)

    # ----- export -----

    def export(self) -> AnnexIVDocument:
        """Assemble all ingested artifacts into an ``AnnexIVDocument``.

        Returns:
            A fully populated ``AnnexIVDocument`` with auto-generated
            content and placeholders for deployer-provided sections.
        """
        sections = [
            self._build_section_1(),
            self._build_section_2(),
            self._build_section_3(),
            self._build_section_4(),
            self._build_section_5(),
        ]
        return AnnexIVDocument(
            system_name=self._system_name,
            provider=self._provider,
            sections=sections,
            metadata={
                "system_version": self._system_version,
                "compliance_reports_count": len(self._compliance_reports),
                "policies_count": len(self._policies),
                "audit_entries_count": len(self._audit_entries),
            },
        )

    # ----- section builders -----

    def _build_section_1(self) -> AnnexIVSection:
        """Section 1: General description of the AI system."""
        lines: list[str] = []
        lines.append(f"**System name:** {self._system_name}")
        lines.append(f"**Provider:** {self._provider}")
        if self._system_version:
            lines.append(f"**Version:** {self._system_version}")

        if self._system_description:
            lines.append("")
            lines.append(f"**Intended purpose:** {self._system_description}")

        # Risk classification from compliance reports
        sources: list[str] = []
        eu_reports = [
            r for r in self._compliance_reports if r.framework == ComplianceFramework.EU_AI_ACT
        ]
        if eu_reports:
            latest = eu_reports[-1]
            lines.append("")
            lines.append(f"**Compliance score:** {latest.compliance_score:.1f}/100")
            lines.append(f"**Controls evaluated:** {latest.total_controls}")
            lines.append(f"**Controls met:** {latest.controls_met}")
            lines.append(f"**Controls failed:** {latest.controls_failed}")
            sources.append("ComplianceReport")

        placeholder = ""
        if not self._system_description:
            placeholder = (
                f"{_PLACEHOLDER}\n"
                "Provide a detailed description of the AI system's "
                "intended purpose, the persons or groups on whom the "
                "system is intended to be used, and the overall "
                "interaction logic."
            )

        return AnnexIVSection(
            number="1",
            title="General Description of the AI System",
            content="\n".join(lines),
            placeholder=placeholder,
            source_artifacts=sources,
        )

    def _build_section_2(self) -> AnnexIVSection:
        """Section 2: Detailed description of development process."""
        lines: list[str] = []
        sources: list[str] = []

        if self._policies:
            lines.append("### Governance Policies")
            lines.append("")
            for policy in self._policies:
                lines.append(f"- **{policy.name}**")
                if policy.description:
                    lines.append(f"  {policy.description}")
                lines.append(f"  Scope: {policy.scope}")
                lines.append(f"  Rules: {len(policy.rules)}")
                lines.append(f"  Default action: {policy.default_action}")
                lines.append("")
            sources.append("Policy")

        placeholder = (
            f"{_PLACEHOLDER}\n"
            "Provide:\n"
            "- Design specifications and development methodology\n"
            "- Data requirements and data governance practices\n"
            "- Applied harmonised standards or common specifications\n"
            "- Description of the training, validation, and testing "
            "procedures and datasets used"
        )

        return AnnexIVSection(
            number="2",
            title="Detailed Description of the Development Process",
            content="\n".join(lines),
            placeholder=placeholder,
            source_artifacts=sources,
        )

    def _build_section_3(self) -> AnnexIVSection:
        """Section 3: Monitoring, functioning, and control."""
        lines: list[str] = []
        sources: list[str] = []

        # Audit trail summary
        if self._audit_entries:
            lines.append("### Audit Trail Summary")
            lines.append("")
            lines.append(f"**Total audit entries:** {len(self._audit_entries)}")

            event_types: dict[str, int] = {}
            outcomes: dict[str, int] = {}
            for entry in self._audit_entries:
                event_types[entry.event_type] = event_types.get(entry.event_type, 0) + 1
                outcomes[entry.outcome] = outcomes.get(entry.outcome, 0) + 1

            lines.append("")
            lines.append("**Event types:**")
            for etype, count in sorted(event_types.items(), key=lambda x: x[1], reverse=True):
                lines.append(f"- {etype}: {count}")

            lines.append("")
            lines.append("**Outcomes:**")
            for outcome, count in sorted(outcomes.items(), key=lambda x: x[1], reverse=True):
                lines.append(f"- {outcome}: {count}")

            sources.append("AuditLog")

        # SLO/SLI data
        if self._slo_data:
            lines.append("")
            lines.append("### SLO/SLI Metrics")
            lines.append("")
            for metric, value in self._slo_data.items():
                lines.append(f"- **{metric}:** {value}")
            sources.append("SLO/SLI")

        # Compliance findings
        if self._compliance_reports:
            lines.append("")
            lines.append("### Compliance Findings")
            lines.append("")
            for report in self._compliance_reports:
                lines.append(f"**Framework:** {report.framework.value}")
                lines.append(
                    f"**Period:** "
                    f"{report.period_start.isoformat()} to "
                    f"{report.period_end.isoformat()}"
                )
                lines.append(f"**Score:** {report.compliance_score:.1f}/100")
                if report.violations:
                    lines.append(f"**Violations:** {len(report.violations)}")
                    for v in report.violations[:10]:
                        lines.append(f"- [{v.severity}] {v.control_id}: " f"{v.description}")
                if report.recommendations:
                    lines.append("")
                    lines.append("**Recommendations:**")
                    for rec in report.recommendations:
                        lines.append(f"- {rec}")
                lines.append("")
            sources.append("ComplianceReport")

        placeholder = (
            f"{_PLACEHOLDER}\n"
            "Provide:\n"
            "- Description of the system's capabilities and "
            "limitations\n"
            "- Human oversight measures and intervention mechanisms\n"
            "- Expected lifetime and maintenance schedule"
        )

        return AnnexIVSection(
            number="3",
            title="Monitoring, Functioning, and Control",
            content="\n".join(lines),
            placeholder=placeholder,
            source_artifacts=sources,
        )

    def _build_section_4(self) -> AnnexIVSection:
        """Section 4: Risk management system."""
        lines: list[str] = []
        sources: list[str] = []

        # Extract risk-related violations
        risk_violations = [
            v
            for r in self._compliance_reports
            for v in r.violations
            if "risk" in v.control_id.lower() or "risk" in v.description.lower()
        ]

        if risk_violations:
            lines.append("### Identified Risks from Compliance Checks")
            lines.append("")
            for v in risk_violations:
                status = "Remediated" if v.remediated else "Open"
                lines.append(f"- **{v.control_id}** [{v.severity}] " f"({status}): {v.description}")
            lines.append("")
            sources.append("ComplianceReport")

        # Policy-based risk controls
        risk_policies = [
            p
            for p in self._policies
            if any(r.action in ("deny", "require_approval") for r in p.rules)
        ]
        if risk_policies:
            lines.append("### Risk Mitigation Policies")
            lines.append("")
            for policy in risk_policies:
                deny_rules = [r for r in policy.rules if r.action in ("deny", "require_approval")]
                lines.append(f"- **{policy.name}**: " f"{len(deny_rules)} protective rule(s)")
                for rule in deny_rules:
                    lines.append(f"  - {rule.name}: {rule.action} " f"when `{rule.condition}`")
            lines.append("")
            sources.append("Policy")

        placeholder = (
            f"{_PLACEHOLDER}\n"
            "Provide:\n"
            "- Complete risk register with identified risks, "
            "likelihood, and impact assessments\n"
            "- Residual risk analysis after mitigation measures\n"
            "- Risk management process documentation per Article 9"
        )

        return AnnexIVSection(
            number="4",
            title="Risk Management System",
            content="\n".join(lines),
            placeholder=placeholder,
            source_artifacts=sources,
        )

    def _build_section_5(self) -> AnnexIVSection:
        """Section 5: Accuracy, robustness, and cybersecurity."""
        lines: list[str] = []
        sources: list[str] = []

        # SLI metrics relevant to accuracy
        accuracy_keys = [
            k
            for k in self._slo_data
            if any(
                term in k.lower()
                for term in ("accuracy", "error", "hallucination", "success", "latency")
            )
        ]
        if accuracy_keys:
            lines.append("### Performance Metrics")
            lines.append("")
            for key in accuracy_keys:
                lines.append(f"- **{key}:** {self._slo_data[key]}")
            lines.append("")
            sources.append("SLO/SLI")

        # Security-related audit events
        security_events = [
            e
            for e in self._audit_entries
            if any(
                term in e.event_type.lower() for term in ("security", "auth", "denied", "violation")
            )
            or e.outcome in ("denied", "error")
        ]
        if security_events:
            lines.append("### Security Events Summary")
            lines.append("")
            lines.append(f"**Security-related events:** {len(security_events)}")
            denied = sum(1 for e in security_events if e.outcome == "denied")
            errors = sum(1 for e in security_events if e.outcome == "error")
            lines.append(f"- Access denied: {denied}")
            lines.append(f"- Errors: {errors}")
            lines.append("")
            sources.append("AuditLog")

        placeholder = (
            f"{_PLACEHOLDER}\n"
            "Provide:\n"
            "- Accuracy metrics and levels declared per Article 15\n"
            "- Robustness testing results (adversarial, edge cases)\n"
            "- Cybersecurity measures and penetration testing results\n"
            "- Bias testing methodology and outcomes"
        )

        return AnnexIVSection(
            number="5",
            title="Accuracy, Robustness, and Cybersecurity",
            content="\n".join(lines),
            placeholder=placeholder,
            source_artifacts=sources,
        )


# ---------------------------------------------------------------------------
# Serialization helpers
# ---------------------------------------------------------------------------


def to_markdown(doc: AnnexIVDocument) -> str:
    """Render an ``AnnexIVDocument`` as Markdown.

    Args:
        doc: The document to render.

    Returns:
        A Markdown string suitable for inclusion in a conformity dossier.
    """
    lines: list[str] = []
    lines.append(f"# {doc.title}")
    lines.append("")
    lines.append(f"**System:** {doc.system_name}")
    lines.append(f"**Provider:** {doc.provider}")
    lines.append(f"**Generated:** {doc.generated_at}")
    lines.append("")
    lines.append("---")
    lines.append("")

    for section in doc.sections:
        lines.append(f"## Section {section.number}: {section.title}")
        lines.append("")

        if section.content:
            lines.append(section.content)
            lines.append("")

        if section.placeholder:
            lines.append(section.placeholder)
            lines.append("")

        if section.source_artifacts:
            lines.append(f"*Sources: {', '.join(section.source_artifacts)}*")
            lines.append("")

        lines.append("---")
        lines.append("")

    return "\n".join(lines)


def to_json(doc: AnnexIVDocument) -> str:
    """Serialize an ``AnnexIVDocument`` to JSON.

    Args:
        doc: The document to serialize.

    Returns:
        A JSON string.
    """
    return doc.model_dump_json(indent=2)
