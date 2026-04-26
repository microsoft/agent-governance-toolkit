# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""
EU AI Act Annex IV — Automated Evidence Pipeline
=================================================

CLI-driven pipeline that collects governance artifacts from a running
AGT deployment and assembles them into an Annex IV technical
documentation dossier.

Scans for:
- Policy YAML files in ``policies/`` directories
- Audit log entries from the audit backend
- Compliance reports from existing compliance checks
- SLO/SLI data from the SRE module

Outputs a Markdown document suitable for conformity assessment
review, plus a machine-readable JSON manifest of all evidence sources.

Usage::

    from agentmesh.governance.evidence_pipeline import EvidencePipeline

    pipeline = EvidencePipeline(
        system_name="Contoso Trading Agent",
        provider="Contoso Financial Inc.",
        policies_dir=Path("policies/"),
        audit_log_path=Path("logs/audit.jsonl"),
    )
    report = pipeline.run()
    report.save_markdown(Path("annex-iv-report.md"))
    report.save_manifest(Path("annex-iv-manifest.json"))

References:
    - EU AI Act (Regulation 2024/1689), Article 11 & Annex IV
    - Deadline: August 2, 2026 (first conformity assessment cycle)
"""

from __future__ import annotations

import json
import logging
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import yaml

from .annex_iv import AnnexIVDocument, TechnicalDocumentationExporter
from .audit import AuditEntry
from .compliance import ComplianceFramework, ComplianceReport
from .policy import Policy

logger = logging.getLogger(__name__)


@dataclass
class EvidenceSource:
    """Metadata about a collected evidence source."""

    source_type: str
    path: str
    collected_at: str = field(
        default_factory=lambda: datetime.now(UTC).isoformat()
    )
    record_count: int = 0
    sha256: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "source_type": self.source_type,
            "path": self.path,
            "collected_at": self.collected_at,
            "record_count": self.record_count,
        }


@dataclass
class EvidenceReport:
    """Complete evidence collection report."""

    document: AnnexIVDocument
    sources: list[EvidenceSource] = field(default_factory=list)
    collection_timestamp: str = field(
        default_factory=lambda: datetime.now(UTC).isoformat()
    )
    warnings: list[str] = field(default_factory=list)

    def save_markdown(self, path: Path) -> None:
        """Write Annex IV document as Markdown."""
        lines = [
            f"# {self.document.title}",
            "",
            f"**Generated:** {self.document.generated_at}",
            f"**System:** {self.document.system_name}",
            f"**Provider:** {self.document.provider}",
            "",
            "---",
            "",
        ]

        for section in self.document.sections:
            lines.append(f"## {section.number}. {section.title}")
            lines.append("")
            if section.content:
                lines.append(section.content)
                lines.append("")
            if section.placeholder:
                lines.append(f"> ⚠️ **DEPLOYER ACTION REQUIRED:** {section.placeholder}")
                lines.append("")
            if section.source_artifacts:
                lines.append(f"*Sources: {', '.join(section.source_artifacts)}*")
                lines.append("")

        if self.warnings:
            lines.append("---")
            lines.append("")
            lines.append("## Evidence Gaps")
            lines.append("")
            for w in self.warnings:
                lines.append(f"- ⚠️ {w}")
            lines.append("")

        lines.append("---")
        lines.append("")
        lines.append(f"*Collected {len(self.sources)} evidence sources at {self.collection_timestamp}*")

        path.write_text("\n".join(lines), encoding="utf-8")
        logger.info("Saved Annex IV Markdown to %s", path)

    def save_manifest(self, path: Path) -> None:
        """Write machine-readable evidence manifest as JSON."""
        manifest = {
            "title": self.document.title,
            "system_name": self.document.system_name,
            "provider": self.document.provider,
            "generated_at": self.document.generated_at,
            "collection_timestamp": self.collection_timestamp,
            "sources": [s.to_dict() for s in self.sources],
            "warnings": self.warnings,
            "section_count": len(self.document.sections),
            "metadata": self.document.metadata,
        }
        path.write_text(
            json.dumps(manifest, indent=2, sort_keys=False),
            encoding="utf-8",
        )
        logger.info("Saved evidence manifest to %s", path)


class EvidencePipeline:
    """Automated evidence collection pipeline for EU AI Act Annex IV.

    Scans configured paths for governance artifacts and assembles them
    into a conformity assessment dossier.

    Args:
        system_name: Name of the AI system.
        provider: Organisation name.
        system_description: Description of the system's intended purpose.
        system_version: Version string.
        policies_dir: Directory containing policy YAML files.
        audit_log_path: Path to JSONL audit log file.
        compliance_reports_dir: Directory containing compliance report JSON files.
        slo_data_path: Path to SLO/SLI metrics JSON file.
    """

    def __init__(
        self,
        system_name: str,
        provider: str,
        system_description: str = "",
        system_version: str = "",
        policies_dir: Path | None = None,
        audit_log_path: Path | None = None,
        compliance_reports_dir: Path | None = None,
        slo_data_path: Path | None = None,
    ) -> None:
        self._system_name = system_name
        self._provider = provider
        self._system_description = system_description
        self._system_version = system_version
        self._policies_dir = policies_dir
        self._audit_log_path = audit_log_path
        self._compliance_reports_dir = compliance_reports_dir
        self._slo_data_path = slo_data_path

    def run(self) -> EvidenceReport:
        """Execute the evidence collection pipeline.

        Returns:
            An ``EvidenceReport`` containing the Annex IV document,
            evidence sources, and any gaps/warnings.
        """
        exporter = TechnicalDocumentationExporter(
            system_name=self._system_name,
            provider=self._provider,
            system_description=self._system_description,
            system_version=self._system_version,
        )

        sources: list[EvidenceSource] = []
        warnings: list[str] = []

        # Collect policies
        policies = self._collect_policies(sources, warnings)
        if policies:
            exporter.add_policies(policies)

        # Collect audit entries
        audit_entries = self._collect_audit_entries(sources, warnings)
        if audit_entries:
            exporter.add_audit_entries(audit_entries)

        # Collect compliance reports
        reports = self._collect_compliance_reports(sources, warnings)
        for report in reports:
            exporter.add_compliance_report(report)

        # Collect SLO data
        slo_data = self._collect_slo_data(sources, warnings)
        if slo_data:
            exporter.add_slo_data(slo_data)

        # Check for required evidence gaps
        if not policies:
            warnings.append(
                "No policy files found. Annex IV §2 (risk management) requires documented governance policies."
            )
        if not audit_entries:
            warnings.append(
                "No audit log entries found. Annex IV §4 (logging) requires audit trail evidence."
            )
        eu_reports = [
            r for r in reports
            if r.framework == ComplianceFramework.EU_AI_ACT
        ]
        if not eu_reports:
            warnings.append(
                "No EU AI Act compliance report found. Run `agt audit --framework eu-ai-act` first."
            )

        document = exporter.export()

        return EvidenceReport(
            document=document,
            sources=sources,
            warnings=warnings,
        )

    def _collect_policies(
        self,
        sources: list[EvidenceSource],
        warnings: list[str],
    ) -> list[Policy]:
        """Scan policies directory for YAML policy files."""
        if not self._policies_dir or not self._policies_dir.exists():
            return []

        policies: list[Policy] = []
        for path in sorted(self._policies_dir.glob("**/*.yaml")):
            try:
                raw_text = path.read_text(encoding="utf-8")
                policy = Policy.from_yaml(raw_text)
                policies.append(policy)
                sources.append(
                    EvidenceSource(
                        source_type="policy",
                        path=str(path),
                        record_count=len(policy.rules),
                    )
                )
            except Exception as exc:
                logger.warning("Failed to load policy %s: %s", path, exc)
        return policies

    def _collect_audit_entries(
        self,
        sources: list[EvidenceSource],
        warnings: list[str],
    ) -> list[AuditEntry]:
        """Read audit entries from JSONL log file."""
        if not self._audit_log_path or not self._audit_log_path.exists():
            return []

        entries: list[AuditEntry] = []
        try:
            count = 0
            for line in self._audit_log_path.read_text(encoding="utf-8").splitlines():
                line = line.strip()
                if not line:
                    continue
                try:
                    data = json.loads(line)
                    entry = AuditEntry(**data)
                    entries.append(entry)
                    count += 1
                except Exception:
                    continue

            sources.append(
                EvidenceSource(
                    source_type="audit_log",
                    path=str(self._audit_log_path),
                    record_count=count,
                )
            )
        except Exception as exc:
            logger.warning("Failed to read audit log: %s", exc)
        return entries

    def _collect_compliance_reports(
        self,
        sources: list[EvidenceSource],
        warnings: list[str],
    ) -> list[ComplianceReport]:
        """Load compliance reports from JSON files."""
        if not self._compliance_reports_dir or not self._compliance_reports_dir.exists():
            return []

        reports: list[ComplianceReport] = []
        for path in sorted(self._compliance_reports_dir.glob("*.json")):
            try:
                data = json.loads(path.read_text(encoding="utf-8"))
                report = ComplianceReport(**data)
                reports.append(report)
                sources.append(
                    EvidenceSource(
                        source_type="compliance_report",
                        path=str(path),
                        record_count=1,
                    )
                )
            except Exception as exc:
                logger.warning("Failed to load compliance report %s: %s", path, exc)
        return reports

    def _collect_slo_data(
        self,
        sources: list[EvidenceSource],
        warnings: list[str],
    ) -> dict[str, Any]:
        """Load SLO/SLI metrics from JSON file."""
        if not self._slo_data_path or not self._slo_data_path.exists():
            return {}

        try:
            data = json.loads(self._slo_data_path.read_text(encoding="utf-8"))
            sources.append(
                EvidenceSource(
                    source_type="slo_metrics",
                    path=str(self._slo_data_path),
                    record_count=len(data),
                )
            )
            return data
        except Exception as exc:
            logger.warning("Failed to load SLO data: %s", exc)
            return {}
