# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""Tests for the Annex IV Technical Documentation Exporter."""

from __future__ import annotations

import json
from datetime import UTC, datetime

import pytest

from agentmesh.governance.annex_iv import (
    AnnexIVDocument,
    AnnexIVSection,
    TechnicalDocumentationExporter,
    to_json,
    to_markdown,
)
from agentmesh.governance.audit import AuditEntry
from agentmesh.governance.compliance import (
    ComplianceFramework,
    ComplianceReport,
    ComplianceViolation,
)
from agentmesh.governance.policy import Policy, PolicyRule

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_compliance_report(**overrides: object) -> ComplianceReport:
    """Create a minimal ComplianceReport for testing."""
    defaults: dict[str, object] = {
        "report_id": "report_test001",
        "framework": ComplianceFramework.EU_AI_ACT,
        "period_start": datetime(2026, 1, 1, tzinfo=UTC),
        "period_end": datetime(2026, 3, 31, tzinfo=UTC),
        "total_controls": 10,
        "controls_met": 8,
        "controls_failed": 2,
        "compliance_score": 80.0,
        "violations": [],
        "recommendations": ["Remediate EUAI-ART13"],
    }
    defaults.update(overrides)
    return ComplianceReport(**defaults)  # type: ignore[arg-type]


def _make_policy(**overrides: object) -> Policy:
    """Create a minimal Policy for testing."""
    defaults: dict[str, object] = {
        "name": "test-policy",
        "description": "A test governance policy",
        "scope": "global",
        "rules": [
            PolicyRule(
                name="block-export",
                description="Block data exports",
                condition="action.type == 'export'",
                action="deny",
            ),
        ],
        "default_action": "allow",
    }
    defaults.update(overrides)
    return Policy(**defaults)  # type: ignore[arg-type]


def _make_audit_entry(**overrides: object) -> AuditEntry:
    """Create a minimal AuditEntry for testing."""
    defaults: dict[str, object] = {
        "event_type": "tool_call",
        "agent_did": "did:example:agent-1",
        "action": "query_database",
        "outcome": "success",
    }
    defaults.update(overrides)
    return AuditEntry(**defaults)  # type: ignore[arg-type]


def _make_violation(**overrides: object) -> ComplianceViolation:
    """Create a minimal ComplianceViolation for testing."""
    defaults: dict[str, object] = {
        "violation_id": "viol_test001",
        "agent_did": "did:example:agent-1",
        "action_type": "data_access",
        "control_id": "EUAI-ART9",
        "framework": ComplianceFramework.EU_AI_ACT,
        "severity": "high",
        "description": "Risk management control not satisfied",
    }
    defaults.update(overrides)
    return ComplianceViolation(**defaults)  # type: ignore[arg-type]


# ---------------------------------------------------------------------------
# AnnexIVSection model
# ---------------------------------------------------------------------------


class TestAnnexIVSection:
    def test_default_values(self) -> None:
        section = AnnexIVSection(number="1", title="Test Section")
        assert section.content == ""
        assert section.placeholder == ""
        assert section.source_artifacts == []

    def test_populated_section(self) -> None:
        section = AnnexIVSection(
            number="3",
            title="Monitoring",
            content="Some content",
            placeholder="Fill this in",
            source_artifacts=["AuditLog", "ComplianceReport"],
        )
        assert section.number == "3"
        assert len(section.source_artifacts) == 2


# ---------------------------------------------------------------------------
# AnnexIVDocument model
# ---------------------------------------------------------------------------


class TestAnnexIVDocument:
    def test_default_title(self) -> None:
        doc = AnnexIVDocument()
        assert "Annex IV" in doc.title

    def test_generated_at_is_set(self) -> None:
        doc = AnnexIVDocument()
        assert doc.generated_at != ""

    def test_model_dump_json(self) -> None:
        doc = AnnexIVDocument(system_name="TestAI", provider="TestCorp")
        raw = doc.model_dump_json()
        parsed = json.loads(raw)
        assert parsed["system_name"] == "TestAI"


# ---------------------------------------------------------------------------
# TechnicalDocumentationExporter — empty export
# ---------------------------------------------------------------------------


class TestExporterEmpty:
    def test_export_with_no_data_produces_five_sections(self) -> None:
        exporter = TechnicalDocumentationExporter(
            system_name="EmptySystem",
            provider="TestCorp",
        )
        doc = exporter.export()
        assert len(doc.sections) == 5
        assert doc.system_name == "EmptySystem"

    def test_all_sections_have_placeholders(self) -> None:
        exporter = TechnicalDocumentationExporter(
            system_name="EmptySystem",
            provider="TestCorp",
        )
        doc = exporter.export()
        for section in doc.sections:
            assert section.placeholder != ""

    def test_metadata_counts_are_zero(self) -> None:
        exporter = TechnicalDocumentationExporter(
            system_name="EmptySystem",
            provider="TestCorp",
        )
        doc = exporter.export()
        assert doc.metadata["compliance_reports_count"] == 0
        assert doc.metadata["policies_count"] == 0
        assert doc.metadata["audit_entries_count"] == 0


# ---------------------------------------------------------------------------
# TechnicalDocumentationExporter — with data
# ---------------------------------------------------------------------------


class TestExporterWithData:
    @pytest.fixture()
    def exporter(self) -> TechnicalDocumentationExporter:
        exp = TechnicalDocumentationExporter(
            system_name="OptimusAI",
            provider="Energy Corp",
            system_description="AI trading assistant for energy markets",
            system_version="2.1.0",
        )
        exp.add_compliance_report(_make_compliance_report())
        exp.add_policies([_make_policy()])
        exp.add_audit_entries(
            [
                _make_audit_entry(),
                _make_audit_entry(
                    event_type="security_check",
                    outcome="denied",
                ),
            ]
        )
        exp.add_slo_data(
            {
                "ToolCallAccuracy": "98.5%",
                "HallucinationRate": "0.3%",
                "p99_latency_ms": 450,
            }
        )
        return exp

    def test_section_1_contains_system_info(self, exporter: TechnicalDocumentationExporter) -> None:
        doc = exporter.export()
        s1 = doc.sections[0]
        assert "OptimusAI" in s1.content
        assert "Energy Corp" in s1.content
        assert "2.1.0" in s1.content
        assert s1.placeholder == ""  # description was provided

    def test_section_1_includes_compliance_score(
        self, exporter: TechnicalDocumentationExporter
    ) -> None:
        doc = exporter.export()
        s1 = doc.sections[0]
        assert "80.0" in s1.content
        assert "ComplianceReport" in s1.source_artifacts

    def test_section_2_lists_policies(self, exporter: TechnicalDocumentationExporter) -> None:
        doc = exporter.export()
        s2 = doc.sections[1]
        assert "test-policy" in s2.content
        assert "Policy" in s2.source_artifacts

    def test_section_3_includes_audit_summary(
        self, exporter: TechnicalDocumentationExporter
    ) -> None:
        doc = exporter.export()
        s3 = doc.sections[2]
        assert "Total audit entries" in s3.content
        assert "2" in s3.content
        assert "AuditLog" in s3.source_artifacts

    def test_section_3_includes_slo_data(self, exporter: TechnicalDocumentationExporter) -> None:
        doc = exporter.export()
        s3 = doc.sections[2]
        assert "ToolCallAccuracy" in s3.content
        assert "SLO/SLI" in s3.source_artifacts

    def test_section_4_with_risk_violations(self) -> None:
        exporter = TechnicalDocumentationExporter(
            system_name="TestAI",
            provider="TestCorp",
        )
        report = _make_compliance_report(
            violations=[_make_violation()],
        )
        exporter.add_compliance_report(report)
        doc = exporter.export()
        s4 = doc.sections[3]
        assert "EUAI-ART9" in s4.content
        assert "ComplianceReport" in s4.source_artifacts

    def test_section_4_with_deny_policies(self, exporter: TechnicalDocumentationExporter) -> None:
        doc = exporter.export()
        s4 = doc.sections[3]
        assert "test-policy" in s4.content
        assert "Policy" in s4.source_artifacts

    def test_section_5_includes_accuracy_metrics(
        self, exporter: TechnicalDocumentationExporter
    ) -> None:
        doc = exporter.export()
        s5 = doc.sections[4]
        assert "ToolCallAccuracy" in s5.content
        assert "HallucinationRate" in s5.content

    def test_section_5_includes_security_events(
        self, exporter: TechnicalDocumentationExporter
    ) -> None:
        doc = exporter.export()
        s5 = doc.sections[4]
        assert "Security-related events" in s5.content

    def test_metadata_reflects_ingested_data(
        self, exporter: TechnicalDocumentationExporter
    ) -> None:
        doc = exporter.export()
        assert doc.metadata["compliance_reports_count"] == 1
        assert doc.metadata["policies_count"] == 1
        assert doc.metadata["audit_entries_count"] == 2


# ---------------------------------------------------------------------------
# Serialization
# ---------------------------------------------------------------------------


class TestSerialization:
    @pytest.fixture()
    def doc(self) -> AnnexIVDocument:
        exporter = TechnicalDocumentationExporter(
            system_name="SerializeTest",
            provider="TestCorp",
        )
        exporter.add_compliance_report(_make_compliance_report())
        return exporter.export()

    def test_to_markdown_contains_title(self, doc: AnnexIVDocument) -> None:
        md = to_markdown(doc)
        assert "# EU AI Act" in md
        assert "SerializeTest" in md

    def test_to_markdown_contains_all_sections(self, doc: AnnexIVDocument) -> None:
        md = to_markdown(doc)
        assert "## Section 1:" in md
        assert "## Section 2:" in md
        assert "## Section 3:" in md
        assert "## Section 4:" in md
        assert "## Section 5:" in md

    def test_to_markdown_includes_placeholders(self, doc: AnnexIVDocument) -> None:
        md = to_markdown(doc)
        assert "DEPLOYER ACTION REQUIRED" in md

    def test_to_json_is_valid(self, doc: AnnexIVDocument) -> None:
        raw = to_json(doc)
        parsed = json.loads(raw)
        assert parsed["system_name"] == "SerializeTest"
        assert len(parsed["sections"]) == 5

    def test_to_json_roundtrip(self, doc: AnnexIVDocument) -> None:
        raw = to_json(doc)
        restored = AnnexIVDocument.model_validate_json(raw)
        assert restored.system_name == doc.system_name
        assert len(restored.sections) == len(doc.sections)


# ---------------------------------------------------------------------------
# Edge cases
# ---------------------------------------------------------------------------


class TestEdgeCases:
    def test_section_3_truncates_violations_to_10(self) -> None:
        violations = [
            _make_violation(
                violation_id=f"viol_{i:03d}",
                description=f"Violation number {i}",
            )
            for i in range(15)
        ]
        exporter = TechnicalDocumentationExporter(
            system_name="TruncateTest",
            provider="TestCorp",
        )
        exporter.add_compliance_report(_make_compliance_report(violations=violations))
        doc = exporter.export()
        s3 = doc.sections[2]
        # Should show at most 10 violations in content
        assert "Violation number 9" in s3.content
        assert "Violation number 10" not in s3.content

    def test_non_eu_framework_report_excluded_from_section_1(
        self,
    ) -> None:
        exporter = TechnicalDocumentationExporter(
            system_name="MultiFramework",
            provider="TestCorp",
        )
        exporter.add_compliance_report(_make_compliance_report(framework=ComplianceFramework.SOC2))
        doc = exporter.export()
        s1 = doc.sections[0]
        # Section 1 only shows EU AI Act reports
        assert "Compliance score" not in s1.content
        assert "ComplianceReport" not in s1.source_artifacts

    def test_policy_with_no_deny_rules_excluded_from_section_4(
        self,
    ) -> None:
        exporter = TechnicalDocumentationExporter(
            system_name="AllowOnly",
            provider="TestCorp",
        )
        exporter.add_policies(
            [
                _make_policy(
                    rules=[
                        PolicyRule(
                            name="allow-all",
                            description="Allow everything",
                            condition="true",
                            action="allow",
                        ),
                    ],
                )
            ]
        )
        doc = exporter.export()
        s4 = doc.sections[3]
        assert "allow-all" not in s4.content

    def test_multiple_policies_in_section_2(self) -> None:
        exporter = TechnicalDocumentationExporter(
            system_name="MultiPolicy",
            provider="TestCorp",
        )
        exporter.add_policies(
            [
                _make_policy(name="policy-alpha"),
                _make_policy(name="policy-beta"),
            ]
        )
        doc = exporter.export()
        s2 = doc.sections[1]
        assert "policy-alpha" in s2.content
        assert "policy-beta" in s2.content

    def test_security_events_counted_in_section_5(self) -> None:
        exporter = TechnicalDocumentationExporter(
            system_name="SecurityTest",
            provider="TestCorp",
        )
        exporter.add_audit_entries(
            [
                _make_audit_entry(event_type="auth_check", outcome="denied"),
                _make_audit_entry(event_type="auth_check", outcome="denied"),
                _make_audit_entry(event_type="tool_call", outcome="success"),
            ]
        )
        doc = exporter.export()
        s5 = doc.sections[4]
        assert "**Security-related events:** 2" in s5.content
        assert "Access denied: 2" in s5.content
