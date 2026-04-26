# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""Tests for the Drift Detector integration module."""

from __future__ import annotations

import pytest

from agent_os.integrations.drift_detector import (
    DriftDetector,
    DriftFinding,
    DriftReport,
    DriftType,
)


@pytest.fixture
def detector():
    return DriftDetector()


# ── compare_configs ───────────────────────────────────────────


class TestCompareConfigs:
    def test_identical_configs_no_findings(self, detector):
        findings = detector.compare_configs(
            {"a": 1, "b": 2}, {"a": 1, "b": 2}
        )
        assert findings == []

    def test_different_value_detected(self, detector):
        findings = detector.compare_configs(
            {"max_tokens": 4096}, {"max_tokens": 2048}
        )
        assert len(findings) == 1
        assert findings[0].drift_type == DriftType.CONFIG_DRIFT
        assert findings[0].field == "max_tokens"
        assert findings[0].expected == 4096
        assert findings[0].actual == 2048

    def test_missing_key_in_target(self, detector):
        findings = detector.compare_configs(
            {"timeout": 300, "retries": 3},
            {"timeout": 300},
        )
        assert len(findings) == 1
        assert findings[0].field == "retries"
        assert findings[0].severity == "critical"

    def test_extra_key_in_target(self, detector):
        findings = detector.compare_configs(
            {"timeout": 300},
            {"timeout": 300, "retries": 5},
        )
        assert len(findings) == 1
        assert findings[0].field == "retries"

    def test_label_propagates(self, detector):
        findings = detector.compare_configs(
            {"x": 1}, {"x": 2}, label="staging-vs-prod"
        )
        assert "staging-vs-prod" in findings[0].source


# ── compare_policies ──────────────────────────────────────────


class TestComparePolicies:
    def test_identical_policies(self, detector):
        findings = detector.compare_policies(
            {"allow_file_write": True},
            {"allow_file_write": True},
        )
        assert findings == []

    def test_value_mismatch(self, detector):
        findings = detector.compare_policies(
            {"allow_file_write": True},
            {"allow_file_write": False},
        )
        assert len(findings) == 1
        assert findings[0].drift_type == DriftType.POLICY_DRIFT
        assert findings[0].severity == "warning"

    def test_missing_policy_critical(self, detector):
        findings = detector.compare_policies(
            {"allow_file_write": True, "max_calls": 10},
            {"allow_file_write": True},
        )
        assert len(findings) == 1
        assert findings[0].severity == "critical"
        assert "missing" in findings[0].message.lower()

    def test_extra_policy_critical(self, detector):
        findings = detector.compare_policies(
            {"allow_file_write": True},
            {"allow_file_write": True, "extra": "val"},
        )
        assert len(findings) == 1
        assert findings[0].severity == "critical"
        assert "only in target" in findings[0].message.lower()


# ── compare_trust_scores ──────────────────────────────────────


class TestCompareTrustScores:
    def test_within_tolerance(self, detector):
        findings = detector.compare_trust_scores(
            {"agent-a": 0.90}, {"agent-a": 0.92}, tolerance=0.1
        )
        assert findings == []

    def test_beyond_tolerance(self, detector):
        findings = detector.compare_trust_scores(
            {"agent-a": 0.90}, {"agent-a": 0.70}, tolerance=0.1
        )
        assert len(findings) == 1
        assert findings[0].drift_type == DriftType.TRUST_DRIFT
        assert findings[0].severity == "warning"

    def test_large_drift_critical(self, detector):
        findings = detector.compare_trust_scores(
            {"agent-a": 0.90}, {"agent-a": 0.40}, tolerance=0.1
        )
        assert len(findings) == 1
        assert findings[0].severity == "critical"

    def test_missing_score_source(self, detector):
        findings = detector.compare_trust_scores(
            {}, {"agent-a": 0.85}, tolerance=0.1
        )
        assert len(findings) == 1
        assert "missing" in findings[0].message.lower()
        assert "source" in findings[0].message.lower()

    def test_missing_score_target(self, detector):
        findings = detector.compare_trust_scores(
            {"agent-a": 0.85}, {}, tolerance=0.1
        )
        assert len(findings) == 1
        assert "missing" in findings[0].message.lower()
        assert "target" in findings[0].message.lower()


# ── detect_version_drift ──────────────────────────────────────


class TestDetectVersionDrift:
    def test_no_drift_all_same(self, detector):
        findings = detector.detect_version_drift({
            "agent-os": "2.1.0",
            "agent-runtime": "2.1.0",
        })
        assert findings == []

    def test_version_mismatch_detected(self, detector):
        findings = detector.detect_version_drift({
            "agent-os": "2.1.0",
            "agent-runtime": "2.1.0",
            "agent-mesh": "1.9.0",
        })
        assert len(findings) == 1
        assert findings[0].drift_type == DriftType.VERSION_DRIFT
        assert findings[0].actual == "1.9.0"

    def test_empty_components(self, detector):
        findings = detector.detect_version_drift({})
        assert findings == []


# ── scan ──────────────────────────────────────────────────────


class TestScan:
    def test_scan_two_sources(self, detector):
        report = detector.scan([
            {
                "label": "staging",
                "config": {"max_tokens": 4096, "timeout": 300},
                "policies": {"allow_write": True},
            },
            {
                "label": "production",
                "config": {"max_tokens": 2048, "timeout": 300},
                "policies": {"allow_write": True},
            },
        ])
        assert isinstance(report, DriftReport)
        assert report.sources_scanned == 2
        assert len(report.findings) >= 1
        assert report.scanned_at  # non-empty timestamp

    def test_scan_with_trust_scores(self, detector):
        report = detector.scan([
            {
                "label": "env-a",
                "trust_scores": {"agent-1": 0.9},
            },
            {
                "label": "env-b",
                "trust_scores": {"agent-1": 0.5},
            },
        ])
        assert len(report.findings) >= 1
        assert any(f.drift_type == DriftType.TRUST_DRIFT for f in report.findings)

    def test_scan_with_version_drift(self, detector):
        report = detector.scan([
            {
                "label": "env-a",
                "components": {"agent-os": "2.1.0", "agent-runtime": "2.0.0"},
            },
        ])
        assert len(report.findings) >= 1
        assert any(f.drift_type == DriftType.VERSION_DRIFT for f in report.findings)

    def test_scan_summary_format(self, detector):
        report = detector.scan([
            {"label": "a", "config": {"x": 1}},
            {"label": "b", "config": {"x": 2}},
        ])
        assert "finding" in report.summary.lower()

    def test_scan_empty_sources(self, detector):
        report = detector.scan([])
        assert report.findings == []
        assert report.sources_scanned == 0


# ── to_markdown ───────────────────────────────────────────────


class TestToMarkdown:
    def test_no_findings_shows_check(self, detector):
        report = DriftReport(
            findings=[], scanned_at="2025-01-01T00:00:00Z",
            sources_scanned=2, summary="0 finding(s)",
        )
        md = detector.to_markdown(report)
        assert "No drift detected" in md

    def test_findings_render_table(self, detector):
        report = DriftReport(
            findings=[
                DriftFinding(
                    drift_type=DriftType.CONFIG_DRIFT,
                    severity="warning",
                    source="src",
                    target="tgt",
                    field="max_tokens",
                    expected=4096,
                    actual=2048,
                    message="differs",
                )
            ],
            scanned_at="2025-01-01T00:00:00Z",
            sources_scanned=2,
            summary="1 finding(s)",
        )
        md = detector.to_markdown(report)
        assert "| warning" in md
        assert "config_drift" in md
        assert "max_tokens" in md

    def test_markdown_header(self, detector):
        report = DriftReport(scanned_at="now", sources_scanned=1, summary="ok")
        md = detector.to_markdown(report)
        assert md.startswith("# Drift Detection Report")
