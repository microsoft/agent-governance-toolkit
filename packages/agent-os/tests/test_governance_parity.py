# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""Tests for CLI vs IDE governance parity detection."""

import pytest
from agent_os.governance_parity import (
    GovernanceParityChecker,
    ParityGap,
    ParityReport,
    STANDARD_CAPABILITIES,
)


class TestGovernanceParityChecker:
    def test_full_parity(self):
        checker = GovernanceParityChecker()
        checker.register_surface("cli", capabilities=STANDARD_CAPABILITIES)
        checker.register_surface("vscode", capabilities=STANDARD_CAPABILITIES)
        report = checker.check_parity()
        assert report.parity_score == 1.0
        assert len(report.gaps) == 0
        assert not report.has_critical_gaps

    def test_gap_detection(self):
        checker = GovernanceParityChecker()
        checker.register_surface("cli", capabilities=STANDARD_CAPABILITIES)
        checker.register_surface("vscode", capabilities=["policy_enforcement", "audit_logging"])
        report = checker.check_parity()
        assert report.parity_score < 1.0
        assert len(report.gaps) > 0
        vscode_missing = report.missing_by_surface.get("vscode", [])
        assert "kill_switch" in vscode_missing
        assert "trust_verification" in vscode_missing

    def test_critical_gaps(self):
        checker = GovernanceParityChecker()
        checker.register_surface("notebook", capabilities=["otel_observability"])
        report = checker.check_parity()
        assert report.has_critical_gaps
        critical = [g for g in report.gaps if g.severity == "critical"]
        assert len(critical) >= 2  # policy + audit at minimum

    def test_no_surfaces(self):
        checker = GovernanceParityChecker()
        report = checker.check_parity()
        assert report.parity_score == 1.0
        assert report.gaps == []

    def test_single_surface_gaps(self):
        checker = GovernanceParityChecker()
        checker.register_surface("cli", capabilities=["policy_enforcement"])
        report = checker.check_parity()
        assert len(report.gaps) == len(STANDARD_CAPABILITIES) - 1

    def test_universal_capabilities(self):
        checker = GovernanceParityChecker()
        checker.register_surface("cli", capabilities=["policy_enforcement", "audit_logging", "kill_switch"])
        checker.register_surface("ide", capabilities=["policy_enforcement", "audit_logging"])
        report = checker.check_parity()
        assert "policy_enforcement" in report.universal_capabilities
        assert "audit_logging" in report.universal_capabilities
        assert "kill_switch" not in report.universal_capabilities

    def test_custom_required_capabilities(self):
        checker = GovernanceParityChecker(required_capabilities=["policy_enforcement", "audit_logging"])
        checker.register_surface("cli", capabilities=["policy_enforcement", "audit_logging"])
        checker.register_surface("ide", capabilities=["policy_enforcement"])
        report = checker.check_parity()
        assert len(report.gaps) == 1
        assert report.gaps[0].surface == "ide"
        assert report.gaps[0].capability == "audit_logging"

    def test_gap_has_recommendation(self):
        checker = GovernanceParityChecker()
        checker.register_surface("test", capabilities=[])
        report = checker.check_parity()
        for gap in report.gaps:
            assert len(gap.recommendation) > 0
            assert len(gap.severity) > 0

    def test_print_report(self):
        checker = GovernanceParityChecker(required_capabilities=["policy_enforcement", "audit_logging"])
        checker.register_surface("cli", capabilities=["policy_enforcement", "audit_logging"])
        checker.register_surface("ide", capabilities=["policy_enforcement"])
        text = checker.print_report()
        assert "Parity Score" in text
        assert "ide" in text
        assert "audit_logging" in text

    def test_three_surfaces(self):
        checker = GovernanceParityChecker(required_capabilities=["policy_enforcement", "audit_logging", "kill_switch"])
        checker.register_surface("cli", capabilities=["policy_enforcement", "audit_logging", "kill_switch"])
        checker.register_surface("ide", capabilities=["policy_enforcement", "audit_logging"])
        checker.register_surface("notebook", capabilities=["policy_enforcement"])
        report = checker.check_parity()
        assert len(report.surfaces) == 3
        assert "notebook" in report.missing_by_surface
        assert "kill_switch" in report.missing_by_surface["notebook"]
        assert "audit_logging" in report.missing_by_surface["notebook"]
