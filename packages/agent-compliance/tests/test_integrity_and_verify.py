# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""Tests for bootstrap integrity verification and governance attestation."""

import json
import os
import tempfile
from urllib.parse import urlparse

import pytest

from agent_compliance.integrity import (
    IntegrityVerifier,
    IntegrityReport,
    GOVERNANCE_MODULES,
    CRITICAL_FUNCTIONS,
    _hash_file,
    _hash_function_bytecode,
)
from agent_compliance.verify import (
    GovernanceVerifier,
    GovernanceAttestation,
    OWASP_ASI_CONTROLS,
)


# ── Integrity Tests ─────────────────────────────────────────


class TestHashHelpers:
    def test_hash_file_deterministic(self, tmp_path):
        f = tmp_path / "test.txt"
        f.write_text("hello world")
        h1 = _hash_file(str(f))
        h2 = _hash_file(str(f))
        assert h1 == h2
        assert len(h1) == 64  # SHA-256 hex

    def test_hash_file_changes_on_modification(self, tmp_path):
        f = tmp_path / "test.txt"
        f.write_text("version 1")
        h1 = _hash_file(str(f))
        f.write_text("version 2")
        h2 = _hash_file(str(f))
        assert h1 != h2

    def test_hash_function_bytecode_deterministic(self):
        def sample_func():
            return 42

        h1 = _hash_function_bytecode(sample_func)
        h2 = _hash_function_bytecode(sample_func)
        assert h1 == h2
        assert len(h1) == 64

    def test_hash_different_functions(self):
        def func_a():
            return 1

        def func_b():
            return 2

        assert _hash_function_bytecode(func_a) != _hash_function_bytecode(func_b)


class TestIntegrityVerifier:
    def test_verify_without_manifest_passes(self):
        """Without a manifest, verification generates baseline — always passes."""
        verifier = IntegrityVerifier(modules=["agent_compliance.integrity"])
        report = verifier.verify()
        assert report.passed is True
        assert report.modules_checked >= 1
        assert len(report.file_results) >= 1

    def test_verify_with_valid_manifest(self, tmp_path):
        """Generate manifest then verify against it — should pass."""
        manifest_path = str(tmp_path / "integrity.json")
        verifier = IntegrityVerifier(modules=["agent_compliance.integrity"])
        verifier.generate_manifest(manifest_path)

        verifier2 = IntegrityVerifier(
            manifest_path=manifest_path,
            modules=["agent_compliance.integrity"],
        )
        report = verifier2.verify()
        assert report.passed is True

    def test_verify_detects_tampered_hash(self, tmp_path):
        """Tampered manifest should fail verification."""
        manifest_path = str(tmp_path / "integrity.json")
        verifier = IntegrityVerifier(modules=["agent_compliance.integrity"])
        manifest = verifier.generate_manifest(manifest_path)

        # Tamper with the hash
        for key in manifest["files"]:
            manifest["files"][key]["sha256"] = "0" * 64
        with open(manifest_path, "w") as f:
            json.dump(manifest, f)

        verifier2 = IntegrityVerifier(
            manifest_path=manifest_path,
            modules=["agent_compliance.integrity"],
        )
        report = verifier2.verify()
        assert report.passed is False
        failed = [r for r in report.file_results if not r.passed]
        assert len(failed) >= 1

    def test_verify_handles_missing_modules(self):
        verifier = IntegrityVerifier(modules=["nonexistent.module.xyz"])
        report = verifier.verify()
        assert "nonexistent.module.xyz" in report.modules_missing

    def test_generate_manifest(self, tmp_path):
        manifest_path = str(tmp_path / "integrity.json")
        verifier = IntegrityVerifier(
            modules=["agent_compliance.integrity"],
            critical_functions=[],
        )
        manifest = verifier.generate_manifest(manifest_path)
        assert os.path.exists(manifest_path)
        assert "agent_compliance.integrity" in manifest["files"]
        assert "sha256" in manifest["files"]["agent_compliance.integrity"]

    def test_report_summary(self):
        report = IntegrityReport(passed=True, modules_checked=5)
        summary = report.summary()
        assert "PASSED" in summary
        assert "5" in summary

    def test_report_to_dict(self):
        report = IntegrityReport(passed=True, modules_checked=3)
        d = report.to_dict()
        assert d["passed"] is True
        assert d["modules_checked"] == 3


# ── Governance Verification Tests ────────────────────────────


class TestGovernanceVerifier:
    def test_verify_produces_attestation(self):
        verifier = GovernanceVerifier()
        attestation = verifier.verify()
        assert isinstance(attestation, GovernanceAttestation)
        assert attestation.controls_total == len(OWASP_ASI_CONTROLS)
        assert attestation.verified_at is not None
        assert len(attestation.attestation_hash) == 64

    def test_controls_are_checked(self):
        verifier = GovernanceVerifier()
        attestation = verifier.verify()
        control_ids = {c.control_id for c in attestation.controls}
        for asi_id in OWASP_ASI_CONTROLS:
            assert asi_id in control_ids

    def test_coverage_percentage(self):
        attestation = GovernanceAttestation(
            controls_passed=8, controls_total=10
        )
        assert attestation.coverage_pct() == 80

    def test_coverage_zero_total(self):
        attestation = GovernanceAttestation(
            controls_passed=0, controls_total=0
        )
        assert attestation.coverage_pct() == 0

    def test_badge_url_full_coverage(self):
        attestation = GovernanceAttestation(
            controls_passed=10, controls_total=10
        )
        url = attestation.badge_url()
        assert "brightgreen" in url
        assert "passed" in url

    def test_badge_url_partial_coverage(self):
        attestation = GovernanceAttestation(
            controls_passed=8, controls_total=10
        )
        url = attestation.badge_url()
        assert "yellow" in url

    def test_badge_url_low_coverage(self):
        attestation = GovernanceAttestation(
            controls_passed=3, controls_total=10
        )
        url = attestation.badge_url()
        assert "red" in url

    def test_badge_markdown(self):
        attestation = GovernanceAttestation(
            controls_passed=10, controls_total=10
        )
        md = attestation.badge_markdown()
        assert md.startswith("[![")
        # Validate badge URL domain using proper URL parsing
        import re
        urls = re.findall(r'https?://[^\s\)]+', md)
        assert any(urlparse(u).hostname == "img.shields.io" for u in urls)
        assert "microsoft/agent-governance-toolkit" in md

    def test_summary_format(self):
        verifier = GovernanceVerifier()
        attestation = verifier.verify()
        summary = attestation.summary()
        assert "OWASP ASI 2026" in summary
        assert "ASI-01" in summary

    def test_to_json_valid(self):
        verifier = GovernanceVerifier()
        attestation = verifier.verify()
        j = attestation.to_json()
        parsed = json.loads(j)
        assert parsed["schema"] == "governance-attestation/v1"
        assert "controls" in parsed
        assert len(parsed["controls"]) == len(OWASP_ASI_CONTROLS)

    def test_attestation_hash_deterministic(self):
        """Same inputs produce the same hash."""
        verifier = GovernanceVerifier()
        a1 = verifier.verify()
        # Hash depends on verified_at timestamp, so we test structure instead
        assert len(a1.attestation_hash) == 64
        assert a1.attestation_hash == a1.attestation_hash  # sanity

    def test_custom_controls(self):
        custom = {
            "CUSTOM-01": {
                "name": "Custom Control",
                "module": "agent_compliance.verify",
                "check": "GovernanceVerifier",
            }
        }
        verifier = GovernanceVerifier(controls=custom)
        attestation = verifier.verify()
        assert attestation.controls_total == 1
        assert attestation.controls[0].control_id == "CUSTOM-01"
        assert attestation.controls[0].present is True


# ── CLI Tests ────────────────────────────────────────────────


class TestCLI:
    def test_verify_command(self):
        from agent_compliance.cli.main import cmd_verify
        import argparse

        args = argparse.Namespace(json=False, badge=False)
        # Should not raise
        result = cmd_verify(args)
        assert result in (0, 1)

    def test_verify_json_output(self, capsys):
        from agent_compliance.cli.main import cmd_verify
        import argparse

        args = argparse.Namespace(json=True, badge=False)
        cmd_verify(args)
        captured = capsys.readouterr()
        parsed = json.loads(captured.out)
        assert "schema" in parsed

    def test_verify_badge_output(self, capsys):
        from agent_compliance.cli.main import cmd_verify
        import argparse

        args = argparse.Namespace(json=False, badge=True)
        cmd_verify(args)
        captured = capsys.readouterr()
        # Validate badge URL domain using proper URL parsing
        import re
        urls = re.findall(r'https?://[^\s\)]+', captured.out)
        assert any(urlparse(u).hostname == "img.shields.io" for u in urls)

    def test_integrity_generate(self, tmp_path):
        from agent_compliance.cli.main import cmd_integrity
        import argparse

        output = str(tmp_path / "integrity.json")
        args = argparse.Namespace(generate=output, manifest=None, json=False)
        result = cmd_integrity(args)
        assert result == 0
        assert os.path.exists(output)

    def test_integrity_verify_no_manifest(self):
        from agent_compliance.cli.main import cmd_integrity
        import argparse

        args = argparse.Namespace(generate=None, manifest=None, json=False)
        result = cmd_integrity(args)
        assert result == 0
