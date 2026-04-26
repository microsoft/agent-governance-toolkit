# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

"""Tests for bootstrap integrity verification and governance attestation."""

from __future__ import annotations

import argparse
import json
import os
import re
from pathlib import Path
from urllib.parse import urlparse

from agent_compliance.integrity import (
    CRITICAL_FUNCTIONS,
    GOVERNANCE_MODULES,
    IntegrityReport,
    IntegrityVerifier,
    _hash_file,
    _hash_function_bytecode,
)
from agent_compliance.verify import (
    OWASP_ASI_CONTROLS,
    GovernanceAttestation,
    GovernanceVerifier,
)


_CUSTOM_VERIFY_CONTROLS = {
    "CUSTOM-01": {
        "name": "Custom Control",
        "module": "agent_compliance.verify",
        "check": "GovernanceVerifier",
    }
}


def _write_runtime_evidence(
    tmp_path: Path,
    *,
    policy_body: str | None = None,
    include_policy: bool = True,
    include_tools: bool = True,
    audit_enabled: bool = True,
    identity_enabled: bool = True,
    include_packages: bool = True,
) -> Path:
    policy_rel_path = "policies/default.yaml"

    if policy_body is None:
        policy_body = """
defaults:
  action: deny
rules:
  - name: allow-crm
    action: allow
    tool: crm_lookup
""".strip()

    if include_policy:
        policy_path = tmp_path / policy_rel_path
        policy_path.parent.mkdir(parents=True, exist_ok=True)
        policy_path.write_text(policy_body, encoding="utf-8")
        policy_files_loaded = [policy_rel_path]
    else:
        policy_files_loaded = []

    evidence = {
        "schema": "agt-runtime-evidence/v1",
        "generated_at": "2026-04-13T12:00:00Z",
        "toolkit_version": "3.0.0",
        "deployment": {
            "policy_files_loaded": policy_files_loaded,
            "registered_tools": ["crm_lookup", "slack_send"] if include_tools else [],
            "audit_sink": {
                "enabled": audit_enabled,
                "type": "file",
                "target": "audit.jsonl",
            },
            "identity": {
                "enabled": identity_enabled,
                "provider": "did:web",
            },
            "packages": (
                [{"package": "agent_governance_toolkit", "version": "3.0.0"}]
                if include_packages
                else []
            ),
        },
    }

    evidence_path = tmp_path / "agt-evidence.json"
    evidence_path.write_text(json.dumps(evidence, indent=2), encoding="utf-8")
    return evidence_path


# ── Integrity Tests ─────────────────────────────────────────


class TestHashHelpers:
    def test_hash_file_deterministic(self, tmp_path: Path):
        f = tmp_path / "test.txt"
        f.write_text("hello world", encoding="utf-8")

        h1 = _hash_file(str(f))
        h2 = _hash_file(str(f))

        assert h1 == h2
        assert len(h1) == 64

    def test_hash_file_changes_on_modification(self, tmp_path: Path):
        f = tmp_path / "test.txt"
        f.write_text("version 1", encoding="utf-8")
        h1 = _hash_file(str(f))

        f.write_text("version 2", encoding="utf-8")
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
        verifier = IntegrityVerifier(modules=["agent_compliance.integrity"])

        report = verifier.verify()

        assert report.passed is True
        assert report.modules_checked >= 1
        assert len(report.file_results) >= 1

    def test_verify_with_valid_manifest(self, tmp_path: Path):
        manifest_path = str(tmp_path / "integrity.json")
        verifier = IntegrityVerifier(modules=["agent_compliance.integrity"])
        verifier.generate_manifest(manifest_path)

        verifier2 = IntegrityVerifier(
            manifest_path=manifest_path,
            modules=["agent_compliance.integrity"],
        )
        report = verifier2.verify()

        assert report.passed is True

    def test_verify_detects_tampered_hash(self, tmp_path: Path):
        manifest_path = str(tmp_path / "integrity.json")
        verifier = IntegrityVerifier(modules=["agent_compliance.integrity"])
        manifest = verifier.generate_manifest(manifest_path)

        for key in manifest["files"]:
            manifest["files"][key]["sha256"] = "0" * 64

        with open(manifest_path, "w", encoding="utf-8") as f:
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

    def test_generate_manifest(self, tmp_path: Path):
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

        data = report.to_dict()

        assert data["passed"] is True
        assert data["modules_checked"] == 3


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
        attestation = GovernanceAttestation(controls_passed=8, controls_total=10)

        assert attestation.coverage_pct() == 80

    def test_coverage_zero_total(self):
        attestation = GovernanceAttestation(controls_passed=0, controls_total=0)

        assert attestation.coverage_pct() == 0

    def test_badge_url_full_coverage(self):
        attestation = GovernanceAttestation(controls_passed=10, controls_total=10)

        url = attestation.badge_url()

        assert "brightgreen" in url
        assert "passed" in url

    def test_badge_url_partial_coverage(self):
        attestation = GovernanceAttestation(controls_passed=8, controls_total=10)

        url = attestation.badge_url()

        assert "yellow" in url

    def test_badge_url_low_coverage(self):
        attestation = GovernanceAttestation(controls_passed=3, controls_total=10)

        url = attestation.badge_url()

        assert "red" in url

    def test_badge_markdown(self):
        attestation = GovernanceAttestation(controls_passed=10, controls_total=10)

        md = attestation.badge_markdown()

        assert md.startswith("[![")
        urls = re.findall(r"https?://[^\s\)]+", md)
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
        parsed = json.loads(attestation.to_json())

        assert parsed["schema"] == "governance-attestation/v1"
        assert "controls" in parsed
        assert len(parsed["controls"]) == len(OWASP_ASI_CONTROLS)

    def test_attestation_hash_deterministic(self):
        verifier = GovernanceVerifier()

        attestation = verifier.verify()

        assert len(attestation.attestation_hash) == 64
        assert attestation.attestation_hash == attestation.attestation_hash

    def test_custom_controls(self):
        verifier = GovernanceVerifier(controls=_CUSTOM_VERIFY_CONTROLS)

        attestation = verifier.verify()

        assert attestation.controls_total == 1
        assert attestation.controls[0].control_id == "CUSTOM-01"
        assert attestation.controls[0].present is True

    def test_verify_evidence_strict_passes_with_runtime_manifest(self, tmp_path: Path):
        evidence_path = _write_runtime_evidence(tmp_path)
        verifier = GovernanceVerifier(controls=_CUSTOM_VERIFY_CONTROLS)

        attestation = verifier.verify_evidence(evidence_path, strict=True)

        assert attestation.passed is True
        assert attestation.mode == "evidence"
        assert attestation.strict is True
        assert len(attestation.evidence_checks) == 6
        assert attestation.failures == []

    def test_verify_evidence_strict_fails_without_policy_files(self, tmp_path: Path):
        evidence_path = _write_runtime_evidence(tmp_path, include_policy=False)
        verifier = GovernanceVerifier(controls=_CUSTOM_VERIFY_CONTROLS)

        attestation = verifier.verify_evidence(evidence_path, strict=True)

        assert attestation.passed is False
        assert any(
            check.check_id == "policy-files" and check.status == "fail"
            for check in attestation.evidence_checks
        )

    def test_verify_evidence_strict_fails_without_deny_semantics(self, tmp_path: Path):
        evidence_path = _write_runtime_evidence(
            tmp_path,
            policy_body="""
rules:
  - name: allow-crm
    action: allow
    tool: crm_lookup
""".strip(),
        )
        verifier = GovernanceVerifier(controls=_CUSTOM_VERIFY_CONTROLS)

        attestation = verifier.verify_evidence(evidence_path, strict=True)

        assert attestation.passed is False
        assert any(
            check.check_id == "deny-semantics" and check.status == "fail"
            for check in attestation.evidence_checks
        )

    def test_verify_evidence_strict_fails_without_audit_sink(self, tmp_path: Path):
        evidence_path = _write_runtime_evidence(tmp_path, audit_enabled=False)
        verifier = GovernanceVerifier(controls=_CUSTOM_VERIFY_CONTROLS)

        attestation = verifier.verify_evidence(evidence_path, strict=True)

        assert attestation.passed is False
        assert any(
            check.check_id == "audit-sink" and check.status == "fail"
            for check in attestation.evidence_checks
        )

    def test_verify_evidence_strict_fails_without_identity(self, tmp_path: Path):
        evidence_path = _write_runtime_evidence(tmp_path, identity_enabled=False)
        verifier = GovernanceVerifier(controls=_CUSTOM_VERIFY_CONTROLS)

        attestation = verifier.verify_evidence(evidence_path, strict=True)

        assert attestation.passed is False
        assert any(
            check.check_id == "identity" and check.status == "fail"
            for check in attestation.evidence_checks
        )

    def test_verify_evidence_to_json_contains_runtime_fields(self, tmp_path: Path):
        evidence_path = _write_runtime_evidence(tmp_path)
        verifier = GovernanceVerifier(controls=_CUSTOM_VERIFY_CONTROLS)

        attestation = verifier.verify_evidence(evidence_path)
        payload = json.loads(attestation.to_json())

        assert payload["schema"] == "governance-attestation/v1"
        assert payload["mode"] == "evidence"
        assert payload["strict"] is False
        assert payload["evidence_source"].endswith("agt-evidence.json")
        assert len(payload["evidence_checks"]) == 6
        assert payload["failures"] == []

    def test_verify_evidence_rejects_policy_path_escape(self, tmp_path: Path):
        outside_policy = tmp_path.parent / "outside-policy.yaml"
        outside_policy.write_text("defaults:\n  action: deny\n", encoding="utf-8")

        evidence_path = tmp_path / "agt-evidence.json"
        evidence_path.write_text(
            json.dumps(
                {
                    "schema": "agt-runtime-evidence/v1",
                    "generated_at": "2026-04-13T12:00:00Z",
                    "toolkit_version": "3.0.0",
                    "deployment": {
                        "policy_files_loaded": [str(Path("..") / outside_policy.name)],
                        "registered_tools": ["crm_lookup"],
                        "audit_sink": {
                            "enabled": True,
                            "type": "file",
                            "target": "audit.jsonl",
                        },
                        "identity": {
                            "enabled": True,
                            "provider": "did:web",
                        },
                        "packages": [
                            {"package": "agent_governance_toolkit", "version": "3.0.0"}
                        ],
                    },
                }
            ),
            encoding="utf-8",
        )

        verifier = GovernanceVerifier(controls=_CUSTOM_VERIFY_CONTROLS)

        try:
            verifier.verify_evidence(evidence_path, strict=True)
            assert False, "Expected ValueError"
        except ValueError as exc:
            assert "escapes evidence directory" in str(exc)

    def test_verify_evidence_rejects_oversized_policy_file(self, tmp_path: Path):
        policy_rel_path = "policies/default.yaml"
        policy_path = tmp_path / policy_rel_path
        policy_path.parent.mkdir(parents=True, exist_ok=True)
        policy_path.write_text("a" * (10 * 1024 * 1024 + 1), encoding="utf-8")

        evidence_path = tmp_path / "agt-evidence.json"
        evidence_path.write_text(
            json.dumps(
                {
                    "schema": "agt-runtime-evidence/v1",
                    "generated_at": "2026-04-13T12:00:00Z",
                    "toolkit_version": "3.0.0",
                    "deployment": {
                        "policy_files_loaded": [policy_rel_path],
                        "registered_tools": ["crm_lookup"],
                        "audit_sink": {
                            "enabled": True,
                            "type": "file",
                            "target": "audit.jsonl",
                        },
                        "identity": {
                            "enabled": True,
                            "provider": "did:web",
                        },
                        "packages": [
                            {"package": "agent_governance_toolkit", "version": "3.0.0"}
                        ],
                    },
                }
            ),
            encoding="utf-8",
        )

        verifier = GovernanceVerifier(controls=_CUSTOM_VERIFY_CONTROLS)

        try:
            verifier.verify_evidence(evidence_path, strict=True)
            assert False, "Expected ValueError"
        except ValueError as exc:
            assert "exceeds size limit" in str(exc)


# ── Legacy CLI Tests ─────────────────────────────────────────


class TestCLI:
    def test_verify_command(self):
        from agent_compliance.cli.main import cmd_verify

        args = argparse.Namespace(json=False, badge=False)

        result = cmd_verify(args)

        assert result in (0, 1)

    def test_verify_json_output(self, capsys):
        from agent_compliance.cli.main import cmd_verify

        args = argparse.Namespace(json=True, badge=False)

        cmd_verify(args)
        captured = capsys.readouterr()
        parsed = json.loads(captured.out)

        assert "schema" in parsed

    def test_verify_badge_output(self, capsys):
        from agent_compliance.cli.main import cmd_verify

        args = argparse.Namespace(json=False, badge=True)

        cmd_verify(args)
        captured = capsys.readouterr()
        urls = re.findall(r"https?://[^\s\)]+", captured.out)

        assert any(urlparse(u).hostname == "img.shields.io" for u in urls)

    def test_integrity_generate(self, tmp_path: Path):
        from agent_compliance.cli.main import cmd_integrity

        output = str(tmp_path / "integrity.json")
        args = argparse.Namespace(generate=output, manifest=None, json=False)

        result = cmd_integrity(args)

        assert result == 0
        assert os.path.exists(output)

    def test_integrity_verify_no_manifest(self):
        from agent_compliance.cli.main import cmd_integrity

        args = argparse.Namespace(generate=None, manifest=None, json=False)

        result = cmd_integrity(args)

        assert result == 0
        