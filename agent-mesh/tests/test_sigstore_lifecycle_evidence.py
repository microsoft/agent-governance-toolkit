# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""Tests for Sigstore provenance, plugin lifecycle, and evidence pipeline."""

from __future__ import annotations

import json
import tempfile
from pathlib import Path

import pytest

# ── Sigstore provenance tests ──────────────────────────────────────────────

from agentmesh.marketplace.sigstore_provenance import (
    ProvenanceAttestation,
    SigstoreProvenanceGenerator,
    VerificationResult,
    _sha256_file,
    verify_provenance,
)


@pytest.fixture()
def tmp_dir():
    with tempfile.TemporaryDirectory() as d:
        yield Path(d)


@pytest.fixture()
def sample_artifact(tmp_dir: Path) -> Path:
    artifact = tmp_dir / "my-plugin-1.0.0.tar.gz"
    artifact.write_bytes(b"fake artifact content for testing")
    return artifact


class TestSigstoreProvenance:
    def test_generate_attestation(self, sample_artifact: Path):
        gen = SigstoreProvenanceGenerator(use_cosign=False)
        att = gen.generate(
            artifact_path=sample_artifact,
            source_repo="https://github.com/test/repo",
            source_commit="abc123",
        )
        assert att.subject_name == "my-plugin-1.0.0.tar.gz"
        assert len(att.subject_digest) == 64  # SHA-256 hex
        assert att.source_repo == "https://github.com/test/repo"
        assert att.source_commit == "abc123"

    def test_slsa_statement_format(self, sample_artifact: Path):
        gen = SigstoreProvenanceGenerator(use_cosign=False)
        att = gen.generate(artifact_path=sample_artifact)
        stmt = att.to_slsa_statement()
        assert stmt["_type"] == "https://in-toto.io/Statement/v1"
        assert stmt["predicateType"] == "https://slsa.dev/provenance/v1"
        assert stmt["subject"][0]["name"] == "my-plugin-1.0.0.tar.gz"
        assert "sha256" in stmt["subject"][0]["digest"]

    def test_save_and_load_roundtrip(self, sample_artifact: Path, tmp_dir: Path):
        gen = SigstoreProvenanceGenerator(use_cosign=False)
        att = gen.generate(
            artifact_path=sample_artifact,
            source_repo="https://github.com/test/repo",
            source_commit="def456",
        )
        att_path = tmp_dir / "attestation.json"
        att.save(att_path)

        loaded = ProvenanceAttestation.load(att_path)
        assert loaded.subject_name == att.subject_name
        assert loaded.subject_digest == att.subject_digest
        assert loaded.source_commit == "def456"

    def test_verify_matching_artifact(self, sample_artifact: Path, tmp_dir: Path):
        gen = SigstoreProvenanceGenerator(use_cosign=False)
        att = gen.generate(artifact_path=sample_artifact)
        att_path = tmp_dir / "attestation.json"
        att.save(att_path)

        result = verify_provenance(sample_artifact, att_path)
        assert result.verified
        assert result.digest_match

    def test_verify_tampered_artifact(self, sample_artifact: Path, tmp_dir: Path):
        gen = SigstoreProvenanceGenerator(use_cosign=False)
        att = gen.generate(artifact_path=sample_artifact)
        att_path = tmp_dir / "attestation.json"
        att.save(att_path)

        # Tamper with the artifact
        sample_artifact.write_bytes(b"tampered content")

        result = verify_provenance(sample_artifact, att_path)
        assert not result.verified
        assert not result.digest_match

    def test_verify_missing_artifact(self, tmp_dir: Path):
        result = verify_provenance(
            tmp_dir / "nonexistent.tar.gz",
            tmp_dir / "attestation.json",
        )
        assert not result.verified
        assert "not found" in result.error.lower()

    def test_sha256_file(self, sample_artifact: Path):
        digest = _sha256_file(sample_artifact)
        assert len(digest) == 64
        assert all(c in "0123456789abcdef" for c in digest)


# ── Plugin lifecycle tests ─────────────────────────────────────────────────

from agentmesh.marketplace.lifecycle import (
    LifecyclePhase,
    PluginLifecycleManager,
)


class TestPluginLifecycle:
    def test_publish(self):
        mgr = PluginLifecycleManager()
        status = mgr.publish("my-plugin", "1.0.0")
        assert status.phase == LifecyclePhase.PUBLISHED
        assert status.is_usable

    def test_full_lifecycle(self):
        mgr = PluginLifecycleManager()
        mgr.publish("my-plugin", "1.0.0")
        mgr.activate("my-plugin", "1.0.0")
        mgr.deprecate(
            "my-plugin", "1.0.0",
            reason="Replaced by v2",
            successor="my-plugin",
            successor_version="2.0.0",
        )
        status = mgr.get_status("my-plugin", "1.0.0")
        assert status.phase == LifecyclePhase.DEPRECATED
        assert status.is_usable  # deprecated is still usable
        assert status.is_deprecated
        assert status.deprecation.reason == "Replaced by v2"

        mgr.end_of_life("my-plugin", "1.0.0")
        status = mgr.get_status("my-plugin", "1.0.0")
        assert status.is_eol
        assert not status.is_usable

    def test_install_check_deprecated(self):
        mgr = PluginLifecycleManager()
        mgr.deprecate(
            "old-plugin", "1.0.0",
            reason="Use new-plugin instead",
            successor="new-plugin",
        )
        allowed, msg = mgr.check_install_allowed("old-plugin", "1.0.0")
        assert allowed  # deprecated but still installable
        assert "WARNING" in msg
        assert "new-plugin" in msg

    def test_install_check_eol(self):
        mgr = PluginLifecycleManager()
        mgr.end_of_life("dead-plugin", "0.9.0")
        allowed, msg = mgr.check_install_allowed("dead-plugin", "0.9.0")
        assert not allowed
        assert "end-of-life" in msg

    def test_install_check_unknown(self):
        mgr = PluginLifecycleManager()
        allowed, msg = mgr.check_install_allowed("unknown-plugin", "1.0.0")
        assert allowed
        assert msg == ""

    def test_cert_renewal(self):
        mgr = PluginLifecycleManager()
        mgr.publish("my-plugin", "1.0.0")
        record = mgr.record_cert_renewal(
            "my-plugin", "1.0.0",
            old_key_fingerprint="abc123",
            new_key_fingerprint="def456",
        )
        assert record.old_key_fingerprint == "abc123"
        status = mgr.get_status("my-plugin", "1.0.0")
        assert len(status.cert_renewals) == 1

    def test_enforce_eol_dates(self):
        mgr = PluginLifecycleManager()
        mgr.deprecate(
            "expiring", "1.0.0",
            reason="old",
            eol_date="2020-01-01T00:00:00+00:00",  # already past
        )
        transitioned = mgr.enforce_eol_dates()
        assert len(transitioned) == 1
        assert transitioned[0].phase == LifecyclePhase.EOL

    def test_list_deprecated(self):
        mgr = PluginLifecycleManager()
        mgr.deprecate("a", "1.0.0", reason="old")
        mgr.deprecate("b", "2.0.0", reason="old")
        mgr.publish("c", "1.0.0")
        assert len(mgr.list_deprecated()) == 2

    def test_phase_history(self):
        mgr = PluginLifecycleManager()
        mgr.publish("p", "1.0.0")
        mgr.activate("p", "1.0.0")
        mgr.deprecate("p", "1.0.0", reason="old")
        status = mgr.get_status("p", "1.0.0")
        phases = [h["phase"] for h in status.phase_history]
        assert phases == ["published", "active", "deprecated"]

    def test_to_dict(self):
        mgr = PluginLifecycleManager()
        mgr.deprecate("x", "1.0.0", reason="replaced", successor="y")
        status = mgr.get_status("x", "1.0.0")
        d = status.to_dict()
        assert d["phase"] == "deprecated"
        assert d["deprecation"]["successor_plugin"] == "y"


# ── Evidence pipeline tests ────────────────────────────────────────────────

from agentmesh.governance.evidence_pipeline import EvidencePipeline


class TestEvidencePipeline:
    def test_empty_pipeline_produces_document(self):
        pipeline = EvidencePipeline(
            system_name="Test Agent",
            provider="Test Corp",
        )
        report = pipeline.run()
        assert report.document.system_name == "Test Agent"
        assert len(report.warnings) >= 2  # no policies, no audit log

    def test_collects_policies(self, tmp_dir: Path):
        policies_dir = tmp_dir / "policies"
        policies_dir.mkdir()
        policy_yaml = (
            "apiVersion: governance.toolkit/v1\n"
            "name: security\n"
            "description: Security policy\n"
            "default_action: deny\n"
            "rules:\n"
            "  - name: block-shell\n"
            "    condition: \"tool.name == 'shell_exec'\"\n"
            "    action: deny\n"
        )
        (policies_dir / "security.yaml").write_text(policy_yaml, encoding="utf-8")

        pipeline = EvidencePipeline(
            system_name="Test Agent",
            provider="Test Corp",
            policies_dir=policies_dir,
        )
        report = pipeline.run()
        policy_sources = [s for s in report.sources if s.source_type == "policy"]
        assert len(policy_sources) == 1
        assert policy_sources[0].record_count == 1

    def test_save_markdown(self, tmp_dir: Path):
        pipeline = EvidencePipeline(
            system_name="Test Agent",
            provider="Test Corp",
        )
        report = pipeline.run()
        md_path = tmp_dir / "report.md"
        report.save_markdown(md_path)
        content = md_path.read_text(encoding="utf-8")
        assert "Test Agent" in content
        assert "Test Corp" in content
        assert "Evidence Gaps" in content

    def test_save_manifest(self, tmp_dir: Path):
        pipeline = EvidencePipeline(
            system_name="Test Agent",
            provider="Test Corp",
        )
        report = pipeline.run()
        manifest_path = tmp_dir / "manifest.json"
        report.save_manifest(manifest_path)
        data = json.loads(manifest_path.read_text(encoding="utf-8"))
        assert data["system_name"] == "Test Agent"
        assert isinstance(data["warnings"], list)
