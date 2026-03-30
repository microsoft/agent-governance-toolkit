# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""Tests for SBOM generation and artifact signing."""

from __future__ import annotations

import json
import textwrap

import pytest

pytest.importorskip("cryptography", reason="cryptography required for signing tests")

from agent_sre.sbom import AgentSBOM, SBOMPackage
from agent_sre.signing import ArtifactSigner, SignatureBundle

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

SAMPLE_REQUIREMENTS = textwrap.dedent("""\
    # Core dependencies
    pydantic==2.4.0
    pyyaml>=6.0
    opentelemetry-api>=1.20
    cryptography==42.0.0
""")


def _write_text(tmp_path, name: str, content: str) -> str:
    """Write *content* to a file under *tmp_path* and return its path."""
    p = tmp_path / name
    p.write_text(content, encoding="utf-8")
    return str(p)


# ---------------------------------------------------------------------------
# SBOM — from_requirements
# ---------------------------------------------------------------------------


class TestFromRequirements:
    """Verify that requirements.txt files are parsed correctly."""

    def test_parses_pinned_and_range_versions(self, tmp_path):
        req_path = _write_text(tmp_path, "requirements.txt", SAMPLE_REQUIREMENTS)
        sbom = AgentSBOM.from_requirements("test-agent", "1.0.0", req_path)

        names = [p.name for p in sbom.packages]
        assert "pydantic" in names
        assert "pyyaml" in names
        assert "opentelemetry-api" in names
        assert "cryptography" in names

    def test_pinned_version_extracted(self, tmp_path):
        req_path = _write_text(tmp_path, "requirements.txt", SAMPLE_REQUIREMENTS)
        sbom = AgentSBOM.from_requirements("test-agent", "1.0.0", req_path)

        pydantic = next(p for p in sbom.packages if p.name == "pydantic")
        assert pydantic.version == "2.4.0"

    def test_skips_comments_and_blanks(self, tmp_path):
        content = "# a comment\n\npydantic==2.0\n"
        req_path = _write_text(tmp_path, "requirements.txt", content)
        sbom = AgentSBOM.from_requirements("a", "0.1", req_path)
        assert len(sbom.packages) == 1

    def test_relationships_created(self, tmp_path):
        req_path = _write_text(tmp_path, "requirements.txt", SAMPLE_REQUIREMENTS)
        sbom = AgentSBOM.from_requirements("test-agent", "1.0.0", req_path)
        assert len(sbom.relationships) == len(sbom.packages)

    def test_missing_file_raises(self):
        with pytest.raises(FileNotFoundError):
            AgentSBOM.from_requirements("a", "0.1", "/no/such/file.txt")


# ---------------------------------------------------------------------------
# SBOM — from_pyproject
# ---------------------------------------------------------------------------


class TestFromPyproject:
    """Verify pyproject.toml parsing."""

    PYPROJECT = textwrap.dedent("""\
        [project]
        name = "demo"
        version = "2.0.0"
        dependencies = [
            "requests>=2.28",
            "click==8.1.7",
        ]
    """)

    def test_parses_dependencies(self, tmp_path):
        pp_path = _write_text(tmp_path, "pyproject.toml", self.PYPROJECT)
        sbom = AgentSBOM.from_pyproject("demo-agent", pp_path)

        names = [p.name for p in sbom.packages]
        assert "requests" in names
        assert "click" in names

    def test_extracts_version_from_project_table(self, tmp_path):
        pp_path = _write_text(tmp_path, "pyproject.toml", self.PYPROJECT)
        sbom = AgentSBOM.from_pyproject("demo-agent", pp_path)
        assert sbom.version == "2.0.0"


# ---------------------------------------------------------------------------
# SPDX output format
# ---------------------------------------------------------------------------


class TestSPDXFormat:
    """Verify SPDX 2.3 JSON compliance."""

    def test_required_top_level_fields(self):
        sbom = AgentSBOM("agent-x", "1.0.0")
        sbom.add_package("dep-a", "0.1.0")
        doc = sbom.to_spdx()

        assert doc["spdxVersion"] == "SPDX-2.3"
        assert doc["dataLicense"] == "CC0-1.0"
        assert doc["SPDXID"] == "SPDXRef-DOCUMENT"
        assert "name" in doc
        assert "documentNamespace" in doc

    def test_packages_present(self):
        sbom = AgentSBOM("agent-x", "1.0.0")
        sbom.add_package("dep-a", "0.1.0")
        doc = sbom.to_spdx()

        # Root package + 1 dependency
        assert len(doc["packages"]) == 2
        pkg_names = {p["name"] for p in doc["packages"]}
        assert "agent-x" in pkg_names
        assert "dep-a" in pkg_names

    def test_describes_relationship_present(self):
        sbom = AgentSBOM("agent-x", "1.0.0")
        doc = sbom.to_spdx()

        describes = [
            r for r in doc["relationships"] if r["relationshipType"] == "DESCRIBES"
        ]
        assert len(describes) == 1

    def test_creation_info(self):
        sbom = AgentSBOM("agent-x", "1.0.0")
        doc = sbom.to_spdx()

        assert "creationInfo" in doc
        assert "created" in doc["creationInfo"]
        assert "Tool: agent-sre" in doc["creationInfo"]["creators"]


# ---------------------------------------------------------------------------
# CycloneDX output format
# ---------------------------------------------------------------------------


class TestCycloneDXFormat:
    """Verify CycloneDX 1.5 JSON compliance."""

    def test_required_top_level_fields(self):
        sbom = AgentSBOM("agent-x", "1.0.0")
        sbom.add_package("dep-a", "0.1.0")
        doc = sbom.to_cyclonedx()

        assert doc["bomFormat"] == "CycloneDX"
        assert doc["specVersion"] == "1.5"
        assert doc["version"] == 1

    def test_metadata_component(self):
        sbom = AgentSBOM("agent-x", "1.0.0")
        doc = sbom.to_cyclonedx()

        meta = doc["metadata"]
        assert meta["component"]["name"] == "agent-x"
        assert meta["component"]["version"] == "1.0.0"

    def test_components_listed(self):
        sbom = AgentSBOM("agent-x", "1.0.0")
        sbom.add_package("dep-a", "0.1.0")
        sbom.add_package("dep-b", "2.0.0")
        doc = sbom.to_cyclonedx()

        assert len(doc["components"]) == 2
        names = {c["name"] for c in doc["components"]}
        assert names == {"dep-a", "dep-b"}


# ---------------------------------------------------------------------------
# SBOM save to disk
# ---------------------------------------------------------------------------


class TestSBOMSave:
    """Verify save() writes valid JSON to disk."""

    def test_save_spdx(self, tmp_path):
        sbom = AgentSBOM("agent-x", "1.0.0")
        sbom.add_package("dep-a", "0.1.0")
        out = str(tmp_path / "sbom.spdx.json")
        sbom.save(out, format="spdx")

        with open(out, encoding="utf-8") as fh:
            data = json.loads(fh.read())
        assert data["spdxVersion"] == "SPDX-2.3"

    def test_save_cyclonedx(self, tmp_path):
        sbom = AgentSBOM("agent-x", "1.0.0")
        sbom.add_package("dep-a", "0.1.0")
        out = str(tmp_path / "sbom.cdx.json")
        sbom.save(out, format="cyclonedx")

        with open(out, encoding="utf-8") as fh:
            data = json.loads(fh.read())
        assert data["bomFormat"] == "CycloneDX"


# ---------------------------------------------------------------------------
# Artifact signing — roundtrip
# ---------------------------------------------------------------------------


class TestSignVerifyRoundtrip:
    """Verify that sign → verify works end-to-end."""

    def test_sign_and_verify_artifact(self, tmp_path):
        artifact = _write_text(tmp_path, "model.bin", "fake-model-weights")

        signer = ArtifactSigner()
        bundle = signer.sign_artifact(artifact)

        assert isinstance(bundle, SignatureBundle)
        assert len(bundle.signature) > 0
        assert len(bundle.public_key) == 32
        assert len(bundle.artifact_hash) == 64  # SHA-256 hex
        assert bundle.timestamp

        # Verification should succeed
        assert signer.verify_artifact(artifact, bundle.signature, bundle.public_key)

    def test_tampered_artifact_fails_verification(self, tmp_path):
        artifact = _write_text(tmp_path, "model.bin", "original-content")

        signer = ArtifactSigner()
        bundle = signer.sign_artifact(artifact)

        # Tamper with the file
        (tmp_path / "model.bin").write_text("tampered-content", encoding="utf-8")

        assert not signer.verify_artifact(artifact, bundle.signature, bundle.public_key)

    def test_wrong_key_fails_verification(self, tmp_path):
        artifact = _write_text(tmp_path, "model.bin", "some content")

        signer1 = ArtifactSigner()
        bundle = signer1.sign_artifact(artifact)

        # A different signer's public key must not verify
        signer2 = ArtifactSigner()
        assert not signer1.verify_artifact(
            artifact, bundle.signature, signer2.public_key_bytes
        )

    def test_sign_sbom(self):
        sbom = AgentSBOM("agent-x", "1.0.0")
        sbom.add_package("dep-a", "0.1.0")

        signer = ArtifactSigner()
        envelope = signer.sign_sbom(sbom)

        assert "payload" in envelope
        assert "signature" in envelope
        assert envelope["payload"]["spdxVersion"] == "SPDX-2.3"

        sig_info = envelope["signature"]
        assert "signature" in sig_info
        assert "public_key" in sig_info
        assert "artifact_hash" in sig_info


# ---------------------------------------------------------------------------
# SignatureBundle serialisation
# ---------------------------------------------------------------------------


class TestSignatureBundleSerde:
    """Verify round-trip serialisation of SignatureBundle."""

    def test_to_dict_and_back(self, tmp_path):
        artifact = _write_text(tmp_path, "data.bin", "hello")

        signer = ArtifactSigner()
        bundle = signer.sign_artifact(artifact)

        d = bundle.to_dict()
        restored = SignatureBundle.from_dict(d)

        assert restored.signature == bundle.signature
        assert restored.public_key == bundle.public_key
        assert restored.artifact_hash == bundle.artifact_hash
        assert restored.timestamp == bundle.timestamp


# ---------------------------------------------------------------------------
# Key loading from PEM file
# ---------------------------------------------------------------------------


class TestKeyPersistence:
    """Verify that Ed25519 keys can be exported and re-loaded."""

    def test_export_and_reload(self, tmp_path):
        signer = ArtifactSigner()
        pem_path = str(tmp_path / "key.pem")
        (tmp_path / "key.pem").write_bytes(signer.export_private_key_pem())

        reloaded = ArtifactSigner(private_key_path=pem_path)
        assert reloaded.public_key_bytes == signer.public_key_bytes
