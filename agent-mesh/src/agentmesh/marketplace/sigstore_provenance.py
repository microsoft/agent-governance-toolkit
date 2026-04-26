# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""
Sigstore Provenance Integration
================================

Generates and verifies Sigstore-compatible provenance attestations for
AGT plugin artifacts. Uses ``sigstore-python`` for keyless signing via
OIDC identity (Fulcio) and transparency log (Rekor).

This module complements the Ed25519 manifest signing in
``agentmesh.marketplace.signing`` by adding supply-chain provenance:

- **Ed25519 signing** (``agt sign``) proves the publisher controls a key.
- **Sigstore provenance** proves *who* built *what* from *which source*,
  recorded in a tamper-evident transparency log.

Usage::

    from agentmesh.marketplace.sigstore_provenance import (
        SigstoreProvenanceGenerator,
        verify_provenance,
    )

    gen = SigstoreProvenanceGenerator(
        builder_id="https://github.com/microsoft/agent-governance-toolkit",
    )
    attestation = gen.generate(
        artifact_path=Path("dist/my-plugin-1.0.0.tar.gz"),
        source_repo="https://github.com/microsoft/agent-governance-toolkit",
        source_commit="abc123",
    )
    attestation.save(Path("dist/my-plugin-1.0.0.tar.gz.sigstore.json"))

    # Verify
    result = verify_provenance(
        artifact_path=Path("dist/my-plugin-1.0.0.tar.gz"),
        attestation_path=Path("dist/my-plugin-1.0.0.tar.gz.sigstore.json"),
    )
    assert result.verified

References:
    - https://www.sigstore.dev/
    - SLSA Provenance v1.0: https://slsa.dev/provenance/v1
"""

from __future__ import annotations

import hashlib
import json
import logging
import subprocess
import time
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)

# SLSA Provenance v1.0 predicate type
SLSA_PROVENANCE_V1 = "https://slsa.dev/provenance/v1"
SIGSTORE_BUNDLE_MEDIA_TYPE = "application/vnd.dev.sigstore.bundle.v0.3+json"


@dataclass
class ProvenanceAttestation:
    """A SLSA v1.0 provenance attestation for a plugin artifact.

    Attributes:
        subject_name: Artifact filename.
        subject_digest: SHA-256 digest of the artifact.
        builder_id: URI identifying the build system.
        source_repo: Source repository URI.
        source_commit: Git commit SHA.
        build_timestamp: ISO-8601 build time.
        sigstore_bundle: Raw Sigstore bundle (populated after signing).
    """

    subject_name: str
    subject_digest: str
    builder_id: str
    source_repo: str = ""
    source_commit: str = ""
    build_timestamp: str = field(
        default_factory=lambda: datetime.now(UTC).isoformat()
    )
    sigstore_bundle: dict[str, Any] = field(default_factory=dict)
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_slsa_statement(self) -> dict[str, Any]:
        """Serialize to an in-toto SLSA Provenance v1.0 statement."""
        return {
            "_type": "https://in-toto.io/Statement/v1",
            "subject": [
                {
                    "name": self.subject_name,
                    "digest": {"sha256": self.subject_digest},
                }
            ],
            "predicateType": SLSA_PROVENANCE_V1,
            "predicate": {
                "buildDefinition": {
                    "buildType": "https://github.com/microsoft/agent-governance-toolkit/plugin-build/v1",
                    "externalParameters": {
                        "source": {
                            "uri": self.source_repo,
                            "digest": {"gitCommit": self.source_commit},
                        }
                    },
                    "resolvedDependencies": [],
                },
                "runDetails": {
                    "builder": {"id": self.builder_id},
                    "metadata": {
                        "invocationId": self.metadata.get("invocation_id", ""),
                        "startedOn": self.build_timestamp,
                    },
                },
            },
        }

    def to_dict(self) -> dict[str, Any]:
        """Serialize to a JSON-compatible dict."""
        return {
            "statement": self.to_slsa_statement(),
            "sigstore_bundle": self.sigstore_bundle,
            "metadata": self.metadata,
        }

    def save(self, path: Path) -> None:
        """Write attestation to a JSON file."""
        path.write_text(
            json.dumps(self.to_dict(), indent=2, sort_keys=False),
            encoding="utf-8",
        )
        logger.info("Saved provenance attestation to %s", path)

    @classmethod
    def load(cls, path: Path) -> ProvenanceAttestation:
        """Load attestation from a JSON file."""
        data = json.loads(path.read_text(encoding="utf-8"))
        stmt = data.get("statement", {})
        subject = stmt.get("subject", [{}])[0]
        predicate = stmt.get("predicate", {})
        build_def = predicate.get("buildDefinition", {})
        run_details = predicate.get("runDetails", {})
        source = build_def.get("externalParameters", {}).get("source", {})

        return cls(
            subject_name=subject.get("name", ""),
            subject_digest=subject.get("digest", {}).get("sha256", ""),
            builder_id=run_details.get("builder", {}).get("id", ""),
            source_repo=source.get("uri", ""),
            source_commit=source.get("digest", {}).get("gitCommit", ""),
            build_timestamp=run_details.get("metadata", {}).get("startedOn", ""),
            sigstore_bundle=data.get("sigstore_bundle", {}),
            metadata=data.get("metadata", {}),
        )


def _sha256_file(path: Path) -> str:
    """Compute SHA-256 hex digest of a file."""
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(8192), b""):
            h.update(chunk)
    return h.hexdigest()


class SigstoreProvenanceGenerator:
    """Generate SLSA provenance attestations for plugin artifacts.

    If ``cosign`` is available on PATH, the attestation is signed via
    Sigstore keyless signing (Fulcio + Rekor). Otherwise, the attestation
    is generated unsigned (useful for local development and CI without
    OIDC identity).

    Args:
        builder_id: URI identifying the build system (e.g., GitHub Actions
            workflow URL).
        use_cosign: Whether to attempt Sigstore signing via cosign.
            Defaults to True; falls back gracefully if cosign is absent.
    """

    def __init__(
        self,
        builder_id: str = "https://github.com/microsoft/agent-governance-toolkit",
        use_cosign: bool = True,
    ) -> None:
        self._builder_id = builder_id
        self._use_cosign = use_cosign

    def generate(
        self,
        artifact_path: Path,
        source_repo: str = "",
        source_commit: str = "",
        metadata: dict[str, Any] | None = None,
    ) -> ProvenanceAttestation:
        """Generate a provenance attestation for an artifact.

        Args:
            artifact_path: Path to the artifact file (e.g., .tar.gz, .whl).
            source_repo: Source repository URI.
            source_commit: Git commit SHA the artifact was built from.
            metadata: Additional metadata to include.

        Returns:
            A ``ProvenanceAttestation`` with SLSA v1.0 statement.
        """
        if not artifact_path.exists():
            raise FileNotFoundError(f"Artifact not found: {artifact_path}")

        digest = _sha256_file(artifact_path)
        attestation = ProvenanceAttestation(
            subject_name=artifact_path.name,
            subject_digest=digest,
            builder_id=self._builder_id,
            source_repo=source_repo,
            source_commit=source_commit,
            metadata=metadata or {},
        )

        if self._use_cosign:
            bundle = self._sign_with_cosign(attestation, artifact_path)
            if bundle:
                attestation.sigstore_bundle = bundle

        logger.info(
            "Generated provenance for %s (sha256:%s)",
            artifact_path.name,
            digest[:12],
        )
        return attestation

    def _sign_with_cosign(
        self,
        attestation: ProvenanceAttestation,
        artifact_path: Path,
    ) -> dict[str, Any] | None:
        """Attempt to sign the attestation with cosign.

        Returns the Sigstore bundle dict, or None if cosign is unavailable.
        """
        try:
            # Check if cosign is available
            result = subprocess.run(
                ["cosign", "version"],
                capture_output=True,
                timeout=10,
            )
            if result.returncode != 0:
                logger.warning("cosign not functional, skipping Sigstore signing")
                return None
        except FileNotFoundError:
            logger.info("cosign not found on PATH, generating unsigned attestation")
            return None
        except subprocess.TimeoutExpired:
            logger.warning("cosign timed out, skipping Sigstore signing")
            return None

        try:
            import tempfile

            stmt = json.dumps(attestation.to_slsa_statement())
            with tempfile.NamedTemporaryFile(
                mode="w", suffix=".json", delete=False
            ) as f:
                f.write(stmt)
                stmt_path = f.name

            bundle_path = f"{artifact_path}.sigstore.json"
            result = subprocess.run(
                [
                    "cosign",
                    "attest",
                    "--predicate",
                    stmt_path,
                    "--type",
                    SLSA_PROVENANCE_V1,
                    "--bundle",
                    bundle_path,
                    str(artifact_path),
                ],
                capture_output=True,
                text=True,
                timeout=60,
            )

            if result.returncode == 0 and Path(bundle_path).exists():
                bundle = json.loads(Path(bundle_path).read_text(encoding="utf-8"))
                Path(stmt_path).unlink(missing_ok=True)
                Path(bundle_path).unlink(missing_ok=True)
                logger.info("Sigstore signing succeeded")
                return bundle

            logger.warning("cosign attest failed: %s", result.stderr[:200])
            Path(stmt_path).unlink(missing_ok=True)
            return None

        except Exception as exc:
            logger.warning("Sigstore signing failed: %s", exc)
            return None


@dataclass
class VerificationResult:
    """Result of verifying a provenance attestation."""

    verified: bool
    artifact_name: str = ""
    digest_match: bool = False
    sigstore_verified: bool = False
    builder_id: str = ""
    source_repo: str = ""
    source_commit: str = ""
    error: str = ""


def verify_provenance(
    artifact_path: Path,
    attestation_path: Path,
) -> VerificationResult:
    """Verify a provenance attestation against an artifact.

    Checks:
    1. Artifact SHA-256 matches the attestation subject digest.
    2. If a Sigstore bundle is present, verifies it with cosign.

    Args:
        artifact_path: Path to the artifact file.
        attestation_path: Path to the attestation JSON file.

    Returns:
        A ``VerificationResult`` with verification details.
    """
    if not artifact_path.exists():
        return VerificationResult(
            verified=False,
            error=f"Artifact not found: {artifact_path}",
        )

    if not attestation_path.exists():
        return VerificationResult(
            verified=False,
            artifact_name=artifact_path.name,
            error=f"Attestation not found: {attestation_path}",
        )

    attestation = ProvenanceAttestation.load(attestation_path)
    actual_digest = _sha256_file(artifact_path)
    digest_match = actual_digest == attestation.subject_digest

    if not digest_match:
        return VerificationResult(
            verified=False,
            artifact_name=artifact_path.name,
            digest_match=False,
            error=f"Digest mismatch: expected {attestation.subject_digest[:16]}..., got {actual_digest[:16]}...",
        )

    # If there's a Sigstore bundle, attempt cosign verification
    sigstore_verified = False
    if attestation.sigstore_bundle:
        sigstore_verified = _verify_cosign_bundle(
            artifact_path, attestation.sigstore_bundle
        )

    return VerificationResult(
        verified=digest_match,
        artifact_name=artifact_path.name,
        digest_match=digest_match,
        sigstore_verified=sigstore_verified,
        builder_id=attestation.builder_id,
        source_repo=attestation.source_repo,
        source_commit=attestation.source_commit,
    )


def _verify_cosign_bundle(
    artifact_path: Path,
    bundle: dict[str, Any],
) -> bool:
    """Verify a Sigstore bundle with cosign. Returns True on success."""
    try:
        import tempfile

        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".json", delete=False
        ) as f:
            json.dump(bundle, f)
            bundle_path = f.name

        result = subprocess.run(
            [
                "cosign",
                "verify-attestation",
                "--bundle",
                bundle_path,
                "--type",
                SLSA_PROVENANCE_V1,
                str(artifact_path),
            ],
            capture_output=True,
            text=True,
            timeout=30,
        )
        Path(bundle_path).unlink(missing_ok=True)
        return result.returncode == 0

    except (FileNotFoundError, subprocess.TimeoutExpired):
        logger.info("cosign not available for bundle verification")
        return False
    except Exception as exc:
        logger.warning("Sigstore bundle verification failed: %s", exc)
        return False
