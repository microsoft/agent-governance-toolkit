"""
Types for the AGT EvidenceAnchor SPI.

These are inline stubs used when agt-evidence is not installed.
When agt-evidence ships the ABC, replace these imports with:
    from agt_evidence import (
        EvidenceAnchor, AnchorReceipt, AnchorVerifyResult,
        AnchorVerifyStatus, InclusionProof,
    )

Conforms to: MYCELIUM-EXTERNAL-ANCHOR-PROPOSAL.md v3
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Optional


class AnchorVerifyStatus(str, Enum):
    VERIFIED = "verified"
    NOT_FOUND = "not_found"
    HASH_MISMATCH = "hash_mismatch"
    BACKEND_UNAVAILABLE = "backend_unavailable"


@dataclass
class InclusionProof:
    """Backend-specific proof that the record exists at the claimed position.

    Mycelium Trails: proof_type="tx_receipt", proof_data contains tx_hash,
    block_number, and explorer_url.
    """
    proof_type: str
    proof_data: dict[str, Any]


@dataclass
class AnchorVerifyResult:
    status: AnchorVerifyStatus
    evidence_hash: str
    inclusion_proof: Optional[InclusionProof] = None
    error_detail: Optional[str] = None


@dataclass
class AnchorReceipt:
    backend: str
    anchor_id: str          # trail_id in Mycelium Trails
    anchored_at: str        # RFC 3339 UTC, e.g. "2026-05-15T10:00:00.123Z"
    evidence_hash: str
    metadata: dict[str, Any] = field(default_factory=dict)


class EvidenceAnchor(ABC):
    @abstractmethod
    def anchor(self, evidence_hash: str, metadata: dict[str, Any]) -> AnchorReceipt:
        """Write evidence_hash to the external surface. Returns a receipt."""
        ...

    @abstractmethod
    def verify(self, evidence_hash: str, receipt: AnchorReceipt) -> AnchorVerifyResult:
        """Confirm evidence_hash is recorded at the position in receipt."""
        ...
