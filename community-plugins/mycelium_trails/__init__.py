"""
agt-evidence-anchor — Mycelium Trails community plugin for the AGT EvidenceAnchor SPI.

Usage:
    from plugins.agt_evidence_anchor import MyceliumAnchor
    anchor = MyceliumAnchor(agent_id="my-agent")
    receipt = anchor.anchor(evidence_hash, metadata={})
    result  = anchor.verify(evidence_hash, receipt)
"""

from .anchor import MyceliumAnchor
from ._types import (
    AnchorReceipt,
    AnchorVerifyResult,
    AnchorVerifyStatus,
    EvidenceAnchor,
    InclusionProof,
)

__all__ = [
    "MyceliumAnchor",
    "EvidenceAnchor",
    "AnchorReceipt",
    "AnchorVerifyResult",
    "AnchorVerifyStatus",
    "InclusionProof",
]
