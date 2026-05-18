"""
Mycelium Trails — community plugin for the AGT EvidenceAnchor SPI.

Implements EvidenceAnchor (anchor + verify) backed by Mycelium Trails
on Arbitrum. Evidence hashes are written as trail records via the public
argentum.rgiskard.xyz API and are immutable once anchored.

Install:
    pip install requests

Registration (explicit, as required by AGT):
    from plugins.agt_evidence_anchor import MyceliumAnchor
    agt_registry.register("mycelium", MyceliumAnchor())

Conforms to: MYCELIUM-EXTERNAL-ANCHOR-PROPOSAL.md v3
Append-only: Mycelium Trails records cannot be modified or deleted once written.
"""

from __future__ import annotations

import datetime
import time
from typing import Any

import requests

from .action_ref import compute_action_ref, format_timestamp
from ._types import (
    AnchorReceipt,
    AnchorVerifyResult,
    AnchorVerifyStatus,
    EvidenceAnchor,
    InclusionProof,
)

_BASE_URL = "https://argentum.rgiskard.xyz"
_BACKEND_NAME = "mycelium-trails"
_DEFAULT_TIMEOUT = 10


class MyceliumAnchor(EvidenceAnchor):
    """
    AGT EvidenceAnchor community plugin backed by Mycelium Trails on Arbitrum.

    anchor() writes a trail record and returns a receipt with the trail_id
    and action_ref. verify() confirms the evidence_hash via /trails/verify.

    Failure semantics: anchor() raises RuntimeError on network failure.
    The caller (AGT runtime) applies mode semantics (enforce/queue/best_effort).
    """

    def __init__(
        self,
        agent_id: str = "agt-evidence-anchor",
        base_url: str = _BASE_URL,
        timeout: int = _DEFAULT_TIMEOUT,
    ) -> None:
        self.agent_id = agent_id
        self.base_url = base_url.rstrip("/")
        self.timeout = timeout

    def anchor(self, evidence_hash: str, metadata: dict[str, Any]) -> AnchorReceipt:
        """
        Writes evidence_hash to Mycelium Trails.

        metadata keys (all optional):
          - agent_id    (str)  overrides instance agent_id for this call
          - action_type (str)  default: "agt:evidence_anchor"
          - scope       (str)  default: "agt-evidence"
          - parent_trail_id (str)
          - root_trail_id   (str)

        Raises RuntimeError if the Mycelium API is unreachable.
        """
        agent_id = metadata.get("agent_id", self.agent_id)
        action_type = metadata.get("action_type", "agt:evidence_anchor")
        scope = metadata.get("scope", "agt-evidence")

        _now = datetime.datetime.now(datetime.timezone.utc)
        now_dt = _now.replace(microsecond=(_now.microsecond // 1000) * 1000)
        ts_str = format_timestamp(now_dt)
        ts_unix = int(time.time())

        action_ref = compute_action_ref(agent_id, action_type, scope, ts_str)

        payload: dict[str, Any] = {
            "agent_id": agent_id,
            "service": "agt-evidence",
            "operation": action_type,
            "action_ref": action_ref,
            "payment_hash": evidence_hash,
            "timestamp": ts_unix,
            "claims": {
                "evidence_hash": evidence_hash,
                "source": "agt-evidence-anchor",
                **{
                    k: v
                    for k, v in metadata.items()
                    if k not in ("agent_id", "action_type", "scope",
                                 "parent_trail_id", "root_trail_id")
                },
            },
            "success": True,
            "scope": scope,
        }

        if "parent_trail_id" in metadata:
            payload["parent_trail_id"] = metadata["parent_trail_id"]
        if "root_trail_id" in metadata:
            payload["root_trail_id"] = metadata["root_trail_id"]

        try:
            resp = requests.post(
                f"{self.base_url}/trails",
                json=payload,
                timeout=self.timeout,
            )
            resp.raise_for_status()
            data = resp.json()
        except requests.RequestException as exc:
            raise RuntimeError(f"MyceliumAnchor.anchor failed: {exc}") from exc

        trail_id = data.get("trail_id", "")
        tx_hash = data.get("tx_hash") or data.get("payment_hash", "")
        anchored_at = data.get("anchored_at") or ts_str

        return AnchorReceipt(
            backend=_BACKEND_NAME,
            anchor_id=trail_id,
            anchored_at=anchored_at,
            evidence_hash=evidence_hash,
            metadata={
                "action_ref": action_ref,
                "agent_id": agent_id,
                "tx_hash": tx_hash,
            },
        )

    def verify(self, evidence_hash: str, receipt: AnchorReceipt) -> AnchorVerifyResult:
        """
        Confirms evidence_hash is recorded at receipt.anchor_id (trail_id).

        Uses GET /trails/verify?agent_id=X&action_ref=Y when action_ref is
        present in receipt.metadata. Falls back to GET /trails/{trail_id}.

        Returns AnchorVerifyResult with:
          VERIFIED           — hash confirmed, InclusionProof included
          NOT_FOUND          — trail_id does not exist
          HASH_MISMATCH      — trail exists but stored hash differs
          BACKEND_UNAVAILABLE — network or API error
        """
        action_ref = receipt.metadata.get("action_ref")
        agent_id = receipt.metadata.get("agent_id", self.agent_id)

        try:
            if action_ref:
                resp = requests.get(
                    f"{self.base_url}/trails/verify",
                    params={"agent_id": agent_id, "action_ref": action_ref},
                    timeout=self.timeout,
                )
            else:
                resp = requests.get(
                    f"{self.base_url}/trails/{receipt.anchor_id}",
                    timeout=self.timeout,
                )

            if resp.status_code == 404:
                return AnchorVerifyResult(
                    status=AnchorVerifyStatus.NOT_FOUND,
                    evidence_hash=evidence_hash,
                )

            resp.raise_for_status()
            data = resp.json()

        except requests.RequestException as exc:
            return AnchorVerifyResult(
                status=AnchorVerifyStatus.BACKEND_UNAVAILABLE,
                evidence_hash=evidence_hash,
                error_detail=str(exc),
            )

        if not data.get("verified", False) and "trail_id" not in data:
            return AnchorVerifyResult(
                status=AnchorVerifyStatus.NOT_FOUND,
                evidence_hash=evidence_hash,
            )

        stored_hash = (
            data.get("claims", {}).get("evidence_hash")
            or data.get("payment_hash")
        )
        if stored_hash and stored_hash != evidence_hash:
            return AnchorVerifyResult(
                status=AnchorVerifyStatus.HASH_MISMATCH,
                evidence_hash=evidence_hash,
                error_detail=f"stored: {stored_hash}",
            )

        tx_hash = data.get("tx_hash") or receipt.metadata.get("tx_hash", "")
        proof = InclusionProof(
            proof_type="tx_receipt",
            proof_data={
                "tx_hash": tx_hash,
                "explorer_url": f"https://arbiscan.io/tx/{tx_hash}" if tx_hash else None,
            },
        ) if tx_hash else None

        return AnchorVerifyResult(
            status=AnchorVerifyStatus.VERIFIED,
            evidence_hash=evidence_hash,
            inclusion_proof=proof,
        )
