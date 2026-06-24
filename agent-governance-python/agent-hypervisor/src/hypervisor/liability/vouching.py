# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""
Sponsorship Protocol — joint-liability bonding between agents.

A voucher stakes (bonds) a fraction of its reputation (sigma) to sponsor a
vouchee into a session. Bonds boost the vouchee's effective score and are the
collateral clipped by the :mod:`~hypervisor.liability.slashing` engine when the
vouchee misbehaves. Bonding is enforced: self-vouching, under-qualified
vouchers, cycles, and over-exposure are rejected.
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from datetime import UTC, datetime

from hypervisor.constants import (
    VOUCHING_DEFAULT_BOND_PCT,
    VOUCHING_DEFAULT_MAX_EXPOSURE,
    VOUCHING_MIN_VOUCHER_SCORE,
    VOUCHING_SCORE_SCALE,
)


@dataclass
class VouchRecord:
    """A record of one agent sponsorship for another within a session."""

    vouch_id: str
    voucher_did: str
    vouchee_did: str
    session_id: str
    bonded_sigma_pct: float
    bonded_amount: float
    created_at: datetime = field(default_factory=lambda: datetime.now(UTC))
    expiry: datetime | None = None
    is_active: bool = True
    released_at: datetime | None = None

    @property
    def is_expired(self) -> bool:
        if self.expiry is None:
            return False
        return datetime.now(UTC) > self.expiry


class VouchingEngine:
    """
    Joint-liability sponsorship engine.

    Enforces voucher qualification, acyclicity, and per-voucher exposure
    limits, and computes a vouchee's effective score from active bonds.
    """

    SCORE_SCALE = VOUCHING_SCORE_SCALE
    MIN_VOUCHER_SCORE = VOUCHING_MIN_VOUCHER_SCORE
    DEFAULT_BOND_PCT = VOUCHING_DEFAULT_BOND_PCT
    DEFAULT_MAX_EXPOSURE = VOUCHING_DEFAULT_MAX_EXPOSURE

    def __init__(self, max_exposure: float | None = None) -> None:
        self._vouches: dict[str, VouchRecord] = {}
        self.max_exposure = max_exposure or self.DEFAULT_MAX_EXPOSURE

    @property
    def vouch_count(self) -> int:
        """Total number of sponsorship records (active + released)."""
        return len(self._vouches)

    def vouch(
        self,
        voucher_did: str,
        vouchee_did: str,
        session_id: str,
        voucher_sigma: float,
        bond_pct: float | None = None,
        expiry: datetime | None = None,
    ) -> VouchRecord:
        """Create a sponsorship bond, staking ``bond_pct`` of the voucher's sigma.

        Raises:
            VouchingError: if the voucher sponsors itself, has a sigma below
                ``MIN_VOUCHER_SCORE``, would create a cycle in the session's
                liability graph, or would exceed its maximum bonded exposure.
        """
        if voucher_did == vouchee_did:
            raise VouchingError("Cannot sponsor for yourself")
        if voucher_sigma < self.MIN_VOUCHER_SCORE:
            raise VouchingError(
                f"Voucher sigma {voucher_sigma:.3f} is below minimum {self.MIN_VOUCHER_SCORE:.2f}"
            )
        if self._creates_cycle(voucher_did, vouchee_did, session_id):
            raise VouchingError(
                f"Circular sponsorship: {vouchee_did} already sponsors {voucher_did}"
            )

        pct = self.DEFAULT_BOND_PCT if bond_pct is None else bond_pct
        bonded_amount = voucher_sigma * pct

        max_bondable = self.max_exposure * voucher_sigma
        projected = self.get_total_exposure(voucher_did, session_id) + bonded_amount
        if projected > max_bondable + 1e-9:
            raise VouchingError(
                f"Bond {bonded_amount:.3f} would exceed max exposure "
                f"{max_bondable:.3f} for {voucher_did}"
            )

        record = VouchRecord(
            vouch_id=f"sponsor:{uuid.uuid4()}",
            voucher_did=voucher_did,
            vouchee_did=vouchee_did,
            session_id=session_id,
            bonded_sigma_pct=pct,
            bonded_amount=bonded_amount,
            expiry=expiry,
        )
        self._vouches[record.vouch_id] = record
        return record

    def compute_eff_score(
        self,
        vouchee_did: str,
        session_id: str,
        vouchee_sigma: float,
        risk_weight: float,
    ) -> float:
        """Effective score: ``sigma_L + omega * sum(bonded_amount)``, capped at 1.0.

        ``sigma_L`` is the vouchee's own score, ``omega`` the risk weight, and the
        sum runs over the bonds of all active vouchers for the vouchee.
        """
        bonded_total = sum(
            v.bonded_amount for v in self._active_vouches_for(vouchee_did, session_id)
        )
        return min(1.0, vouchee_sigma + risk_weight * bonded_total)

    def get_vouchers_for(self, agent_did: str, session_id: str) -> list[VouchRecord]:
        """Get all sponsors for an agent in a session."""
        return [
            v
            for v in self._vouches.values()
            if v.vouchee_did == agent_did and v.session_id == session_id and v.is_active
        ]

    def get_total_exposure(self, voucher_did: str, session_id: str) -> float:
        """Total sigma a voucher has bonded across all its active vouches in a session."""
        return sum(
            v.bonded_amount
            for v in self._vouches.values()
            if v.voucher_did == voucher_did and v.session_id == session_id and v.is_active
        )

    def release_bond(self, vouch_id: str) -> None:
        """Release a sponsorship bond."""
        if vouch_id not in self._vouches:
            raise VouchingError(f"Sponsor {vouch_id} not found")
        record = self._vouches[vouch_id]
        record.is_active = False
        record.released_at = datetime.now(UTC)

    def release_session_bonds(self, session_id: str) -> int:
        """Release all bonds for a session."""
        count = 0
        for v in self._vouches.values():
            if v.session_id == session_id and v.is_active:
                v.is_active = False
                v.released_at = datetime.now(UTC)
                count += 1
        return count

    def _active_vouches_for(self, agent_did: str, session_id: str) -> list[VouchRecord]:
        return self.get_vouchers_for(agent_did, session_id)

    def _creates_cycle(self, voucher_did: str, vouchee_did: str, session_id: str) -> bool:
        """True if adding ``voucher_did -> vouchee_did`` would close a cycle.

        Walks the existing active sponsor graph (edges point voucher -> vouchee)
        looking for a path from ``vouchee_did`` back to ``voucher_did``.
        """
        if voucher_did == vouchee_did:
            return True
        adjacency: dict[str, list[str]] = {}
        for v in self._vouches.values():
            if v.session_id == session_id and v.is_active:
                adjacency.setdefault(v.voucher_did, []).append(v.vouchee_did)

        stack = [vouchee_did]
        seen: set[str] = set()
        while stack:
            node = stack.pop()
            if node == voucher_did:
                return True
            if node in seen:
                continue
            seen.add(node)
            stack.extend(adjacency.get(node, ()))
        return False


class VouchingError(Exception):
    """Raised for sponsorship protocol violations."""
