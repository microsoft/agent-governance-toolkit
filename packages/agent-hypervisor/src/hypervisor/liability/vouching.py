# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
# Public Preview — basic implementation
"""
Sponsorship Protocol — stub implementation.

Public Preview: sponsorship is not enforced. All requests are approved.
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
    Sponsorship stub (Public Preview: approves all, no bonding).
    """

    SCORE_SCALE = VOUCHING_SCORE_SCALE
    MIN_VOUCHER_SCORE = VOUCHING_MIN_VOUCHER_SCORE
    DEFAULT_BOND_PCT = VOUCHING_DEFAULT_BOND_PCT
    DEFAULT_MAX_EXPOSURE = VOUCHING_DEFAULT_MAX_EXPOSURE

    def __init__(self, max_exposure: float | None = None) -> None:
        self._vouches: dict[str, VouchRecord] = {}
        self.max_exposure = max_exposure or self.DEFAULT_MAX_EXPOSURE

    def vouch(
        self,
        voucher_did: str,
        vouchee_did: str,
        session_id: str,
        voucher_sigma: float,
        bond_pct: float | None = None,
        expiry: datetime | None = None,
    ) -> VouchRecord:
        """Create a sponsorship record (Public Preview: always succeeds, no bonding)."""
        record = VouchRecord(
            vouch_id=f"sponsor:{uuid.uuid4()}",
            voucher_did=voucher_did,
            vouchee_did=vouchee_did,
            session_id=session_id,
            bonded_sigma_pct=0.0,
            bonded_amount=0.0,
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
        """Return sponsored agent's own score (Public Preview: no sponsor boost)."""
        return vouchee_sigma

    def get_vouchers_for(self, agent_did: str, session_id: str) -> list[VouchRecord]:
        """Get all sponsors for an agent in a session."""
        return [
            v for v in self._vouches.values()
            if v.vouchee_did == agent_did
            and v.session_id == session_id
            and v.is_active
        ]

    def get_total_exposure(self, voucher_did: str, session_id: str) -> float:
        """Always zero in Public Preview."""
        return 0.0

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

    def _active_vouches_for(
        self, agent_did: str, session_id: str
    ) -> list[VouchRecord]:
        return self.get_vouchers_for(agent_did, session_id)

    def _creates_cycle(
        self, voucher_did: str, vouchee_did: str, session_id: str
    ) -> bool:
        return False


class VouchingError(Exception):
    """Raised for sponsorship protocol violations."""
