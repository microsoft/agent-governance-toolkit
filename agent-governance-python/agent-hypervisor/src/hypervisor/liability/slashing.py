# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""
Collateral Penalty Engine — slashes misbehaving agents and their sponsors.

A slash blacklists the offending vouchee (sigma -> 0) and clips every active
voucher's collateral (``sigma * (1 - omega)``, floored at ``SIGMA_FLOOR``). The
penalty cascades up the liability graph to vouchers-of-vouchers, bounded by
``MAX_CASCADE_DEPTH``.
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from datetime import UTC, datetime

from hypervisor.liability.vouching import VouchingEngine


@dataclass
class SlashResult:
    """Result of a penalty operation."""

    slash_id: str
    vouchee_did: str
    vouchee_sigma_before: float
    vouchee_sigma_after: float
    voucher_clips: list[VoucherClip]
    reason: str
    session_id: str
    timestamp: datetime = field(default_factory=lambda: datetime.now(UTC))
    cascade_depth: int = 0


@dataclass
class VoucherClip:
    """A collateral clip applied to a sponsor."""

    voucher_did: str
    sigma_before: float
    sigma_after: float
    risk_weight: float
    vouch_id: str


class SlashingEngine:
    """
    Penalty engine: blacklists offenders and clips their sponsors' collateral.
    """

    MAX_CASCADE_DEPTH = 2
    SIGMA_FLOOR = 0.05

    def __init__(self, vouching_engine: VouchingEngine) -> None:
        self._vouching = vouching_engine
        self._slash_history: list[SlashResult] = []

    def slash(
        self,
        vouchee_did: str,
        session_id: str,
        vouchee_sigma: float,
        risk_weight: float,
        reason: str,
        agent_scores: dict[str, float],
        cascade_depth: int = 0,
    ) -> SlashResult:
        """Blacklist the vouchee and clip its (transitive) vouchers' collateral.

        Args:
            agent_scores: live score map, mutated in place. The vouchee is set to
                ``0.0``; each clipped voucher is reduced to
                ``max(SIGMA_FLOOR, sigma * (1 - risk_weight))``. Vouchers absent
                from this map are skipped (their score is unknown to the caller).
        """
        agent_scores[vouchee_did] = 0.0

        clips: list[VoucherClip] = []
        visited: set[str] = {vouchee_did}
        reached = self._clip_chain(
            vouchee_did, session_id, risk_weight, agent_scores, clips, visited, cascade_depth + 1
        )

        result = SlashResult(
            slash_id=f"penalize:{uuid.uuid4()}",
            vouchee_did=vouchee_did,
            vouchee_sigma_before=vouchee_sigma,
            vouchee_sigma_after=0.0,
            voucher_clips=clips,
            reason=reason,
            session_id=session_id,
            cascade_depth=max(0, reached),
        )
        self._slash_history.append(result)
        return result

    def _clip_chain(
        self,
        vouchee_did: str,
        session_id: str,
        risk_weight: float,
        agent_scores: dict[str, float],
        clips: list[VoucherClip],
        visited: set[str],
        depth: int,
    ) -> int:
        """Clip the direct vouchers of ``vouchee_did`` and cascade upward.

        Returns the deepest cascade level that applied a clip.
        """
        if depth > self.MAX_CASCADE_DEPTH:
            return depth - 1

        reached = depth - 1
        for record in self._vouching.get_vouchers_for(vouchee_did, session_id):
            voucher = record.voucher_did
            if voucher in visited or voucher not in agent_scores:
                continue
            visited.add(voucher)

            sigma_before = agent_scores[voucher]
            sigma_after = max(self.SIGMA_FLOOR, sigma_before * (1.0 - risk_weight))
            agent_scores[voucher] = sigma_after
            clips.append(
                VoucherClip(
                    voucher_did=voucher,
                    sigma_before=sigma_before,
                    sigma_after=sigma_after,
                    risk_weight=risk_weight,
                    vouch_id=record.vouch_id,
                )
            )
            reached = max(reached, depth)
            reached = max(
                reached,
                self._clip_chain(
                    voucher, session_id, risk_weight, agent_scores, clips, visited, depth + 1
                ),
            )
        return reached

    @property
    def history(self) -> list[SlashResult]:
        return list(self._slash_history)
