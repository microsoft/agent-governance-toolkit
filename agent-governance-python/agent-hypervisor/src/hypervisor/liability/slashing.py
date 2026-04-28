# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
# Public Preview — basic implementation
"""
Collateral Penalty Engine — stub implementation.

Public Preview: penalty is not enforced. Penalty calls are logged only.
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from datetime import UTC, datetime


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
    Penalty stub (Public Preview: logs penalty events, no penalties applied).
    """

    MAX_CASCADE_DEPTH = 2
    SIGMA_FLOOR = 0.05

    def __init__(self, vouching_engine: object) -> None:
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
        """Log a penalty event (Public Preview: no penalties applied)."""
        result = SlashResult(
            slash_id=f"penalize:{uuid.uuid4()}",
            vouchee_did=vouchee_did,
            vouchee_sigma_before=vouchee_sigma,
            vouchee_sigma_after=vouchee_sigma,
            voucher_clips=[],
            reason=reason,
            session_id=session_id,
            cascade_depth=0,
        )
        self._slash_history.append(result)
        return result

    @property
    def history(self) -> list[SlashResult]:
        return list(self._slash_history)
