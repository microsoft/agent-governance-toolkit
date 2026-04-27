# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""
Trust Score Exporter.

Provider-agnostic abstraction for exposing TrustProvider scores as
first-class agent trust attributes that downstream systems can consume.
"""

import math
from abc import ABC, abstractmethod
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, Optional

from pydantic import BaseModel, Field, field_validator, model_validator


def _utc_now() -> datetime:
    """Return current UTC time as a timezone-aware datetime."""
    return datetime.now(timezone.utc)


class TrustAttributeRecord(BaseModel):
    """
    Normalized trust attribute record produced by a ``TrustScoreExporter``.

    Kept intentionally separate from ``TrustedAgentCard`` so that the trust
    attribute surface is not coupled to the card model's lifecycle. A card
    can reference one or more records via ``provider`` keys without owning
    their storage or refresh cadence.
    """

    provider: str = Field(
        ...,
        min_length=1,
        description="Stable identifier of the trust provider that produced this record.",
    )
    subject_did: str = Field(
        ...,
        min_length=1,
        description="DID of the agent the record refers to.",
    )
    score: Optional[float] = Field(
        default=None,
        ge=0.0,
        le=1.0,
        description="Optional scalar trust score normalized to [0.0, 1.0].",
    )
    score_dimensions: Optional[Dict[str, float]] = Field(
        default=None,
        description=(
            "Optional multi-dimensional scores. Each value must be normalized "
            "to [0.0, 1.0]. Use this when a single scalar is insufficient."
        ),
    )
    updated_at: datetime = Field(
        default_factory=_utc_now,
        description="Timestamp at which the record's scores were last computed.",
    )
    max_age_seconds: Optional[int] = Field(
        default=None,
        gt=0,
        description=(
            "Optional freshness budget in seconds. If unset, freshness is "
            "considered unbounded by the provider."
        ),
    )
    metadata: Dict[str, Any] = Field(
        default_factory=dict,
        description="Provider-specific metadata that does not fit the normalized shape.",
    )

    @field_validator("updated_at")
    @classmethod
    def validate_updated_at_is_aware(cls, v: datetime) -> datetime:
        if v.tzinfo is None or v.tzinfo.utcoffset(v) is None:
            raise ValueError("updated_at must be a timezone-aware datetime")
        return v

    @field_validator("score", mode="before")
    @classmethod
    def reject_bool_score(cls, v: Any) -> Any:
        # Run before coercion: pydantic would otherwise turn True/False into
        # 1.0/0.0 and silently produce maximum/zero trust from a malformed bool.
        if isinstance(v, bool):
            raise ValueError("score must not be a bool")
        return v

    @field_validator("score_dimensions", mode="before")
    @classmethod
    def reject_bool_dimension_values(cls, v: Any) -> Any:
        # Same reasoning as reject_bool_score, applied to each dimension value.
        if isinstance(v, dict):
            for name, score in v.items():
                if isinstance(score, bool):
                    raise ValueError(
                        f"score_dimensions['{name}'] must not be a bool"
                    )
        return v

    @field_validator("score_dimensions")
    @classmethod
    def validate_dimension_ranges(
        cls, v: Optional[Dict[str, float]]
    ) -> Optional[Dict[str, float]]:
        if v is None:
            return v
        for name, score in v.items():
            if not isinstance(name, str) or not name:
                raise ValueError("score_dimensions keys must be non-empty strings")
            if not math.isfinite(score):
                raise ValueError(
                    f"score_dimensions['{name}']={score} is not a finite number"
                )
            if score < 0.0 or score > 1.0:
                raise ValueError(
                    f"score_dimensions['{name}']={score} is outside [0.0, 1.0]"
                )
        return v

    @model_validator(mode="after")
    def validate_at_least_one_score(self) -> "TrustAttributeRecord":
        if self.score is None and not self.score_dimensions:
            raise ValueError(
                "TrustAttributeRecord requires at least one of "
                "'score' or 'score_dimensions'"
            )
        return self


class TrustScoreExporter(ABC):
    """
    Base abstraction that providers implement to export trust scores as
    normalized ``TrustAttributeRecord`` instances.

    Implementations are responsible for fetching/computing their own scores;
    this class only defines the surface and a freshness helper so consumers
    can reason about staleness uniformly across providers.
    """

    @property
    @abstractmethod
    def provider_key(self) -> str:
        """Stable identifier for the provider this exporter represents."""

    @abstractmethod
    def export(self, subject_did: str) -> TrustAttributeRecord:
        """
        Return a ``TrustAttributeRecord`` for the given subject DID.

        Implementations should populate ``provider`` with ``self.provider_key``
        and set ``updated_at`` to the time the underlying scores were computed.
        """

    def is_fresh(
        self,
        record: TrustAttributeRecord,
        *,
        now: Optional[datetime] = None,
    ) -> bool:
        """
        Return whether ``record`` is still within its freshness budget.

        If ``record.max_age_seconds`` is ``None``, the record is treated as
        having no provider-declared expiry and is always considered fresh.

        Raises ``ValueError`` if ``now`` is provided as a naive datetime,
        to prevent silent mismatches against the timezone-aware
        ``record.updated_at``.
        """
        if record.max_age_seconds is None:
            return True
        if now is None:
            reference = _utc_now()
        else:
            if now.tzinfo is None or now.tzinfo.utcoffset(now) is None:
                raise ValueError("is_fresh() requires a timezone-aware 'now'")
            reference = now
        age = reference - record.updated_at
        return age <= timedelta(seconds=record.max_age_seconds)
