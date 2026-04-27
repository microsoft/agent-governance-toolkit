# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""Tests for the provider-agnostic trust score exporter."""
from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import Optional

import pytest
from pydantic import ValidationError

from agentmesh.trust import TrustAttributeRecord, TrustScoreExporter


SUBJECT_DID = "did:mesh:subject"


def _record(**overrides) -> TrustAttributeRecord:
    """Build a minimal valid record, allowing per-test overrides."""
    base = {
        "provider": "test-provider",
        "subject_did": SUBJECT_DID,
        "score": 0.5,
    }
    base.update(overrides)
    return TrustAttributeRecord(**base)


# ---------------------------------------------------------------------------
# TrustAttributeRecord — shape & validation
# ---------------------------------------------------------------------------

class TestTrustAttributeRecord:
    def test_minimal_valid_record_with_scalar_score(self) -> None:
        r = _record()
        assert r.provider == "test-provider"
        assert r.subject_did == SUBJECT_DID
        assert r.score == 0.5
        assert r.score_dimensions is None
        assert r.max_age_seconds is None
        assert r.metadata == {}
        assert r.updated_at.tzinfo is not None

    def test_minimal_valid_record_with_dimensions_only(self) -> None:
        r = _record(score=None, score_dimensions={"reliability": 0.8})
        assert r.score is None
        assert r.score_dimensions == {"reliability": 0.8}

    def test_at_least_one_score_required(self) -> None:
        with pytest.raises(ValidationError):
            TrustAttributeRecord(
                provider="p",
                subject_did=SUBJECT_DID,
            )

    def test_empty_score_dimensions_does_not_satisfy_at_least_one(self) -> None:
        with pytest.raises(ValidationError):
            TrustAttributeRecord(
                provider="p",
                subject_did=SUBJECT_DID,
                score_dimensions={},
            )

    def test_provider_must_be_non_empty(self) -> None:
        with pytest.raises(ValidationError):
            _record(provider="")

    def test_subject_did_must_be_non_empty(self) -> None:
        with pytest.raises(ValidationError):
            _record(subject_did="")

    def test_score_above_one_raises(self) -> None:
        with pytest.raises(ValidationError):
            _record(score=1.5)

    def test_score_below_zero_raises(self) -> None:
        with pytest.raises(ValidationError):
            _record(score=-0.1)

    def test_score_dimension_value_above_one_raises(self) -> None:
        with pytest.raises(ValidationError):
            _record(score=None, score_dimensions={"reliability": 1.2})

    def test_score_dimension_value_below_zero_raises(self) -> None:
        with pytest.raises(ValidationError):
            _record(score=None, score_dimensions={"reliability": -0.01})

    def test_score_dimension_empty_key_raises(self) -> None:
        with pytest.raises(ValidationError):
            _record(score=None, score_dimensions={"": 0.5})

    def test_max_age_seconds_must_be_positive(self) -> None:
        with pytest.raises(ValidationError):
            _record(max_age_seconds=0)
        with pytest.raises(ValidationError):
            _record(max_age_seconds=-1)

    def test_updated_at_explicit_none_raises(self) -> None:
        with pytest.raises(ValidationError):
            _record(updated_at=None)

    def test_updated_at_naive_raises(self) -> None:
        naive = datetime(2026, 4, 27, 12, 0, 0)
        assert naive.tzinfo is None
        with pytest.raises(ValidationError):
            _record(updated_at=naive)

    def test_score_dimension_nan_raises(self) -> None:
        with pytest.raises(ValidationError):
            _record(score=None, score_dimensions={"x": float("nan")})

    def test_score_dimension_inf_raises(self) -> None:
        with pytest.raises(ValidationError):
            _record(score=None, score_dimensions={"x": float("inf")})
        with pytest.raises(ValidationError):
            _record(score=None, score_dimensions={"x": float("-inf")})

    def test_score_dimension_string_nan_raises(self) -> None:
        with pytest.raises(ValidationError):
            _record(score=None, score_dimensions={"x": "nan"})  # type: ignore[dict-item]

    def test_score_scalar_bool_rejected(self) -> None:
        with pytest.raises(ValidationError):
            _record(score=True)  # type: ignore[arg-type]
        with pytest.raises(ValidationError):
            _record(score=False)  # type: ignore[arg-type]

    def test_score_dimensions_bool_rejected(self) -> None:
        with pytest.raises(ValidationError):
            _record(
                score=None,
                score_dimensions={"x": True},  # type: ignore[dict-item]
            )
        with pytest.raises(ValidationError):
            _record(
                score=None,
                score_dimensions={"x": False},  # type: ignore[dict-item]
            )

    def test_serialization_round_trip(self) -> None:
        original = _record(
            score=0.7,
            score_dimensions={"latency": 0.9, "accuracy": 0.6},
            max_age_seconds=120,
            metadata={"region": "eu"},
        )
        as_dict = original.model_dump()
        for key in (
            "provider",
            "subject_did",
            "score",
            "score_dimensions",
            "updated_at",
            "max_age_seconds",
            "metadata",
        ):
            assert key in as_dict
        rebuilt = TrustAttributeRecord.model_validate(as_dict)
        assert rebuilt == original


# ---------------------------------------------------------------------------
# TrustScoreExporter — surface & freshness helper
# ---------------------------------------------------------------------------

class _FakeExporter(TrustScoreExporter):
    """Minimal in-test implementation; not a reference exporter."""

    def __init__(self, key: str, score: float, max_age: Optional[int] = None) -> None:
        self._key = key
        self._score = score
        self._max_age = max_age

    @property
    def provider_key(self) -> str:
        return self._key

    def export(self, subject_did: str) -> TrustAttributeRecord:
        return TrustAttributeRecord(
            provider=self._key,
            subject_did=subject_did,
            score=self._score,
            max_age_seconds=self._max_age,
        )


class TestTrustScoreExporter:
    def test_cannot_instantiate_abstract_base(self) -> None:
        with pytest.raises(TypeError):
            TrustScoreExporter()  # type: ignore[abstract]

    def test_provider_key_isolation(self) -> None:
        a = _FakeExporter("provider-a", 0.4).export(SUBJECT_DID)
        b = _FakeExporter("provider-b", 0.9).export(SUBJECT_DID)
        assert a.provider == "provider-a"
        assert b.provider == "provider-b"
        assert a != b

    def test_is_fresh_no_max_age_is_always_fresh(self) -> None:
        exporter = _FakeExporter("p", 0.5, max_age=None)
        record = exporter.export(SUBJECT_DID)
        far_future = record.updated_at + timedelta(days=365)
        assert exporter.is_fresh(record, now=far_future) is True

    def test_is_fresh_within_window(self) -> None:
        exporter = _FakeExporter("p", 0.5, max_age=60)
        record = exporter.export(SUBJECT_DID)
        now = record.updated_at + timedelta(seconds=30)
        assert exporter.is_fresh(record, now=now) is True

    def test_is_fresh_at_exact_boundary(self) -> None:
        exporter = _FakeExporter("p", 0.5, max_age=60)
        record = exporter.export(SUBJECT_DID)
        now = record.updated_at + timedelta(seconds=60)
        assert exporter.is_fresh(record, now=now) is True

    def test_is_fresh_expired(self) -> None:
        exporter = _FakeExporter("p", 0.5, max_age=60)
        record = exporter.export(SUBJECT_DID)
        now = record.updated_at + timedelta(seconds=120)
        assert exporter.is_fresh(record, now=now) is False

    def test_is_fresh_default_now_uses_utc(self) -> None:
        exporter = _FakeExporter("p", 0.5, max_age=60)
        stale = TrustAttributeRecord(
            provider="p",
            subject_did=SUBJECT_DID,
            score=0.5,
            updated_at=datetime.now(timezone.utc) - timedelta(seconds=120),
            max_age_seconds=60,
        )
        assert exporter.is_fresh(stale) is False

    def test_is_fresh_naive_now_raises(self) -> None:
        exporter = _FakeExporter("p", 0.5, max_age=60)
        record = exporter.export(SUBJECT_DID)
        naive_now = datetime(2026, 4, 27, 12, 0, 0)
        assert naive_now.tzinfo is None
        with pytest.raises(ValueError):
            exporter.is_fresh(record, now=naive_now)
