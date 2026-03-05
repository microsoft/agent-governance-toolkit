# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""
Unit tests for IATP attestation and reputation system.
"""
from iatp.attestation import AttestationValidator, ReputationManager
from iatp.models import (
    AttestationRecord,
    ReputationEvent,
    ReputationScore,
    TrustLevel,
)
from iatp.telemetry import _get_utc_timestamp


def test_attestation_record_creation():
    """Test creating an attestation record."""
    attestation = AttestationRecord(
        agent_id="test-agent",
        codebase_hash="abc123def456",
        config_hash="789xyz",
        signature="base64_signature",
        signing_key_id="control-plane-key-1",
        timestamp="2026-01-25T10:00:00Z",
        expires_at="2026-01-26T10:00:00Z"
    )

    assert attestation.agent_id == "test-agent"
    assert attestation.codebase_hash == "abc123def456"
    assert not attestation.is_expired("2026-01-25T12:00:00Z")
    assert attestation.is_expired("2026-01-27T10:00:00Z")


def test_attestation_validator_add_key():
    """Test adding a trusted public key."""
    validator = AttestationValidator()
    validator.add_trusted_key("key-1", "-----BEGIN PUBLIC KEY-----\ntest\n-----END PUBLIC KEY-----")

    assert "key-1" in validator.public_keys


def test_attestation_validation_expired():
    """Test that expired attestations are rejected."""
    validator = AttestationValidator()
    validator.add_trusted_key("key-1", "test-public-key")

    # Create expired attestation
    attestation = AttestationRecord(
        agent_id="test-agent",
        codebase_hash="abc123",
        config_hash="def456",
        signature="sig",
        signing_key_id="key-1",
        timestamp="2026-01-20T10:00:00Z",
        expires_at="2026-01-21T10:00:00Z"  # Already expired
    )

    is_valid, error = validator.validate_attestation(attestation, verify_signature=False)
    assert not is_valid
    assert "expired" in error.lower()


def test_attestation_validation_unknown_key():
    """Test that attestations with unknown keys are rejected."""
    validator = AttestationValidator()

    attestation = AttestationRecord(
        agent_id="test-agent",
        codebase_hash="abc123",
        config_hash="def456",
        signature="sig",
        signing_key_id="unknown-key",
        timestamp=_get_utc_timestamp(),
        expires_at=None
    )

    is_valid, error = validator.validate_attestation(attestation, verify_signature=False)
    assert not is_valid
    assert "unknown signing key" in error.lower()


def test_attestation_validation_success():
    """Test successful attestation validation."""
    validator = AttestationValidator()
    validator.add_trusted_key("key-1", "test-public-key")

    attestation = AttestationRecord(
        agent_id="test-agent",
        codebase_hash="abc123",
        config_hash="def456",
        signature="sig",
        signing_key_id="key-1",
        timestamp=_get_utc_timestamp(),
        expires_at=None
    )

    is_valid, error = validator.validate_attestation(attestation, verify_signature=False)
    assert is_valid
    assert error is None
    assert attestation.agent_id in validator.attestation_cache


def test_attestation_create():
    """Test creating an attestation."""
    validator = AttestationValidator()

    attestation = validator.create_attestation(
        agent_id="test-agent",
        codebase_hash="abc123",
        config_hash="def456",
        signing_key_id="key-1",
        expires_in_hours=24
    )

    assert attestation.agent_id == "test-agent"
    assert attestation.codebase_hash == "abc123"
    assert attestation.config_hash == "def456"
    assert attestation.expires_at is not None


def test_compute_codebase_hash():
    """Test computing codebase hash."""
    validator = AttestationValidator()

    hash1 = validator.compute_codebase_hash("test content")
    hash2 = validator.compute_codebase_hash("test content")
    hash3 = validator.compute_codebase_hash("different content")

    assert hash1 == hash2
    assert hash1 != hash3
    assert len(hash1) == 64  # SHA-256 produces 64 hex characters


def test_reputation_score_creation():
    """Test creating a reputation score."""
    score = ReputationScore(
        agent_id="test-agent",
        score=5.0,
        initial_score=5.0,
        last_updated=_get_utc_timestamp()
    )

    assert score.agent_id == "test-agent"
    assert score.score == 5.0
    assert score.total_events == 0


def test_reputation_event_application():
    """Test applying reputation events."""
    score = ReputationScore(
        agent_id="test-agent",
        score=5.0,
        initial_score=5.0,
        last_updated=_get_utc_timestamp()
    )

    # Apply negative event
    event = ReputationEvent(
        event_id="evt-1",
        agent_id="test-agent",
        event_type="hallucination",
        severity="high",
        score_delta=-1.0,
        timestamp=_get_utc_timestamp()
    )
    score.apply_event(event)

    assert score.score == 4.0
    assert score.total_events == 1
    assert score.negative_events == 1
    assert len(score.recent_events) == 1


def test_reputation_score_clamping():
    """Test that reputation scores are clamped to 0-10."""
    score = ReputationScore(
        agent_id="test-agent",
        score=1.0,
        initial_score=5.0,
        last_updated=_get_utc_timestamp()
    )

    # Try to go below 0
    event = ReputationEvent(
        event_id="evt-1",
        agent_id="test-agent",
        event_type="hallucination",
        severity="critical",
        score_delta=-5.0,
        timestamp=_get_utc_timestamp()
    )
    score.apply_event(event)

    assert score.score == 0.0  # Clamped to minimum

    # Try to go above 10
    for i in range(20):
        event = ReputationEvent(
            event_id=f"evt-{i}",
            agent_id="test-agent",
            event_type="success",
            severity="low",
            score_delta=1.0,
            timestamp=_get_utc_timestamp()
        )
        score.apply_event(event)

    assert score.score == 10.0  # Clamped to maximum


def test_reputation_trust_level_mapping():
    """Test conversion from reputation score to trust level."""
    score = ReputationScore(
        agent_id="test-agent",
        score=9.0,
        initial_score=5.0,
        last_updated=_get_utc_timestamp()
    )

    assert score.get_trust_level() == TrustLevel.VERIFIED_PARTNER

    score.score = 7.0
    assert score.get_trust_level() == TrustLevel.TRUSTED

    score.score = 5.0
    assert score.get_trust_level() == TrustLevel.STANDARD

    score.score = 3.0
    assert score.get_trust_level() == TrustLevel.UNKNOWN

    score.score = 1.0
    assert score.get_trust_level() == TrustLevel.UNTRUSTED


def test_reputation_manager_hallucination():
    """Test recording hallucination with reputation manager."""
    manager = ReputationManager()

    score = manager.record_hallucination(
        agent_id="bad-agent",
        severity="high",
        trace_id="trace-123",
        details={"reason": "generated fake data"}
    )

    assert score.score < 5.0  # Score should be reduced
    assert score.negative_events == 1
    assert len(score.recent_events) == 1
    assert score.recent_events[0].event_type == "hallucination"
    assert score.recent_events[0].detected_by == "cmvk"


def test_reputation_manager_success():
    """Test recording successful transaction."""
    manager = ReputationManager()

    score = manager.record_success(
        agent_id="good-agent",
        trace_id="trace-123"
    )

    assert score.score > 5.0  # Score should improve
    assert score.positive_events == 1


def test_reputation_manager_failure():
    """Test recording failure."""
    manager = ReputationManager()

    score = manager.record_failure(
        agent_id="flaky-agent",
        failure_type="timeout",
        trace_id="trace-123",
        details={"timeout_seconds": 30}
    )

    assert score.score < 5.0  # Score should decrease
    assert score.negative_events == 1


def test_reputation_manager_multiple_events():
    """Test multiple reputation events."""
    manager = ReputationManager()

    # Start with successes
    for i in range(5):
        manager.record_success("stable-agent", trace_id=f"trace-{i}")

    score = manager.get_score("stable-agent")
    assert score.score > 5.0

    # Now have some failures
    for i in range(2):
        manager.record_hallucination("stable-agent", severity="medium")

    score = manager.get_score("stable-agent")
    assert score.total_events == 7
    assert score.positive_events == 5
    assert score.negative_events == 2


def test_reputation_export_import():
    """Test exporting and importing reputation data."""
    manager1 = ReputationManager()
    manager1.record_hallucination("agent-1", severity="high")
    manager1.record_success("agent-2")

    # Export from manager1
    data = manager1.export_reputation_data()
    assert "agent-1" in data
    assert "agent-2" in data

    # Import to manager2
    manager2 = ReputationManager()
    manager2.import_reputation_data(data)

    assert manager2.get_score("agent-1") is not None
    assert manager2.get_score("agent-2") is not None


def test_reputation_import_merge():
    """Test that importing takes the lower (more conservative) score."""
    manager1 = ReputationManager()
    manager1.get_or_create_score("agent-1").score = 8.0

    # Import data with lower score
    import_data = {
        "agent-1": {
            "agent_id": "agent-1",
            "score": 3.0,
            "initial_score": 5.0,
            "total_events": 0,
            "positive_events": 0,
            "negative_events": 0,
            "last_updated": _get_utc_timestamp(),
            "recent_events": []
        }
    }

    manager1.import_reputation_data(import_data)

    # Should take the lower score
    assert manager1.get_score("agent-1").score == 3.0


def test_reputation_recent_events_limit():
    """Test that recent events are limited to 100."""
    score = ReputationScore(
        agent_id="test-agent",
        score=5.0,
        initial_score=5.0,
        last_updated=_get_utc_timestamp()
    )

    # Add 150 events
    for i in range(150):
        event = ReputationEvent(
            event_id=f"evt-{i}",
            agent_id="test-agent",
            event_type="success",
            severity="low",
            score_delta=0.01,
            timestamp=_get_utc_timestamp()
        )
        score.apply_event(event)

    # Should only keep last 100
    assert len(score.recent_events) == 100
    # Should have the most recent ones
    assert score.recent_events[-1].event_id == "evt-149"
