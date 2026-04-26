# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""
Tests for the IATP Recovery Engine (scak integration).
"""
import pytest

from iatp.models import (
    AgentCapabilities,
    CapabilityManifest,
    PrivacyContract,
    RetentionPolicy,
    ReversibilityLevel,
    TrustLevel,
)
from iatp.recovery import IATPRecoveryEngine


@pytest.mark.asyncio
async def test_recovery_engine_initialization():
    """Test that recovery engine initializes correctly."""
    engine = IATPRecoveryEngine()
    assert engine is not None
    assert engine.recovery_history == {}


@pytest.mark.asyncio
async def test_handle_failure_with_reversibility():
    """Test handling failure with reversible agent."""
    engine = IATPRecoveryEngine()

    manifest = CapabilityManifest(
        agent_id="reversible-agent",
        trust_level=TrustLevel.TRUSTED,
        capabilities=AgentCapabilities(
            idempotency=True,
            reversibility=ReversibilityLevel.FULL,
        ),
        privacy_contract=PrivacyContract(
            retention=RetentionPolicy.EPHEMERAL,
            human_review=False,
        )
    )

    error = Exception("Test error")
    payload = {"test": "data"}

    # Test without compensation callback
    result = await engine.handle_failure(
        trace_id="test-trace-1",
        error=error,
        manifest=manifest,
        payload=payload,
        compensation_callback=None
    )

    assert result is not None
    assert "strategy" in result
    assert "trace_id" in result
    assert result["trace_id"] == "test-trace-1"


@pytest.mark.asyncio
async def test_handle_failure_with_compensation():
    """Test handling failure with compensation callback."""
    engine = IATPRecoveryEngine()

    manifest = CapabilityManifest(
        agent_id="compensating-agent",
        trust_level=TrustLevel.TRUSTED,
        capabilities=AgentCapabilities(
            idempotency=True,
            reversibility=ReversibilityLevel.FULL,
        ),
        privacy_contract=PrivacyContract(
            retention=RetentionPolicy.EPHEMERAL,
            human_review=False,
        )
    )

    compensation_called = False

    async def compensation_callback():
        nonlocal compensation_called
        compensation_called = True

    error = Exception("Test error")
    payload = {"test": "data"}

    result = await engine.handle_failure(
        trace_id="test-trace-2",
        error=error,
        manifest=manifest,
        payload=payload,
        compensation_callback=compensation_callback
    )

    assert result is not None
    assert compensation_called is True
    assert result["success"] is True
    assert "compensation_executed" in result["actions_taken"]


@pytest.mark.asyncio
async def test_handle_failure_no_reversibility():
    """Test handling failure with non-reversible agent."""
    engine = IATPRecoveryEngine()

    manifest = CapabilityManifest(
        agent_id="non-reversible-agent",
        trust_level=TrustLevel.STANDARD,
        capabilities=AgentCapabilities(
            idempotency=False,
            reversibility=ReversibilityLevel.NONE,
        ),
        privacy_contract=PrivacyContract(
            retention=RetentionPolicy.TEMPORARY,
            human_review=False,
        )
    )

    error = Exception("Test error")
    payload = {"test": "data"}

    result = await engine.handle_failure(
        trace_id="test-trace-3",
        error=error,
        manifest=manifest,
        payload=payload,
        compensation_callback=None
    )

    assert result is not None
    assert result["success"] is False
    # Should give up or recommend retry
    assert "strategy" in result


def test_should_attempt_recovery_reversible():
    """Test recovery attempt decision for reversible agent."""
    engine = IATPRecoveryEngine()

    manifest = CapabilityManifest(
        agent_id="reversible-agent",
        trust_level=TrustLevel.TRUSTED,
        capabilities=AgentCapabilities(
            idempotency=True,
            reversibility=ReversibilityLevel.FULL,
        ),
        privacy_contract=PrivacyContract(
            retention=RetentionPolicy.EPHEMERAL,
            human_review=False,
        )
    )

    error = Exception("Test error")

    should_recover = engine.should_attempt_recovery(error, manifest)

    assert should_recover is True


def test_should_attempt_recovery_timeout():
    """Test recovery attempt decision for timeout error."""
    engine = IATPRecoveryEngine()

    manifest = CapabilityManifest(
        agent_id="non-reversible-agent",
        trust_level=TrustLevel.STANDARD,
        capabilities=AgentCapabilities(
            idempotency=False,
            reversibility=ReversibilityLevel.NONE,
        ),
        privacy_contract=PrivacyContract(
            retention=RetentionPolicy.TEMPORARY,
            human_review=False,
        )
    )

    error = TimeoutError("Request timeout")

    should_recover = engine.should_attempt_recovery(error, manifest)

    # Should attempt recovery for timeout even without reversibility
    assert should_recover is True


def test_get_recovery_history():
    """Test retrieval of recovery history."""
    engine = IATPRecoveryEngine()

    # Add some history manually
    engine.recovery_history["test-trace"] = {
        "test": "data"
    }

    history = engine.get_recovery_history("test-trace")

    assert history is not None
    assert history["test"] == "data"

    # Non-existent trace
    missing_history = engine.get_recovery_history("non-existent")
    assert missing_history is None


@pytest.mark.asyncio
async def test_handle_failure_compensation_exception():
    """Test handling failure when compensation callback raises exception."""
    engine = IATPRecoveryEngine()

    manifest = CapabilityManifest(
        agent_id="failing-compensation-agent",
        trust_level=TrustLevel.TRUSTED,
        capabilities=AgentCapabilities(
            idempotency=True,
            reversibility=ReversibilityLevel.FULL,
        ),
        privacy_contract=PrivacyContract(
            retention=RetentionPolicy.EPHEMERAL,
            human_review=False,
        )
    )

    async def failing_compensation():
        raise Exception("Compensation failed")

    error = Exception("Test error")
    payload = {"test": "data"}

    result = await engine.handle_failure(
        trace_id="test-trace-4",
        error=error,
        manifest=manifest,
        payload=payload,
        compensation_callback=failing_compensation
    )

    assert result is not None
    assert result["success"] is False
    assert any("compensation_failed" in action for action in result["actions_taken"])


@pytest.mark.asyncio
async def test_handle_failure_sync_callback():
    """Test handling failure with synchronous compensation callback."""
    engine = IATPRecoveryEngine()

    manifest = CapabilityManifest(
        agent_id="sync-compensation-agent",
        trust_level=TrustLevel.TRUSTED,
        capabilities=AgentCapabilities(
            idempotency=True,
            reversibility=ReversibilityLevel.FULL,
        ),
        privacy_contract=PrivacyContract(
            retention=RetentionPolicy.EPHEMERAL,
            human_review=False,
        )
    )

    compensation_called = False

    def sync_compensation():
        nonlocal compensation_called
        compensation_called = True

    error = Exception("Test error")
    payload = {"test": "data"}

    result = await engine.handle_failure(
        trace_id="test-trace-5",
        error=error,
        manifest=manifest,
        payload=payload,
        compensation_callback=sync_compensation
    )

    assert result is not None
    assert compensation_called is True
    assert result["success"] is True
