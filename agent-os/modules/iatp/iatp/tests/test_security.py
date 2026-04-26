# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""
Unit tests for IATP security module.
"""
from iatp.models import (
    AgentCapabilities,
    CapabilityManifest,
    PrivacyContract,
    RetentionPolicy,
    ReversibilityLevel,
    TrustLevel,
)
from iatp.security import PrivacyScrubber, SecurityValidator


def test_detect_credit_card():
    """Test credit card detection with Luhn validation."""
    validator = SecurityValidator()

    # Test various credit card formats (using valid test card numbers)
    # 4532015112830366 is a valid test Visa card that passes Luhn check
    payload1 = {"data": "My card is 4532-0151-1283-0366"}
    sensitive1 = validator.detect_sensitive_data(payload1)
    assert "credit_card" in sensitive1

    payload2 = {"data": "My card is 4532 0151 1283 0366"}
    sensitive2 = validator.detect_sensitive_data(payload2)
    assert "credit_card" in sensitive2

    payload3 = {"data": "My card is 4532015112830366"}
    sensitive3 = validator.detect_sensitive_data(payload3)
    assert "credit_card" in sensitive3

    # Test with invalid card number (should not be detected)
    payload4 = {"data": "My card is 1234-5678-9012-3456"}
    sensitive4 = validator.detect_sensitive_data(payload4)
    assert "credit_card" not in sensitive4


def test_detect_ssn():
    """Test SSN detection."""
    validator = SecurityValidator()

    payload = {"data": "My SSN is 123-45-6789"}
    sensitive = validator.detect_sensitive_data(payload)
    assert "ssn" in sensitive


def test_detect_email():
    """Test email detection."""
    validator = SecurityValidator()

    payload = {"data": "Contact me at test@example.com"}
    sensitive = validator.detect_sensitive_data(payload)
    assert "email" in sensitive


def test_validate_privacy_policy_blocks_credit_card_forever():
    """Test that credit cards are blocked for permanent retention."""
    validator = SecurityValidator()
    manifest = CapabilityManifest(
        agent_id="bad-agent",
        trust_level=TrustLevel.UNTRUSTED,
        capabilities=AgentCapabilities(),
        privacy_contract=PrivacyContract(
            retention=RetentionPolicy.FOREVER
        )
    )

    payload = {"credit_card": "4532-0151-1283-0366"}  # Valid test card
    is_valid, error = validator.validate_privacy_policy(manifest, payload)

    assert not is_valid
    assert "Privacy Violation" in error
    assert "credit card" in error.lower()


def test_validate_privacy_policy_allows_credit_card_ephemeral():
    """Test that credit cards are allowed for ephemeral retention."""
    validator = SecurityValidator()
    manifest = CapabilityManifest(
        agent_id="good-agent",
        trust_level=TrustLevel.VERIFIED_PARTNER,
        capabilities=AgentCapabilities(),
        privacy_contract=PrivacyContract(
            retention=RetentionPolicy.EPHEMERAL
        )
    )

    payload = {"credit_card": "4532-0151-1283-0366"}  # Valid test card
    is_valid, error = validator.validate_privacy_policy(manifest, payload)

    assert is_valid
    assert error is None


def test_validate_privacy_policy_blocks_ssn_non_ephemeral():
    """Test that SSN is blocked for non-ephemeral retention."""
    validator = SecurityValidator()
    manifest = CapabilityManifest(
        agent_id="medium-agent",
        trust_level=TrustLevel.STANDARD,
        capabilities=AgentCapabilities(),
        privacy_contract=PrivacyContract(
            retention=RetentionPolicy.TEMPORARY
        )
    )

    payload = {"ssn": "123-45-6789"}
    is_valid, error = validator.validate_privacy_policy(manifest, payload)

    assert not is_valid
    assert "SSN" in error


def test_generate_warning_low_trust():
    """Test warning generation for low trust agents."""
    validator = SecurityValidator()
    manifest = CapabilityManifest(
        agent_id="sketchy-agent",
        trust_level=TrustLevel.UNTRUSTED,
        capabilities=AgentCapabilities(
            idempotency=False,
            reversibility=ReversibilityLevel.NONE
        ),
        privacy_contract=PrivacyContract(
            retention=RetentionPolicy.FOREVER,
            human_review=True
        )
    )

    warning = validator.generate_warning_message(manifest, {})

    assert warning is not None
    assert "Low trust score" in warning
    assert "does not support transaction reversal" in warning
    assert "stores data indefinitely" in warning
    assert "may have humans review your data" in warning


def test_generate_warning_trusted_agent():
    """Test that no warning is generated for trusted agents."""
    validator = SecurityValidator()
    manifest = CapabilityManifest(
        agent_id="trusted-agent",
        trust_level=TrustLevel.VERIFIED_PARTNER,
        capabilities=AgentCapabilities(
            idempotency=True,
            reversibility=ReversibilityLevel.FULL
        ),
        privacy_contract=PrivacyContract(
            retention=RetentionPolicy.EPHEMERAL,
            human_review=False
        )
    )

    warning = validator.generate_warning_message(manifest, {})
    assert warning is None


def test_should_quarantine_untrusted():
    """Test quarantine decision for untrusted agents."""
    validator = SecurityValidator()
    manifest = CapabilityManifest(
        agent_id="untrusted-agent",
        trust_level=TrustLevel.UNTRUSTED,
        capabilities=AgentCapabilities(),
        privacy_contract=PrivacyContract(
            retention=RetentionPolicy.EPHEMERAL
        )
    )

    assert validator.should_quarantine(manifest)


def test_should_quarantine_no_reversibility_permanent():
    """Test quarantine for no reversibility and permanent storage."""
    validator = SecurityValidator()
    manifest = CapabilityManifest(
        agent_id="risky-agent",
        trust_level=TrustLevel.STANDARD,
        capabilities=AgentCapabilities(
            reversibility=ReversibilityLevel.NONE
        ),
        privacy_contract=PrivacyContract(
            retention=RetentionPolicy.FOREVER
        )
    )

    assert validator.should_quarantine(manifest)


def test_scrub_credit_card():
    """Test scrubbing credit card from payload."""
    payload = {
        "user": "john",
        "payment": {
            "card": "4532-0151-1283-0366",  # Valid test card
            "cvv": "123"
        }
    }

    scrubbed = PrivacyScrubber.scrub_payload(payload)

    scrubbed_str = str(scrubbed)
    assert "4532-0151-1283-0366" not in scrubbed_str
    assert "[CREDIT_CARD_REDACTED]" in scrubbed_str


def test_scrub_ssn():
    """Test scrubbing SSN from payload."""
    payload = {
        "user": "john",
        "ssn": "123-45-6789"
    }

    scrubbed = PrivacyScrubber.scrub_payload(payload)

    scrubbed_str = str(scrubbed)
    assert "123-45-6789" not in scrubbed_str
    assert "[SSN_REDACTED]" in scrubbed_str
