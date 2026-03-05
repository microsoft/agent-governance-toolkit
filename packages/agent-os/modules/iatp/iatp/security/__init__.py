# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""
Security and privacy validation logic.
"""
import re
from typing import Any, Dict, List, Optional, Tuple

from iatp.attestation import AttestationValidator
from iatp.models import (
    AttestationRecord,
    CapabilityManifest,
    RetentionPolicy,
    ReversibilityLevel,
    TrustLevel,
)


def _luhn_check(card_number: str) -> bool:
    """
    Validate a credit card number using the Luhn algorithm.

    Args:
        card_number: String of digits (spaces/dashes already removed)

    Returns:
        bool: True if valid according to Luhn algorithm
    """
    if not card_number.isdigit() or len(card_number) < 13:
        return False

    # Luhn algorithm
    digits = [int(d) for d in card_number]
    checksum = 0

    # Double every second digit from right to left
    for i in range(len(digits) - 2, -1, -2):
        doubled = digits[i] * 2
        checksum += doubled if doubled < 10 else doubled - 9

    # Add remaining digits
    for i in range(len(digits) - 1, -1, -2):
        checksum += digits[i]

    return checksum % 10 == 0


class SecurityValidator:
    """Validates requests against capability manifests and security policies."""

    # Patterns for detecting sensitive data
    CREDIT_CARD_PATTERN = re.compile(r'\b\d{4}[\s-]?\d{4}[\s-]?\d{4}[\s-]?\d{4}\b')
    SSN_PATTERN = re.compile(r'\b\d{3}-\d{2}-\d{4}\b')
    EMAIL_PATTERN = re.compile(r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b')

    def __init__(self):
        self.blocked_requests = []
        self.warnings = []
        self.attestation_validator = AttestationValidator()

    def validate_attestation(
        self,
        attestation: AttestationRecord,
        verify_signature: bool = True
    ) -> Tuple[bool, Optional[str]]:
        """
        Validate an agent attestation record.

        This ensures the agent is running verified code and not a hacked version.

        Args:
            attestation: The attestation record from the agent
            verify_signature: Whether to verify cryptographic signature

        Returns:
            Tuple of (is_valid, error_message)
        """
        return self.attestation_validator.validate_attestation(
            attestation, verify_signature=verify_signature
        )

    def detect_sensitive_data(self, payload: Dict[str, Any]) -> List[str]:
        """
        Detect sensitive data in the request payload.
        Uses Luhn algorithm to validate credit card numbers.
        Returns a list of detected sensitive data types.
        """
        sensitive_types = []
        payload_str = str(payload)

        # Check for credit cards with Luhn validation
        card_matches = self.CREDIT_CARD_PATTERN.finditer(payload_str)
        for match in card_matches:
            card_number = match.group().replace(' ', '').replace('-', '')
            if _luhn_check(card_number):
                sensitive_types.append("credit_card")
                break  # Only need to detect once

        if self.SSN_PATTERN.search(payload_str):
            sensitive_types.append("ssn")
        # Email is less sensitive but still PII
        if self.EMAIL_PATTERN.search(payload_str):
            sensitive_types.append("email")

        return sensitive_types

    def validate_privacy_policy(
        self,
        manifest: CapabilityManifest,
        payload: Dict[str, Any]
    ) -> Tuple[bool, Optional[str]]:
        """
        Validate that the request complies with privacy policies.

        Returns:
            Tuple of (is_valid, error_message)
            is_valid: True if request should be allowed
            error_message: Description of the violation if blocked
        """
        sensitive_data = self.detect_sensitive_data(payload)

        # Check for credit card data with permanent retention
        if "credit_card" in sensitive_data and manifest.privacy_contract.retention in [
            RetentionPolicy.PERMANENT,
            RetentionPolicy.FOREVER
        ]:
            return False, (
                f"Privacy Violation: Agent '{manifest.agent_id}' stores data "
                f"permanently and request contains credit card information. "
                f"Request blocked for security."
            )

        # Check for SSN with any non-ephemeral retention
        if "ssn" in sensitive_data:
            if manifest.privacy_contract.retention != RetentionPolicy.EPHEMERAL:
                return False, (
                    f"Privacy Violation: Agent '{manifest.agent_id}' retains data "
                    f"beyond session lifetime and request contains SSN. "
                    f"Request blocked for security."
                )

        return True, None

    def generate_warning_message(
        self,
        manifest: CapabilityManifest,
        payload: Dict[str, Any]
    ) -> Optional[str]:
        """
        Generate a warning message for risky requests that aren't blocked.
        Returns None if no warnings are needed.
        """
        warnings = []
        trust_score = manifest.calculate_trust_score()

        # Low trust score warning
        if trust_score < 5:
            warnings.append(
                f"Low trust score ({trust_score}/10) for agent '{manifest.agent_id}'"
            )

        # No reversibility warning
        if manifest.capabilities.reversibility == ReversibilityLevel.NONE:
            warnings.append(
                f"Agent '{manifest.agent_id}' does not support transaction reversal"
            )

        # No idempotency warning
        if not manifest.capabilities.idempotency:
            warnings.append(
                f"Agent '{manifest.agent_id}' may not handle duplicate requests safely"
            )

        # Data retention warning
        if manifest.privacy_contract.retention in [
            RetentionPolicy.PERMANENT,
            RetentionPolicy.FOREVER
        ]:
            warnings.append(
                f"Agent '{manifest.agent_id}' stores data indefinitely"
            )

        # Human review warning
        if manifest.privacy_contract.human_review:
            warnings.append(
                f"Agent '{manifest.agent_id}' may have humans review your data"
            )

        if warnings:
            return "⚠️  WARNING:\n" + "\n".join(f"  • {w}" for w in warnings)

        return None

    def should_quarantine(self, manifest: CapabilityManifest) -> bool:
        """
        Determine if requests to this agent should be quarantined.
        """
        trust_score = manifest.calculate_trust_score()

        # Quarantine if:
        # - Trust score is very low
        # - No reversibility and permanent storage
        # - Untrusted agent

        if trust_score < 3:
            return True

        if (manifest.capabilities.reversibility == ReversibilityLevel.NONE and
            manifest.privacy_contract.retention in [
                RetentionPolicy.PERMANENT,
                RetentionPolicy.FOREVER
            ]):
            return True

        return manifest.trust_level == TrustLevel.UNTRUSTED


class PrivacyScrubber:
    """Scrubs sensitive data from payloads before logging."""

    @staticmethod
    def scrub_payload(payload: Dict[str, Any]) -> Dict[str, Any]:
        """
        Create a scrubbed copy of the payload for logging.
        Redacts sensitive information.
        """
        scrubbed = payload.copy()

        # Convert to string for pattern matching
        payload_str = str(payload)

        # Redact credit cards
        if SecurityValidator.CREDIT_CARD_PATTERN.search(payload_str):
            scrubbed = PrivacyScrubber._redact_in_dict(
                scrubbed,
                SecurityValidator.CREDIT_CARD_PATTERN,
                "[CREDIT_CARD_REDACTED]"
            )

        # Redact SSN
        if SecurityValidator.SSN_PATTERN.search(payload_str):
            scrubbed = PrivacyScrubber._redact_in_dict(
                scrubbed,
                SecurityValidator.SSN_PATTERN,
                "[SSN_REDACTED]"
            )

        return scrubbed

    @staticmethod
    def _redact_in_dict(
        data: Any,
        pattern: re.Pattern,
        replacement: str
    ) -> Any:
        """Recursively redact patterns in dictionary."""
        if isinstance(data, dict):
            return {
                k: PrivacyScrubber._redact_in_dict(v, pattern, replacement)
                for k, v in data.items()
            }
        elif isinstance(data, list):
            return [
                PrivacyScrubber._redact_in_dict(item, pattern, replacement)
                for item in data
            ]
        elif isinstance(data, str):
            return pattern.sub(replacement, data)
        else:
            return data
