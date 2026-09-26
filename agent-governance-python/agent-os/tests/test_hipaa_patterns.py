# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""Tests for HIPAA PHI patterns."""

import pytest

from agent_os.credential_redactor import CredentialRedactor

HIPAA_NAMES = {
    "Medical Record Number (MRN)",
    "National Provider Identifier (NPI)",
    "Health Plan ID",
}


def _hipaa_matches(text: str) -> list[tuple[str, str]]:
    return [
        (match.name, match.matched_text)
        for match in CredentialRedactor.find_pii_matches(text)
        if match.name in HIPAA_NAMES
    ]


@pytest.mark.parametrize(
    ("text", "expected_name", "expected_match"),
    [
        # MRN cases
        ("Patient MRN: A123456789", "Medical Record Number (MRN)", "MRN: A123456789"),
        ("medical record # Z987654", "Medical Record Number (MRN)", "medical record # Z987654"),
        ("medical_record: Z987654", "Medical Record Number (MRN)", "medical_record: Z987654"),
        ("MRN-123456", "Medical Record Number (MRN)", "MRN-123456"),
        ("MRN: ABC123456", "Medical Record Number (MRN)", "MRN: ABC123456"),
        # NPI cases (1234567893 is a valid NPI)
        ("Provider NPI: 1234567893", "National Provider Identifier (NPI)", "NPI: 1234567893"),
        ("npi 1234567893", "National Provider Identifier (NPI)", "npi 1234567893"),
        ("provider id 1234567893", "National Provider Identifier (NPI)", "provider id 1234567893"),
        (
            "Provider ID: 1234567893",
            "National Provider Identifier (NPI)",
            "Provider ID: 1234567893",
        ),
        (
            "provider-id # 1234567893",
            "National Provider Identifier (NPI)",
            "provider-id # 1234567893",
        ),
        (
            "provider_id: 1234567893",
            "National Provider Identifier (NPI)",
            "provider_id: 1234567893",
        ),
        # Health Plan ID cases
        ("Member ID: ABC12345678", "Health Plan ID", "Member ID: ABC12345678"),
        ("member id: ABC12345678", "Health Plan ID", "member id: ABC12345678"),
        ("member_id: ABC12345678", "Health Plan ID", "member_id: ABC12345678"),
        (
            "member identification: ABC12345678",
            "Health Plan ID",
            "member identification: ABC12345678",
        ),
        ("member identification: 123456789", "Health Plan ID", "member identification: 123456789"),
        ("health plan: PLAN123456", "Health Plan ID", "health plan: PLAN123456"),
        ("hpid # 999888777", "Health Plan ID", "hpid # 999888777"),
        ("policy id X1234567890", "Health Plan ID", "policy id X1234567890"),
        ("policy-id: X1234567890", "Health Plan ID", "policy-id: X1234567890"),
        ("policy_id: X1234567890", "Health Plan ID", "policy_id: X1234567890"),
    ],
)
def test_detects_valid_hipaa_patterns(text, expected_name, expected_match):
    assert _hipaa_matches(text) == [(expected_name, expected_match)]


def test_member_identification_uses_full_health_plan_cue():
    assert _hipaa_matches("member identification: ABC12345678") == [
        ("Health Plan ID", "member identification: ABC12345678")
    ]


@pytest.mark.parametrize(
    "text",
    [
        # NPI false positives (valid digits but no context)
        "1234567893",
        "The number is 1234567893",
        # NPI invalid Luhn (even with context)
        "NPI: 1234567890",
        "provider id 1111111111",
        # Phone numbers (should NOT match NPI)
        "NPI: 555-010-9999",
        "Call 1234567890 for support",
        # MRN/HPID without context
        "A123456789",
        "Z987654",
        # Alphanumeric glue (boundary check)
        "XMRN: A123456789",
        "MRN: A123456789012345",  # Too long
        "MRN: patient 123456",
        "member id: confused",
        "policy id: alphabetic",
        "We shipped build ABC12345678 to staging.",
    ],
)
def test_avoids_hipaa_false_positives(text):
    assert _hipaa_matches(text) == []
