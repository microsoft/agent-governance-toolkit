# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""Tests for HIPAA PHI patterns."""

import pytest

from agent_os.credential_redactor import CredentialMatch, CredentialRedactor
from agent_os.policies.data_classification import detect_phi

PHI_NAMES = {
    "Medical Record Number (MRN)",
    "Health Plan ID",
}
HEALTHCARE_IDENTIFIER_NAMES = {"National Provider Identifier (NPI)"}
ORDINARY_PII_NAMES = {
    "Email address",
    "US phone number",
    "US SSN",
    "Credit card number",
    "IPv4 address",
}


def _hipaa_matches(text: str) -> list[tuple[str, str]]:
    return [
        (match.name, match.matched_text)
        for match in CredentialRedactor.find_pii_matches(text)
        if match.name in PHI_NAMES | HEALTHCARE_IDENTIFIER_NAMES
    ]


def _all_named_matches(text: str) -> list[tuple[str, str]]:
    return [
        (match.name, match.matched_text)
        for match in CredentialRedactor.find_pii_matches(text)
        if match.name in PHI_NAMES | HEALTHCARE_IDENTIFIER_NAMES | ORDINARY_PII_NAMES
    ]


def test_healthcare_pattern_collections_are_separate():
    assert {pattern.name for pattern in CredentialRedactor.PII_PATTERNS} == ORDINARY_PII_NAMES
    assert {pattern.name for pattern in CredentialRedactor.PHI_PATTERNS} == PHI_NAMES
    assert {pattern.name for pattern in CredentialRedactor.HEALTHCARE_IDENTIFIER_PATTERNS} == (
        HEALTHCARE_IDENTIFIER_NAMES
    )
    assert "National Provider Identifier (NPI)" not in {
        pattern.name for pattern in CredentialRedactor.PHI_PATTERNS
    }
    assert not ({pattern.name for pattern in CredentialRedactor.PII_PATTERNS} & PHI_NAMES)


@pytest.mark.parametrize(
    ("text", "expected_name", "expected_match"),
    [
        # MRN cases
        ("Patient MRN: A123456789", "Medical Record Number (MRN)", "MRN: A123456789"),
        ("medical record # Z987654", "Medical Record Number (MRN)", "medical record # Z987654"),
        ("medical_record: Z987654", "Medical Record Number (MRN)", "medical_record: Z987654"),
        ("MRN-123456", "Medical Record Number (MRN)", "MRN-123456"),
        ("MRN: ABC123456", "Medical Record Number (MRN)", "MRN: ABC123456"),
        ("mrn: A12345", "Medical Record Number (MRN)", "mrn: A12345"),
        ("medical record 123456", "Medical Record Number (MRN)", "medical record 123456"),
        ("MRN: 1a2b3c", "Medical Record Number (MRN)", "MRN: 1a2b3c"),
        # NPI cases (1234567893 is a valid NPI)
        ("Provider NPI: 1234567893", "National Provider Identifier (NPI)", "NPI: 1234567893"),
        ("NPI1234567893", "National Provider Identifier (NPI)", "NPI1234567893"),
        ("npi 1234567893", "National Provider Identifier (NPI)", "npi 1234567893"),
        ("NPI_1234567893", "National Provider Identifier (NPI)", "NPI_1234567893"),
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
        (
            "member identification: X1234567890",
            "Health Plan ID",
            "member identification: X1234567890",
        ),
        ("health plan: PLAN123456", "Health Plan ID", "health plan: PLAN123456"),
        ("health plan X1234567890", "Health Plan ID", "health plan X1234567890"),
        ("health plan id X1234567890", "Health Plan ID", "health plan id X1234567890"),
        ("health-plan_id: X1234567890", "Health Plan ID", "health-plan_id: X1234567890"),
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
    ("text", "expected_match"),
    [
        ("MRN: ABC123456", "MRN: ABC123456"),
        ("medical record: ABC123456", "medical record: ABC123456"),
        ("Patient MRN: 12345678", "MRN: 12345678"),
    ],
)
def test_data_classification_and_redactor_agree_on_valid_mrn_detection(text, expected_match):
    assert "MRN" in detect_phi(text)
    assert _hipaa_matches(text) == [("Medical Record Number (MRN)", expected_match)]


@pytest.mark.parametrize(
    ("text", "expected_match"),
    [
        ("prefixNPI: 1234567893", []),
        ("NPI: 1234567893X", []),
        ("NPI_1234567893", [("National Provider Identifier (NPI)", "NPI_1234567893")]),
    ],
)
def test_npi_boundaries_and_separators_follow_port_behavior(text, expected_match):
    assert _hipaa_matches(text) == expected_match


@pytest.mark.parametrize(
    ("text", "expected_match"),
    [
        ("MRN: ABC123456", ("Medical Record Number (MRN)", "MRN: ABC123456")),
        ("NPI: 1234567893", ("National Provider Identifier (NPI)", "NPI: 1234567893")),
        ("member id: ABC12345678", ("Health Plan ID", "member id: ABC12345678")),
        ("Email me at jane.doe@example.com", ("Email address", "jane.doe@example.com")),
        ("Call 555-123-4567 today", ("US phone number", "555-123-4567")),
    ],
)
def test_find_pii_matches_remains_backward_compatible_for_pii_and_phi(text, expected_match):
    assert expected_match in _all_named_matches(text)


def test_find_pii_matches_preserves_healthcare_then_pii_ordering():
    matches = CredentialRedactor.find_pii_matches(
        "MRN: ABC123456; NPI: 1234567893; contact jane.doe@example.com"
    )

    assert matches[:3] == [
        CredentialMatch(
            name="Medical Record Number (MRN)",
            matched_text="MRN: ABC123456",
            start=0,
            end=14,
        ),
        CredentialMatch(
            name="National Provider Identifier (NPI)",
            matched_text="NPI: 1234567893",
            start=16,
            end=31,
        ),
        CredentialMatch(
            name="Email address",
            matched_text="jane.doe@example.com",
            start=41,
            end=61,
        ),
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
        "MRN: patient",
        "MRN: ſ12345",
        "MRN: K12345",
        "MRN: İ12345",
        "MRN: 123456²",
        "MRN: 123456\u0301",
        "MRN: 123456-7",
        "MRN: 123456_more",
        "MRN: A12345_more",
        "NPI: ١٢٣٤٥٦٧٨٩٣",
        "medical\u00a0record 123456",
        "prefixNPI: 1234567893",
        "NPI: 1234567893X",
        "member id: confused",
        "health plan id confused",
        "policy id: alphabetic",
        "We shipped build ABC12345678 to staging.",
    ],
)
def test_avoids_hipaa_false_positives(text):
    assert _hipaa_matches(text) == []
