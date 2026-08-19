# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""Tests for HIPAA PHI patterns."""

import pytest
from agent_os.credential_redactor import CredentialRedactor

@pytest.mark.parametrize(
    ("text", "expected_match"),
    [
        # MRN cases
        ("Patient MRN: A123456789", "Medical Record Number (MRN)"),
        ("medical record # Z987654", "Medical Record Number (MRN)"),
        ("MRN-123456", "Medical Record Number (MRN)"),
        
        # NPI cases (1234567893 is a valid NPI)
        ("Provider NPI: 1234567893", "National Provider Identifier (NPI)"),
        ("npi 1234567893", "National Provider Identifier (NPI)"),
        ("provider-id # 1234567893", "National Provider Identifier (NPI)"),
        
        # Health Plan ID cases
        ("Member ID: ABC12345678", "Health Plan ID"),
        ("hpid # 999888777", "Health Plan ID"),
        ("policy-id: X1234567890", "Health Plan ID"),
    ],
)
def test_detects_valid_hipaa_patterns(text, expected_match):
    matches = CredentialRedactor.find_pii_matches(text)
    assert any(m.name == expected_match for m in matches)

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
        "MRN: A123456789012345", # Too long
    ],
)
def test_avoids_hipaa_false_positives(text):
    matches = CredentialRedactor.find_pii_matches(text)
    # Ensure none of the HIPAA patterns matched
    hipaa_names = {
        "Medical Record Number (MRN)",
        "National Provider Identifier (NPI)",
        "Health Plan ID",
    }
    assert not any(m.name in hipaa_names for m in matches)
