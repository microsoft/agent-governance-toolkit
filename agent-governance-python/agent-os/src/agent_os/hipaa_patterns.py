# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""HIPAA PHI patterns for the credential redactor."""

import re

def is_valid_npi(npi: str) -> bool:
    """Check if a 10-digit string is a valid NPI using the Luhn algorithm.

    The NPI check digit calculation uses the 80840 prefix.
    """
    if not npi or not npi.isdigit() or len(npi) != 10:
        return False

    # Standard NPI Luhn check includes the '80840' prefix
    # 80840 is the ISO identifier for US health identifiers.
    full_npi = "80840" + npi

    digits = [int(d) for d in full_npi]
    # Luhn algorithm
    checksum = 0
    for i, digit in enumerate(reversed(digits)):
        if i % 2 == 1:
            digit *= 2
            if digit > 9:
                digit -= 9
        checksum += digit

    return checksum % 10 == 0

def validate_npi_match(match: re.Match[str]) -> bool:
    """Validator for NPI matches that extracts digits and checks Luhn."""
    # Extract just the digits from the match
    text = match.group(0)
    digits = "".join(re.findall(r"\d", text))
    # We expect exactly 10 digits for a valid NPI
    if len(digits) != 10:
        return False
    return is_valid_npi(digits)

# We define the raw patterns here as tuples of (name, regex_string, [optional_validator])
# to avoid a circular dependency with credential_redactor.py.
# The CredentialRedactor will instantiate these as CredentialPattern objects.
HIPAA_PHI_RAW_PATTERNS = (
    (
        "Medical Record Number (MRN)",
        r"(?i)(?<![A-Za-z0-9])(?:mrn|medical\s*record)[\s#:-]*([A-Z0-9]{6,12})(?![A-Za-z0-9])",
    ),
    (
        "National Provider Identifier (NPI)",
        r"(?i)(?<![0-9])(?:npi|provider[_-]?id)[\s#:-]*(\d{10})(?![0-9])",
        validate_npi_match,
    ),
    (
        "Health Plan ID",
        r"(?i)(?<![A-Za-z0-9])(?:hpid|member\s*id|policy[_-]?id)[\s#:-]*([A-Z0-9]{8,15})(?![A-Za-z0-9])",
    ),
)
