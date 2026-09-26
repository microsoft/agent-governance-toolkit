# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""HIPAA PHI patterns for the credential redactor."""

import re

_IDENTIFIER_VALUE_SEPARATOR = r"[ \t\r\n_#:-]+"


def _build_contextual_identifier_pattern(cue: str, min_length: int, max_length: int) -> str:
    """Build an identifier pattern with a strict separator for letter-prefixed values."""
    digits_only = rf"\d{{{min_length},{max_length}}}"
    alphanumeric = rf"[A-Z](?=[A-Z0-9]*\d)[A-Z0-9]{{{min_length - 1},{max_length - 1}}}"
    return (
        rf"(?i)(?<![A-Za-z0-9])(?:{cue})"
        rf"(?:{_IDENTIFIER_VALUE_SEPARATOR}(?:{alphanumeric}|{digits_only})|{digits_only})"
        rf"(?![A-Za-z0-9])"
    )


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
        _build_contextual_identifier_pattern(r"mrn|medical[\s_-]*record", 6, 12),
    ),
    (
        "National Provider Identifier (NPI)",
        r"(?i)(?<![0-9])(?:npi|provider[\s_-]*id)[\s#:-]*(\d{10})(?![0-9])",
        validate_npi_match,
    ),
    (
        "Health Plan ID",
        _build_contextual_identifier_pattern(
            r"hpid|health[\s_-]*plan|member[\s_-]*(?:id|identification)|policy[\s_-]*id",
            8,
            15,
        ),
    ),
)
