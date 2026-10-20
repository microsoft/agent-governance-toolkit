# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""HIPAA PHI patterns for the credential redactor."""

import re
import unicodedata

_IDENTIFIER_SEPARATOR_CHARS = r"[ \t\r\n_#:-]"
_IDENTIFIER_VALUE_GROUP = "value"


def _build_contextual_identifier_pattern(cue: str, min_length: int, max_length: int) -> str:
    """Build an ASCII-only contextual identifier pattern."""
    return (
        rf"(?ai)(?<![A-Za-z0-9])(?:{cue})"
        rf"{_IDENTIFIER_SEPARATOR_CHARS}*(?P<{_IDENTIFIER_VALUE_GROUP}>[a-z0-9]{{{min_length},{max_length}}})"
        rf"(?![A-Za-z0-9])"
    )


def _is_identifier_separator(character: str) -> bool:
    """Return whether *character* is an accepted cue/value separator."""
    return character in " \t\r\n_#:-"


def _has_ascii_digit(value: str) -> bool:
    """Return whether *value* contains at least one ASCII digit."""
    return any("0" <= character <= "9" for character in value)


def _has_disallowed_identifier_continuation(text: str, end: int) -> bool:
    """Reject Unicode continuation characters immediately after a matched value."""
    if end >= len(text):
        return False
    next_character = text[end]
    if next_character in "_-":
        return True
    return unicodedata.category(next_character).startswith(("L", "M", "N"))


def validate_contextual_identifier_match(match: re.Match[str]) -> bool:
    """Validate shared post-match identifier rules for MRN and health-plan IDs."""
    value = match.group(_IDENTIFIER_VALUE_GROUP)
    if not _has_ascii_digit(value):
        return False
    if not value[0].isdigit():
        value_start = match.start(_IDENTIFIER_VALUE_GROUP)
        if value_start == 0 or not _is_identifier_separator(match.string[value_start - 1]):
            return False
    return not _has_disallowed_identifier_continuation(
        match.string, match.end(_IDENTIFIER_VALUE_GROUP)
    )


# Canonical MRN raw regex shared by the credential redactor and data-layer PHI
# classification so both components enforce identical cue, separator, and value
# semantics for medical record numbers.
MEDICAL_RECORD_NUMBER_REGEX = _build_contextual_identifier_pattern(
    r"mrn|medical[\s_-]*record",
    6,
    12,
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
    """Validator for NPI matches that enforces shared boundaries and Luhn."""
    digits = match.group(_IDENTIFIER_VALUE_GROUP)
    if _has_disallowed_identifier_continuation(match.string, match.end(_IDENTIFIER_VALUE_GROUP)):
        return False
    return is_valid_npi(digits)


# We define the raw patterns here as tuples of (name, regex_string, [optional_validator])
# to avoid a circular dependency with credential_redactor.py.
# The CredentialRedactor will instantiate these as CredentialPattern objects.
HIPAA_PHI_RAW_PATTERNS = (
    # MRNs identify a patient within a healthcare record system, so they are
    # treated as PHI and grouped with patient-linked healthcare identifiers.
    (
        "Medical Record Number (MRN)",
        MEDICAL_RECORD_NUMBER_REGEX,
        validate_contextual_identifier_match,
    ),
    # NPIs identify healthcare providers, are publicly available via the NPPES
    # registry, and are retained for healthcare identifier detection but are
    # not treated as PHI by the redactor collections.
    (
        "National Provider Identifier (NPI)",
        rf"(?ai)(?<![A-Za-z0-9])(?:npi|provider[\s_-]*id){_IDENTIFIER_SEPARATOR_CHARS}*"
        rf"(?P<{_IDENTIFIER_VALUE_GROUP}>[0-9]{{10}})(?![A-Za-z0-9])",
        validate_npi_match,
    ),
    # Health-plan or member identifiers describe a patient's insurance
    # relationship in clinical workflows, so they are treated as PHI.
    (
        "Health Plan ID",
        _build_contextual_identifier_pattern(
            r"hpid|health[\s_-]*plan(?:[\s_-]*id)?|member[\s_-]*(?:identification|id)|policy[\s_-]*id",
            8,
            15,
        ),
        validate_contextual_identifier_match,
    ),
)
