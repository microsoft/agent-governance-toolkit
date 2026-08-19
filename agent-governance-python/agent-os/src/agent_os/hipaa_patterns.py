# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""HIPAA PHI patterns for the credential redactor."""

# We define the raw patterns here as tuples of (name, regex_string)
# to avoid a circular dependency with credential_redactor.py.
# The CredentialRedactor will instantiate these as CredentialPattern objects.
HIPAA_PHI_RAW_PATTERNS = (
    (
        "Medical Record Number (MRN)",
        r"(?i)\b(?:mrn|medical\s*record)[\s#-]*([A-Z0-9]{6,12})\b",
    ),
    (
        "National Provider Identifier (NPI)",
        r"\b\d{10}\b",
    ),
    (
        "Health Plan ID",
        r"(?i)\b(?:hpid|member\s*id|policy\s*id)[\s#-]*([A-Z0-9]{8,15})\b",
    ),
)
