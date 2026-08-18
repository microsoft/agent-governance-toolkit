# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""HIPAA PHI patterns for the credential redactor."""

import re
from .credential_redactor import CredentialPattern

HIPAA_PHI_PATTERNS: tuple[CredentialPattern, ...] = (
    CredentialPattern(
        name="Medical Record Number (MRN)",
        pattern=re.compile(r"(?i)\b(?:mrn|medical\s*record)[\s#-]*([A-Z0-9]{6,12})\b"),
    ),
    CredentialPattern(
        name="National Provider Identifier (NPI)",
        pattern=re.compile(r"\b\d{10}\b"),
    ),
    CredentialPattern(
        name="Health Plan ID",
        pattern=re.compile(r"(?i)\b(?:hpid|member\s*id|policy\s*id)[\s#-]*([A-Z0-9]{8,15})\b"),
    ),
)