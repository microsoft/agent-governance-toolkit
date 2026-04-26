# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""Governance attestation validation module.

This module provides validation for PR governance attestation checklists,
ensuring compliance with organizational governance requirements.

Example:
    from agent_compliance.governance import validate_attestation

    result = validate_attestation(
        pr_body="...",
        required_sections=[
            "Security review",
            "Privacy review",
            "CELA review"
        ]
    )

    if not result.valid:
        print(f"Errors: {result.errors}")
"""

from .attestation_validator import AttestationResult, validate_attestation

__all__ = [
    "AttestationResult",
    "validate_attestation",
]
