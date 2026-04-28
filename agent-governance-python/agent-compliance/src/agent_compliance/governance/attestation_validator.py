# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
#!/usr/bin/env python3
# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""Governance attestation validation.

Validates that PR descriptions contain properly filled out governance
attestation checklists with exactly one checkbox marked per section.
"""

import re
from dataclasses import dataclass
from typing import Optional


@dataclass
class AttestationResult:
    """Result of attestation validation."""

    valid: bool
    errors: list[str]
    warnings: list[str]
    sections_found: dict[str, int]  # section -> number of checked boxes

    @property
    def message(self) -> str:
        """Get formatted message for display."""
        if self.valid:
            return "✅ Governance attestation checklist looks good."

        lines = ["❌ Governance attestation check failed:"]
        for error in self.errors:
            lines.append(f"  - {error}")
        return "\n".join(lines)


def _normalize_line_endings(text: str) -> str:
    """Normalize CRLF to LF for consistent matching."""
    return text.replace("\r\n", "\n")


def _count_section_checkboxes(section_title: str, pr_body: str) -> dict:
    """Count checked boxes in a specific section.

    Args:
        section_title: Title of the section to find (e.g., "1) Security review")
        pr_body: Full PR description body

    Returns:
        dict with:
            - found: bool (whether section was found)
            - checked: int (number of checked boxes)
            - details: str (section content) or None
    """
    # Escape special regex characters in section title
    escaped_title = re.escape(section_title)

    # Find section header and capture content until next ## / ### or end.
    # Supports both ## (h2) and ### (h3) headings for compatibility with
    # GitHub Issue Forms, which render checkbox group labels as ### headings.
    pattern = rf"(^|\n)#{{2,3}}\s+{escaped_title}\n([\s\S]*?)(?=\n#{{2,3}}\s+|$)"
    match = re.search(pattern, pr_body, re.IGNORECASE)

    if not match:
        return {"found": False, "checked": 0, "details": None}

    section_content = match.group(2)

    # Count checked boxes (case-insensitive, allows leading whitespace)
    checked_pattern = r"(^|\n)\s*-\s*\[x\]"
    checked_boxes = re.findall(checked_pattern, section_content, re.IGNORECASE)

    return {
        "found": True,
        "checked": len(checked_boxes),
        "details": section_content,
    }


def validate_attestation(
    pr_body: str,
    required_sections: Optional[list[str]] = None,
    min_body_length: int = 40,
) -> AttestationResult:
    """Validate governance attestation in PR description.

    Args:
        pr_body: PR description body text
        required_sections: List of section titles that must be present.
            Defaults to standard 7-section attestation.
        min_body_length: Minimum length for PR body to be considered valid

    Returns:
        AttestationResult with validation status and details
    """
    if required_sections is None:
        required_sections = [
            "1) Security review",
            "2) Privacy review",
            "3) CELA review",
            "4) Responsible AI review",
            "5) Accessibility review",
            "6) Release Readiness / Safe Deployment",
            "7) Org-specific Launch Gates",
        ]

    # Normalize line endings
    pr_body = _normalize_line_endings(pr_body or "")

    errors = []
    sections_found = {}

    # Check each required section
    for section in required_sections:
        result = _count_section_checkboxes(section, pr_body)

        if not result["found"]:
            errors.append(f'Missing section: "{section}"')
            continue

        checked_count = result["checked"]
        sections_found[section] = checked_count

        if checked_count != 1:
            errors.append(
                f'Section "{section}" must have exactly ONE checked box, '
                f"found {checked_count}."
            )

    # Check minimum body length
    if pr_body.strip() and len(pr_body.strip()) < min_body_length:
        errors.append(
            "PR description is too short; "
            "please use the governance attestation template."
        )

    return AttestationResult(
        valid=len(errors) == 0,
        errors=errors,
        warnings=[],
        sections_found=sections_found,
    )
