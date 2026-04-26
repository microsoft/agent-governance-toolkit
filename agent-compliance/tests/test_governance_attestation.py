# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""Tests for governance attestation validation."""

from __future__ import annotations


from agent_compliance.governance import AttestationResult, validate_attestation


class TestAttestationResult:
    """Tests for AttestationResult dataclass."""

    def test_message_property_success(self):
        """Test message property for successful validation."""
        result = AttestationResult(
            valid=True,
            errors=[],
            warnings=[],
            sections_found={"1) Security review": 1},
        )
        assert result.message == "✅ Governance attestation checklist looks good."

    def test_message_property_failure(self):
        """Test message property for failed validation."""
        result = AttestationResult(
            valid=False,
            errors=[
                'Missing section: "1) Security review"',
                'Section "2) Privacy review" must have exactly ONE checked box, found 0.',
            ],
            warnings=[],
            sections_found={},
        )
        message = result.message
        assert "❌ Governance attestation check failed:" in message
        assert "Missing section" in message
        assert "must have exactly ONE checked box" in message


class TestValidateAttestation:
    """Tests for validate_attestation function."""

    def test_valid_attestation_all_sections_checked(self):
        """Test validation passes when all sections have exactly one checkbox marked."""
        pr_body = """
# Governance Attestations (required)

## 1) Security review
- [x] ✅ Yes
- [ ] ❌ No
- [ ] ⚠️ Not needed (explain below)

## 2) Privacy review
- [ ] ✅ Yes
- [x] ❌ No
- [ ] ⚠️ Not needed (explain below)

## 3) CELA review
- [ ] ✅ Yes
- [ ] ❌ No
- [x] ⚠️ Not needed (explain below)

## 4) Responsible AI review
- [x] ✅ Yes
- [ ] ❌ No
- [ ] ⚠️ Not needed (explain below)

## 5) Accessibility review
- [ ] ✅ Yes
- [x] ❌ No
- [ ] ⚠️ Not needed (explain below)

## 6) Release Readiness / Safe Deployment
- [x] ✅ Yes
- [ ] ❌ No
- [ ] ⚠️ Not needed (explain below)

## 7) Org-specific Launch Gates
- [ ] ✅ Yes
- [ ] ❌ No
- [x] ⚠️ Not needed (explain below)

---

# Notes / Links
Some additional context here.
"""
        result = validate_attestation(pr_body)
        assert result.valid is True
        assert len(result.errors) == 0
        assert len(result.sections_found) == 7
        for count in result.sections_found.values():
            assert count == 1

    def test_missing_section(self):
        """Test validation fails when required section is missing."""
        pr_body = """
## 1) Security review
- [x] ✅ Yes
- [ ] ❌ No

## 2) Privacy review
- [x] ✅ Yes
- [ ] ❌ No
"""
        result = validate_attestation(pr_body)
        assert result.valid is False
        assert any("Missing section" in error for error in result.errors)
        # Should have errors for 5 missing sections (3-7)
        missing_errors = [e for e in result.errors if "Missing section" in e]
        assert len(missing_errors) == 5

    def test_no_checkbox_marked(self):
        """Test validation fails when no checkbox is marked in a section."""
        pr_body = """
## 1) Security review
- [ ] ✅ Yes
- [ ] ❌ No
- [ ] ⚠️ Not needed (explain below)

## 2) Privacy review
- [x] ✅ Yes
- [ ] ❌ No

## 3) CELA review
- [x] ✅ Yes

## 4) Responsible AI review
- [x] ✅ Yes

## 5) Accessibility review
- [x] ✅ Yes

## 6) Release Readiness / Safe Deployment
- [x] ✅ Yes

## 7) Org-specific Launch Gates
- [x] ✅ Yes
"""
        result = validate_attestation(pr_body)
        assert result.valid is False
        assert any(
            "must have exactly ONE checked box, found 0" in error
            for error in result.errors
        )
        assert result.sections_found["1) Security review"] == 0

    def test_multiple_checkboxes_marked(self):
        """Test validation fails when multiple checkboxes are marked in a section."""
        pr_body = """
## 1) Security review
- [x] ✅ Yes
- [x] ❌ No
- [ ] ⚠️ Not needed (explain below)

## 2) Privacy review
- [x] ✅ Yes

## 3) CELA review
- [x] ✅ Yes

## 4) Responsible AI review
- [x] ✅ Yes

## 5) Accessibility review
- [x] ✅ Yes

## 6) Release Readiness / Safe Deployment
- [x] ✅ Yes

## 7) Org-specific Launch Gates
- [x] ✅ Yes
"""
        result = validate_attestation(pr_body)
        assert result.valid is False
        assert any(
            "must have exactly ONE checked box, found 2" in error
            for error in result.errors
        )
        assert result.sections_found["1) Security review"] == 2

    def test_custom_required_sections(self):
        """Test validation with custom required sections."""
        pr_body = """
## Security review
- [x] ✅ Yes

## Privacy review
- [x] ✅ Yes

## Legal review
- [x] ✅ Yes
"""
        custom_sections = ["Security review", "Privacy review", "Legal review"]
        result = validate_attestation(pr_body, required_sections=custom_sections)
        assert result.valid is True
        assert len(result.sections_found) == 3

    def test_case_insensitive_checkbox_matching(self):
        """Test that checkbox matching is case-insensitive."""
        pr_body = """
## 1) Security review
- [X] ✅ Yes
- [ ] ❌ No

## 2) Privacy review
- [x] ✅ Yes

## 3) CELA review
- [X] ✅ Yes

## 4) Responsible AI review
- [x] ✅ Yes

## 5) Accessibility review
- [X] ✅ Yes

## 6) Release Readiness / Safe Deployment
- [x] ✅ Yes

## 7) Org-specific Launch Gates
- [X] ✅ Yes
"""
        result = validate_attestation(pr_body)
        assert result.valid is True
        for count in result.sections_found.values():
            assert count == 1

    def test_crlf_line_endings_normalized(self):
        """Test that CRLF line endings are properly normalized."""
        pr_body = "## 1) Security review\r\n- [x] ✅ Yes\r\n- [ ] ❌ No\r\n\r\n## 2) Privacy review\r\n- [x] ✅ Yes\r\n\r\n## 3) CELA review\r\n- [x] ✅ Yes\r\n\r\n## 4) Responsible AI review\r\n- [x] ✅ Yes\r\n\r\n## 5) Accessibility review\r\n- [x] ✅ Yes\r\n\r\n## 6) Release Readiness / Safe Deployment\r\n- [x] ✅ Yes\r\n\r\n## 7) Org-specific Launch Gates\r\n- [x] ✅ Yes\r\n"
        result = validate_attestation(pr_body)
        assert result.valid is True

    def test_pr_body_too_short(self):
        """Test validation fails when PR body is too short."""
        pr_body = "Short PR body"
        result = validate_attestation(pr_body, min_body_length=40)
        assert result.valid is False
        assert any("too short" in error for error in result.errors)

    def test_empty_pr_body(self):
        """Test validation with empty PR body."""
        result = validate_attestation("")
        assert result.valid is False
        assert any("Missing section" in error for error in result.errors)

    def test_none_pr_body(self):
        """Test validation with None PR body."""
        result = validate_attestation(None)
        assert result.valid is False
        assert any("Missing section" in error for error in result.errors)

    def test_whitespace_before_checkbox(self):
        """Test that leading whitespace before checkboxes is allowed."""
        pr_body = """
## 1) Security review
  - [x] ✅ Yes
  - [ ] ❌ No

## 2) Privacy review
    - [x] ✅ Yes

## 3) CELA review
- [x] ✅ Yes

## 4) Responsible AI review
        - [x] ✅ Yes

## 5) Accessibility review
- [x] ✅ Yes

## 6) Release Readiness / Safe Deployment
- [x] ✅ Yes

## 7) Org-specific Launch Gates
- [x] ✅ Yes
"""
        result = validate_attestation(pr_body)
        assert result.valid is True

    def test_section_with_special_regex_characters(self):
        """Test sections with special regex characters are properly escaped."""
        pr_body = """
## Test (with parens)
- [x] ✅ Yes

## Test [with brackets]
- [x] ✅ Yes
"""
        custom_sections = ["Test (with parens)", "Test [with brackets]"]
        result = validate_attestation(pr_body, required_sections=custom_sections)
        assert result.valid is True

    def test_section_not_at_start_of_line(self):
        """Test that sections must start at beginning of line."""
        pr_body = """
Some text ## 1) Security review
- [x] ✅ Yes

## 2) Privacy review
- [x] ✅ Yes

## 3) CELA review
- [x] ✅ Yes

## 4) Responsible AI review
- [x] ✅ Yes

## 5) Accessibility review
- [x] ✅ Yes

## 6) Release Readiness / Safe Deployment
- [x] ✅ Yes

## 7) Org-specific Launch Gates
- [x] ✅ Yes
"""
        result = validate_attestation(pr_body)
        assert result.valid is False
        assert any(
            'Missing section: "1) Security review"' in error for error in result.errors
        )

    def test_multiple_errors_aggregated(self):
        """Test that multiple errors are properly aggregated."""
        pr_body = """
## 1) Security review
- [x] ✅ Yes
- [x] ❌ No

## 2) Privacy review
- [ ] ✅ Yes
"""
        result = validate_attestation(pr_body)
        assert result.valid is False
        # Should have error for section 1 (multiple checkboxes)
        # and errors for missing sections 3-7
        assert len(result.errors) >= 6
        assert any("found 2" in error for error in result.errors)
        assert any("Missing section" in error for error in result.errors)

    def test_custom_min_body_length(self):
        """Test validation with custom minimum body length."""
        pr_body = "A" * 100  # 100 characters
        result = validate_attestation(pr_body, min_body_length=50)
        # Will fail due to missing sections, but not due to length
        assert not any("too short" in error for error in result.errors)

        pr_body = "A" * 30  # 30 characters
        result = validate_attestation(pr_body, min_body_length=50)
        # Will fail due to length
        assert any("too short" in error for error in result.errors)

    def test_pr_body_no_checkboxes_at_all(self):
        """Test validation when sections exist but contain no checkboxes."""
        pr_body = """
## 1) Security review
This section has no checkboxes at all.

## 2) Privacy review
Just plain text.

## 3) CELA review
Nothing here either.

## 4) Responsible AI review
More prose.

## 5) Accessibility review
Nope.

## 6) Release Readiness / Safe Deployment
Still nothing.

## 7) Org-specific Launch Gates
End.
"""
        result = validate_attestation(pr_body)
        assert result.valid is False
        # Every section found but 0 checked boxes
        zero_errors = [e for e in result.errors if "found 0" in e]
        assert len(zero_errors) == 7

    def test_pr_body_html_encoded_checkboxes(self):
        """Test that HTML-encoded checkbox characters are NOT counted as checked."""
        pr_body = """
## 1) Security review
- &#91;x&#93; Yes
- [ ] No

## 2) Privacy review
- [x] Yes
"""
        custom_sections = ["1) Security review", "2) Privacy review"]
        result = validate_attestation(pr_body, required_sections=custom_sections)
        # Section 1 uses HTML entities — should NOT match as a checked box
        assert result.sections_found.get("1) Security review", 0) == 0
        assert result.sections_found.get("2) Privacy review", 0) == 1

    def test_pr_body_multiple_governance_sections_all_validated(self):
        """Test that ALL required governance sections are validated."""
        pr_body = """
## Alpha
- [x] Done

## Beta
- [x] Done

## Gamma
- [ ] Not done
"""
        custom_sections = ["Alpha", "Beta", "Gamma"]
        result = validate_attestation(pr_body, required_sections=custom_sections)
        assert result.valid is False
        assert result.sections_found["Alpha"] == 1
        assert result.sections_found["Beta"] == 1
        assert result.sections_found["Gamma"] == 0
        assert any("found 0" in e for e in result.errors)

    def test_empty_string_pr_body(self):
        """Test validation with a completely empty string PR body."""
        result = validate_attestation("")
        assert result.valid is False
        missing = [e for e in result.errors if "Missing section" in e]
        assert len(missing) == 7
        assert result.sections_found == {}

    def test_h3_headings_supported(self):
        """Test that ### (h3) headings are accepted (GitHub Issue Forms render these)."""
        pr_body = """
### 1) Security review
- [x] ✅ Yes
- [ ] ❌ No

### 2) Privacy review
- [x] ✅ Yes

### 3) CELA review
- [x] ✅ Yes

### 4) Responsible AI review
- [x] ✅ Yes

### 5) Accessibility review
- [x] ✅ Yes

### 6) Release Readiness / Safe Deployment
- [x] ✅ Yes

### 7) Org-specific Launch Gates
- [x] ✅ Yes
"""
        result = validate_attestation(pr_body)
        assert result.valid is True
        assert len(result.errors) == 0
        assert len(result.sections_found) == 7

    def test_h3_headings_mixed_with_h2(self):
        """Test that ## and ### headings can coexist in the same document."""
        pr_body = """
## 1) Security review
- [x] ✅ Yes

### 2) Privacy review
- [x] ✅ Yes

## 3) CELA review
- [x] ✅ Yes

### 4) Responsible AI review
- [x] ✅ Yes

## 5) Accessibility review
- [x] ✅ Yes

### 6) Release Readiness / Safe Deployment
- [x] ✅ Yes

## 7) Org-specific Launch Gates
- [x] ✅ Yes
"""
        result = validate_attestation(pr_body)
        assert result.valid is True
        assert len(result.errors) == 0

    def test_h3_no_checkbox_marked(self):
        """Test that h3 sections still enforce exactly-one-checked rule."""
        pr_body = """
### 1) Security review
- [ ] ✅ Yes
- [ ] ❌ No

### 2) Privacy review
- [x] ✅ Yes

### 3) CELA review
- [x] ✅ Yes

### 4) Responsible AI review
- [x] ✅ Yes

### 5) Accessibility review
- [x] ✅ Yes

### 6) Release Readiness / Safe Deployment
- [x] ✅ Yes

### 7) Org-specific Launch Gates
- [x] ✅ Yes
"""
        result = validate_attestation(pr_body)
        assert result.valid is False
        assert any("found 0" in e for e in result.errors)
        assert result.sections_found["1) Security review"] == 0

    def test_h4_headings_not_supported(self):
        """Test that #### (h4) headings are NOT matched — only h2 and h3 are valid."""
        pr_body = """
#### 1) Security review
- [x] ✅ Yes
"""
        custom_sections = ["1) Security review"]
        result = validate_attestation(pr_body, required_sections=custom_sections)
        assert result.valid is False
        assert any("Missing section" in e for e in result.errors)
