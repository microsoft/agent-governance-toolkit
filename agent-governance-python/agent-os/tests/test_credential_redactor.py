# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""Tests for credential redaction helpers."""

from __future__ import annotations

import time

import pytest

from agent_os.credential_redactor import REDACTED_PLACEHOLDER, CredentialRedactor


def _fake_github_token(prefix: str) -> str:
    return f"{prefix}_FAKEFORTESTING000000000000000000"


def _fake_pem_block(label: str) -> str:
    return (
        f"-----BEGIN {label}-----\n"
        "VGhpcyBpcyBub3QgYSByZWFsIGtleS4=\n"
        "QWxsIHZhbHVlcyBhcmUgZmFrZSBmb3IgdGVzdGluZy4=\n"
        f"-----END {label}-----"
    )


@pytest.mark.parametrize(
    ("input_text", "expected_type"),
    [
        ("key=sk-test_abcdefghijklmnopqrstuvwxyz", "OpenAI API key"),
        ("token=ghp_FAKEFORTESTING000000000000000000", "GitHub token"),
        ("aws=AKIAIOSFODNN7EXAMPLE", "AWS access key"),
        ("AccountKey=abc123def456ghi789jkl012mno345pqr678stu901vw==", "Azure key"),
        (
            "Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.payload.signature",
            "Bearer token",
        ),
        ("-----BEGIN RSA PRIVATE KEY-----\nabc\n-----END RSA PRIVATE KEY-----", "PEM private key"),
        ("Server=db;Password=supersecret;", "Connection string secret"),
        ("https://user:pass123@example.com/resource", "Basic auth secret"),
        ("eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.payload.signature", "JWT"),
        ("api_key=super-secret-value", "Generic API secret"),
    ],
)
def test_detects_and_redacts_supported_credential_types(input_text: str, expected_type: str):
    redacted = CredentialRedactor.redact(input_text)
    detected = CredentialRedactor.detect_credential_types(input_text)

    assert REDACTED_PLACEHOLDER in redacted
    assert expected_type in detected
    assert CredentialRedactor.contains_credentials(input_text) is True


def test_redact_dictionary_alias_redacts_nested_values():
    payload = {
        "headers": {
            "authorization": "Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.payload.signature",
        },
        "items": [
            "safe value",
            "api_key=secret-value",
        ],
    }

    redacted = CredentialRedactor.redact_dictionary(payload)

    assert redacted["headers"]["authorization"] == REDACTED_PLACEHOLDER
    assert redacted["items"][0] == "safe value"
    assert redacted["items"][1] == REDACTED_PLACEHOLDER


def test_clean_values_remain_unchanged():
    payload = {
        "message": "hello world",
        "list": ["one", "two"],
    }

    assert CredentialRedactor.redact("hello world") == "hello world"
    assert CredentialRedactor.redact_data_structure(payload) == payload
    assert CredentialRedactor.contains_credentials("hello world") is False


def test_incomplete_pem_header_is_not_treated_as_full_key():
    text = "-----BEGIN RSA PRIVATE KEY-----\nmissing footer"

    assert CredentialRedactor.redact(text) == text
    assert CredentialRedactor.contains_credentials(text) is False


@pytest.mark.parametrize(
    "label",
    [
        "RSA PRIVATE KEY",
        "EC PRIVATE KEY",
        "DSA PRIVATE KEY",
        "OPENSSH PRIVATE KEY",
        "ENCRYPTED PRIVATE KEY",
        "PRIVATE KEY",
    ],
)
def test_redacts_full_rfc7468_private_key_blocks(label: str):
    pem_block = _fake_pem_block(label)
    text = f"before\n{pem_block}\nafter"

    redacted = CredentialRedactor.redact(text)
    matches = CredentialRedactor.find_matches(text)

    assert redacted == f"before\n{REDACTED_PLACEHOLDER}\nafter"
    assert any(match.name == "PEM private key" and match.matched_text == pem_block for match in matches)


@pytest.mark.parametrize(
    "text",
    [
        _fake_pem_block("PUBLIC KEY"),
        "-----BEGIN RSA PRIVATE KEY-----\nZmFrZQ==\n-----END EC PRIVATE KEY-----",
        "BEGIN RSA PRIVATE KEY\nZmFrZQ==\nEND RSA PRIVATE KEY",
    ],
)
def test_does_not_redact_non_private_or_malformed_pem_blocks(text: str):
    assert CredentialRedactor.redact(text) == text
    assert CredentialRedactor.contains_credentials(text) is False


@pytest.mark.parametrize(
    "token",
    [
        _fake_github_token("ghp"),
        _fake_github_token("ghs"),
        _fake_github_token("gho"),
        _fake_github_token("ghu"),
        _fake_github_token("ghr"),
        "github_pat_FAKE_FOR_TESTING_0000000000000000000000",
    ],
)
def test_redacts_supported_github_token_prefixes(token: str):
    text = f"token {token} end"

    redacted = CredentialRedactor.redact(text)

    assert redacted == f"token {REDACTED_PLACEHOLDER} end"
    assert "GitHub token" in CredentialRedactor.detect_credential_types(text)


@pytest.mark.parametrize(
    "text",
    [
        f"x{_fake_github_token('ghp')}",
        f"{_fake_github_token('ghs')}_",
        "gho_short",
        "github_pat_short",
        "notgithub_pat_FAKE_FOR_TESTING_0000000000000000000000",
    ],
)
def test_github_token_boundaries_and_lengths_avoid_false_positives(text: str):
    assert CredentialRedactor.redact(text) == text
    assert CredentialRedactor.contains_credentials(text) is False


def test_redaction_is_idempotent():
    text = (
        f"first {_fake_github_token('ghp')} "
        f"second {_fake_pem_block('EC PRIVATE KEY')} "
        "third key=sk-FAKEFORTESTING000000000000000000"
    )

    once = CredentialRedactor.redact(text)
    twice = CredentialRedactor.redact(once)

    assert once == twice
    assert once.count(REDACTED_PLACEHOLDER) == 3


def test_private_key_pattern_handles_adversarial_input_quickly():
    text = "-----BEGIN RSA PRIVATE KEY-----\n" + ("A" * 100_000)

    start = time.perf_counter()
    redacted = CredentialRedactor.redact(text)
    elapsed = time.perf_counter() - start

    assert redacted == text
    assert elapsed < 1.0


# ---------------------------------------------------------------------------
# PII redaction — opt-in via ``redact_pii=True`` (see issue #3239).
#
# redact() is secrets-only by default; PII is detected by find_pii_matches() /
# contains_pii() but not removed unless the caller opts in. These tests pin
# both halves of that contract so the gap reported in #3239 cannot regress.
# ---------------------------------------------------------------------------

_PII_CASES = [
    ("email user@example.com", "user@example.com"),
    ("phone 415-555-0142", "415-555-0142"),
    ("ssn 123-45-6789", "123-45-6789"),
    ("card 4111111111111111", "4111111111111111"),
    ("ip 10.0.0.1", "10.0.0.1"),
]


@pytest.mark.parametrize(("text", "fragment"), _PII_CASES)
def test_default_redact_leaves_pii_untouched(text: str, fragment: str):
    # Regression for #3239: by default redact() is secrets-only, so PII is
    # detected but NOT removed.
    assert CredentialRedactor.contains_pii(text) is True
    assert CredentialRedactor.redact(text) == text
    assert fragment in CredentialRedactor.redact(text)


@pytest.mark.parametrize(("text", "fragment"), _PII_CASES)
def test_redact_pii_scrubs_pii(text: str, fragment: str):
    redacted = CredentialRedactor.redact(text, redact_pii=True)

    assert REDACTED_PLACEHOLDER in redacted
    assert fragment not in redacted


@pytest.mark.parametrize(
    "ssn",
    ["123-45-6789", "123 45 6789", "123.45.6789", "123456789"],
)
def test_ssn_pattern_matches_all_separator_variants(ssn: str):
    # The SSN pattern in PII_PATTERNS is reconciled with the canonical broadened
    # form in integrations/base.py (dash/space/dot/none). See #3239.
    matches = {match.matched_text for match in CredentialRedactor.find_pii_matches(ssn)}
    assert ssn in matches
    assert CredentialRedactor.redact(ssn, redact_pii=True) == REDACTED_PLACEHOLDER


def test_ssn_word_boundary_does_not_overmatch_longer_digit_runs():
    # The no-separator SSN branch matches a bare 9-digit run. The \b anchors
    # must keep it from over-matching longer numeric IDs (e.g. account numbers),
    # which now surface through find_pii_matches()/contains_pii() callers such
    # as mcp_response_scanner.py and stateless.py. A 12-digit run is longer
    # than both SSN (9) and US phone (10/11 with optional leading 1), so no PII
    # pattern should fire. (Review feedback on #3259.)
    assert CredentialRedactor.contains_pii("acct 123456789012") is False
    assert CredentialRedactor.find_pii_matches("acct 123456789012") == []


def test_redact_pii_still_redacts_secrets_too():
    text = "key=sk-test_abcdefghijklmnopqrstuvwxyz email user@example.com"

    redacted = CredentialRedactor.redact(text, redact_pii=True)

    assert "sk-test_abcdefghijklmnopqrstuvwxyz" not in redacted
    assert "user@example.com" not in redacted
    assert redacted.count(REDACTED_PLACEHOLDER) >= 2


def test_redact_pii_threads_through_nested_data_structure():
    payload = {
        "email": "user@example.com",
        "nested": ["ssn 123-45-6789", {"ip": "10.0.0.1"}],
        "safe": "hello",
    }

    redacted = CredentialRedactor.redact_data_structure(payload, redact_pii=True)

    assert redacted["email"] == REDACTED_PLACEHOLDER
    assert redacted["nested"][0] == f"ssn {REDACTED_PLACEHOLDER}"
    assert redacted["nested"][1]["ip"] == REDACTED_PLACEHOLDER
    assert redacted["safe"] == "hello"
    # Default still leaves PII untouched in nested structures.
    default_redacted = CredentialRedactor.redact_data_structure(payload)
    assert default_redacted["email"] == "user@example.com"


def test_redact_pii_threads_through_mapping():
    payload = {"email": "user@example.com"}

    assert (
        CredentialRedactor.redact_mapping(payload, redact_pii=True)["email"]
        == REDACTED_PLACEHOLDER
    )
    # Default remains secrets-only.
    assert CredentialRedactor.redact_mapping(payload)["email"] == "user@example.com"


def test_redact_pii_is_idempotent():
    text = "email user@example.com ssn 123-45-6789"

    once = CredentialRedactor.redact(text, redact_pii=True)
    twice = CredentialRedactor.redact(once, redact_pii=True)

    assert once == twice
