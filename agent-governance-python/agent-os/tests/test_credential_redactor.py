# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""Tests for credential redaction helpers."""

from __future__ import annotations

import time

import pytest

from agent_os.credential_redactor import CredentialRedactor, REDACTED_PLACEHOLDER


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
