# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""Tests for process scanner credential redaction."""

from __future__ import annotations

import pytest

from agent_discovery.scanners.process import _redact_secrets


def test_redacts_modern_github_tokens_from_process_text():
    text = "agent --header github_pat_FAKE_FOR_TESTING_0000000000000000000000"

    redacted = _redact_secrets(text)

    assert "github_pat_" not in redacted
    assert "[REDACTED]" in redacted


def test_redacts_full_private_key_blocks_from_process_text():
    text = (
        "agent --key '-----BEGIN OPENSSH PRIVATE KEY-----\n"
        "ZmFrZSBmb3IgdGVzdGluZw==\n"
        "-----END OPENSSH PRIVATE KEY-----'"
    )

    redacted = _redact_secrets(text)

    assert "BEGIN OPENSSH PRIVATE KEY" not in redacted
    assert "END OPENSSH PRIVATE KEY" not in redacted
    assert "[REDACTED]" in redacted


def test_does_not_redact_public_or_malformed_pem_process_text():
    public_key = "-----BEGIN PUBLIC KEY-----\nZmFrZSBmb3IgdGVzdGluZw==\n-----END PUBLIC KEY-----"

    assert _redact_secrets(public_key) == public_key


_FAKE_KEY_BODY = "ZmFrZSBmb3IgdGVzdGluZw=="


def test_redacts_private_key_with_real_newlines_in_process_text():
    """A PEM block with real line endings remains redacted."""
    text = f"agent --key '-----BEGIN RSA PRIVATE KEY-----\n{_FAKE_KEY_BODY}\n-----END RSA PRIVATE KEY-----'"

    redacted = _redact_secrets(text)

    assert _FAKE_KEY_BODY not in redacted
    assert "BEGIN RSA PRIVATE KEY" not in redacted
    assert "[REDACTED]" in redacted


def test_redacts_private_key_with_escaped_newlines_in_process_text():
    """The other argv shape: newlines escaped rather than stripped."""
    text = (
        "agent --key '-----BEGIN OPENSSH PRIVATE KEY-----\\n"
        f"{_FAKE_KEY_BODY}\\n"
        "-----END OPENSSH PRIVATE KEY-----'"
    )

    redacted = _redact_secrets(text)

    assert _FAKE_KEY_BODY not in redacted
    assert "[REDACTED]" in redacted


def test_redacts_private_key_with_stripped_newlines_in_process_text():
    """Env-var / argv shape: newlines removed entirely between markers."""
    text = (
        "agent --key '-----BEGIN OPENSSH PRIVATE KEY-----"
        f"{_FAKE_KEY_BODY}"
        "-----END OPENSSH PRIVATE KEY-----'"
    )

    redacted = _redact_secrets(text)

    assert _FAKE_KEY_BODY not in redacted
    assert "[REDACTED]" in redacted


def test_does_not_redact_public_key_without_newlines():
    """Widening the separator must not start matching public keys."""
    public_key = f"-----BEGIN PUBLIC KEY-----{_FAKE_KEY_BODY}-----END PUBLIC KEY-----"

    assert _redact_secrets(public_key) == public_key


@pytest.mark.parametrize(
    "separator",
    ["\n", "\r\n", "\\n", "", " "],
    ids=["newline", "crlf", "escaped", "stripped", "space"],
)
def test_does_not_terminate_at_glued_decoy_end_label(separator: str):
    """A glued END literal is body text, not the end of a key."""
    text = (
        f"agent --key '-----BEGIN PRIVATE KEY-----{separator}"
        f"glued-----END PRIVATE KEY-----{_FAKE_KEY_BODY}{separator}"
        "-----END PRIVATE KEY-----'"
    )

    redacted = _redact_secrets(text)

    assert _FAKE_KEY_BODY not in redacted, "the real key body survived the decoy END label"
    assert "[REDACTED]" in redacted


@pytest.mark.parametrize(
    "separator",
    ["\n", "\\n", ""],
    ids=["newline", "escaped", "stripped"],
)
def test_redacts_two_private_keys_separately(separator: str):
    """Adjacent PEM blocks stay separate; log noise between them survives."""
    first = (
        f"-----BEGIN PRIVATE KEY-----{separator}"
        f"first{separator}"
        f"-----END PRIVATE KEY-----"
    )
    second = (
        f"-----BEGIN PRIVATE KEY-----{separator}"
        f"second{separator}"
        f"-----END PRIVATE KEY-----"
    )

    assert (
        _redact_secrets(f"{first} 500 log lines {second}")
        == "[REDACTED] 500 log lines [REDACTED]"
    )
