# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""Tests for process scanner credential redaction."""

from __future__ import annotations

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


def test_redacts_private_key_passed_on_one_command_line():
    """A key in argv has no real newlines — a shell cannot put them there.

    This is the shape the process scanner actually sees, so a pattern that
    requires a line break inside the block never fires on real process text and
    the key is written into the discovery inventory verbatim.
    """
    text = f"agent --key '-----BEGIN RSA PRIVATE KEY-----{_FAKE_KEY_BODY}-----END RSA PRIVATE KEY-----'"

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


def test_does_not_redact_public_key_without_newlines():
    """Widening the separator must not start matching public keys."""
    public_key = f"-----BEGIN PUBLIC KEY-----{_FAKE_KEY_BODY}-----END PUBLIC KEY-----"

    assert _redact_secrets(public_key) == public_key
