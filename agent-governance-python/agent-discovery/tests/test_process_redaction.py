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
    public_key = (
        "-----BEGIN PUBLIC KEY-----\n"
        "ZmFrZSBmb3IgdGVzdGluZw==\n"
        "-----END PUBLIC KEY-----"
    )

    assert _redact_secrets(public_key) == public_key
