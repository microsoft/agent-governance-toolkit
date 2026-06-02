# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""Regression tests for the IATP X-User-Override double-gate.

The legacy behavior accepted any truthy ``X-User-Override`` header as a
bypass of policy/security warnings — a caller-controlled bypass with the
same shape as the kernel ``approved`` parameter hardened in the Agent OS
authz sweep. These tests assert the new contract:

* No env-side token set → header is ignored entirely, fail closed.
* Env-side token set, caller sends wrong/missing value → fail closed.
* Env-side token set, caller sends matching value → bypass permitted.
"""

from __future__ import annotations

import pytest

from iatp.main import _trusted_user_override as main_trusted_override
from iatp.sidecar import _trusted_user_override as sidecar_trusted_override

ALL_HELPERS = pytest.mark.parametrize(
    "helper",
    [main_trusted_override, sidecar_trusted_override],
    ids=["main", "sidecar"],
)


@ALL_HELPERS
def test_no_env_token_denies_even_with_true_header(helper, monkeypatch):
    monkeypatch.delenv("IATP_TRUSTED_USER_OVERRIDE_TOKEN", raising=False)
    assert helper("true") is False
    assert helper("yes") is False
    assert helper("1") is False
    assert helper("anything") is False


@ALL_HELPERS
def test_empty_env_token_denies(helper, monkeypatch):
    monkeypatch.setenv("IATP_TRUSTED_USER_OVERRIDE_TOKEN", "   ")
    assert helper("anything") is False


@ALL_HELPERS
def test_missing_header_denies(helper, monkeypatch):
    monkeypatch.setenv("IATP_TRUSTED_USER_OVERRIDE_TOKEN", "super-strong-token-9X4z")
    assert helper(None) is False
    assert helper("") is False


@ALL_HELPERS
def test_wrong_header_value_denies(helper, monkeypatch):
    monkeypatch.setenv("IATP_TRUSTED_USER_OVERRIDE_TOKEN", "super-strong-token-9X4z")
    assert helper("true") is False
    assert helper("wrong-token") is False


@ALL_HELPERS
def test_matching_token_allows(helper, monkeypatch):
    monkeypatch.setenv("IATP_TRUSTED_USER_OVERRIDE_TOKEN", "super-strong-token-9X4z")
    assert helper("super-strong-token-9X4z") is True
    # leading/trailing whitespace is tolerated
    assert helper("  super-strong-token-9X4z  ") is True


@ALL_HELPERS
def test_legacy_truthy_string_no_longer_authorizes(helper, monkeypatch):
    """Regression: this is the original CVE shape — any caller could
    self-authorize by sending the header. Even with a token set, that
    string must not match unless it happens to equal the token."""
    monkeypatch.setenv("IATP_TRUSTED_USER_OVERRIDE_TOKEN", "production-secret-token-77")
    for header in ("true", "yes", "1", "TRUE", "True"):
        assert helper(header) is False


@ALL_HELPERS
@pytest.mark.parametrize(
    "weak_token",
    ["true", "yes", "1", "admin", "password", "secret", "approved", "TRUE"],
)
def test_blacklisted_weak_token_disables_gate(helper, monkeypatch, weak_token):
    """A weak/well-known token must disable the override entirely so
    a sloppy operator can't accidentally make the gate trivially
    bypassable."""
    monkeypatch.setenv("IATP_TRUSTED_USER_OVERRIDE_TOKEN", weak_token)
    # Even sending the exact "matching" weak value must be denied.
    assert helper(weak_token) is False


@ALL_HELPERS
def test_short_token_disables_gate(helper, monkeypatch):
    """Tokens shorter than the minimum entropy threshold are rejected."""
    monkeypatch.setenv("IATP_TRUSTED_USER_OVERRIDE_TOKEN", "shortone")  # 8 chars
    assert helper("shortone") is False
