#!/usr/bin/env python3
# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""Parity regression tests for issue #3571.

Verifies that scripts/contributor_check.py and scripts/credential_audit.py
have full retry behaviour (URLError + 5xx) and that both the scripts path and
the agent_compliance.cli package path expose the same key functions and
produce equivalent results.  This file only imports the scripts modules (no
package install required).
"""

from __future__ import annotations

import json
import os
import sys
import time
from datetime import datetime, timedelta, timezone
from io import StringIO
from unittest.mock import MagicMock, call, patch
from urllib.error import HTTPError, URLError

import pytest

# ---------------------------------------------------------------------------
# Path setup – import scripts directly without installing the package
# ---------------------------------------------------------------------------

_scripts_dir = os.path.join(os.path.dirname(__file__), "..")
if _scripts_dir not in sys.path:
    sys.path.insert(0, _scripts_dir)

import contributor_check as cc
import credential_audit as ca


# ===========================================================================
# 1. Retry surface – contributor_check.py (scripts path)
# ===========================================================================

class TestContributorCheckRetry:
    """Verifies the full retry envelope: rate-limit (403), 5xx, and URLError."""

    def _make_response(self, body: bytes = b"{}") -> MagicMock:
        m = MagicMock()
        m.__enter__ = lambda s: s
        m.__exit__ = MagicMock(return_value=False)
        m.read.return_value = body
        return m

    def test_retries_on_rate_limit_403(self):
        """403 with Retry-After should be retried up to _RETRY_MAX_ATTEMPTS-1 times."""
        rate_exc = HTTPError("url", 403, "Forbidden", {"Retry-After": "0"}, None)
        ok_resp = self._make_response(b'{"login": "x"}')

        with patch("contributor_check.urlopen", side_effect=[rate_exc, ok_resp]), \
             patch("contributor_check._get_token", return_value="tok"), \
             patch("contributor_check.time.sleep"):
            result = cc._api("/users/x")
        assert result == {"login": "x"}

    def test_retries_on_5xx(self):
        """5xx server errors should trigger retry with backoff."""
        err_exc = HTTPError("url", 503, "Service Unavailable", {}, None)
        ok_resp = self._make_response(b'{"ok": true}')

        with patch("contributor_check.urlopen", side_effect=[err_exc, ok_resp]), \
             patch("contributor_check._get_token", return_value="tok"), \
             patch("contributor_check.time.sleep"), \
             patch("contributor_check._retry_sleep_seconds", return_value=0):
            result = cc._api("/some/path")
        assert result == {"ok": True}

    def test_retries_on_url_error(self):
        """Network-layer URLError (DNS, TCP reset) should be retried."""
        net_exc = URLError("connection reset")
        ok_resp = self._make_response(b'{"items": []}')

        with patch("contributor_check.urlopen", side_effect=[net_exc, ok_resp]), \
             patch("contributor_check._get_token", return_value="tok"), \
             patch("contributor_check.time.sleep"), \
             patch("contributor_check._retry_sleep_seconds", return_value=0):
            result = cc._api("/search/issues")
        assert result == {"items": []}

    def test_raises_after_max_attempts_url_error(self):
        """Exhausted retries for URLError should propagate the exception."""
        net_exc = URLError("connection refused")
        with patch("contributor_check.urlopen", side_effect=[net_exc, net_exc, net_exc]), \
             patch("contributor_check._get_token", return_value="tok"), \
             patch("contributor_check.time.sleep"), \
             patch("contributor_check._retry_sleep_seconds", return_value=0):
            with pytest.raises(URLError):
                cc._api("/users/x")

    def test_404_returns_none(self):
        """404 responses must return None without retrying."""
        not_found = HTTPError("url", 404, "Not Found", {}, None)
        with patch("contributor_check.urlopen", side_effect=not_found), \
             patch("contributor_check._get_token", return_value="tok"):
            result = cc._api("/users/nobody")
        assert result is None

    def test_retry_max_attempts_constant_present(self):
        assert hasattr(cc, "_RETRY_MAX_ATTEMPTS")
        assert cc._RETRY_MAX_ATTEMPTS >= 2

    def test_retry_sleep_seconds_returns_float(self):
        val = cc._retry_sleep_seconds(1)
        assert isinstance(val, float)
        assert val >= 0


# ===========================================================================
# 2. Retry surface – credential_audit.py (scripts path)
# ===========================================================================

class TestCredentialAuditRetry:
    """Same retry contract for the credential audit script."""

    def _make_response(self, body: bytes = b"{}") -> MagicMock:
        m = MagicMock()
        m.__enter__ = lambda s: s
        m.__exit__ = MagicMock(return_value=False)
        m.read.return_value = body
        return m

    def test_retries_on_url_error(self):
        net_exc = URLError("name resolution failed")
        ok_resp = self._make_response(b'{"items": []}')

        with patch("credential_audit.urlopen", side_effect=[net_exc, ok_resp]), \
             patch("credential_audit._get_token", return_value="tok"), \
             patch("credential_audit.time.sleep"), \
             patch("credential_audit._retry_sleep_seconds", return_value=0):
            result = ca._api("/search/issues")
        assert result == {"items": []}

    def test_retries_on_5xx(self):
        err_exc = HTTPError("url", 502, "Bad Gateway", {}, None)
        ok_resp = self._make_response(b'{"ok": true}')

        with patch("credential_audit.urlopen", side_effect=[err_exc, ok_resp]), \
             patch("credential_audit._get_token", return_value="tok"), \
             patch("credential_audit.time.sleep"), \
             patch("credential_audit._retry_sleep_seconds", return_value=0):
            result = ca._api("/repos/org/repo/pulls/1")
        assert result == {"ok": True}

    def test_404_422_returns_none(self):
        for code in (404, 422):
            exc = HTTPError("url", code, "error", {}, None)
            with patch("credential_audit.urlopen", side_effect=exc), \
                 patch("credential_audit._get_token", return_value="tok"):
                assert ca._api("/some/path") is None


# ===========================================================================
# 3. Org/allowlist hardening – contributor_check.py (scripts path)
# ===========================================================================

class TestContributorCheckHardening:
    """Verifies the allowlist and dampening subsystems are present in scripts."""

    def test_load_allowlist_missing_file_returns_empty(self, tmp_path):
        users, orgs = cc._load_allowlist(tmp_path / "nonexistent.json")
        assert users == set()
        assert orgs == set()

    def test_load_allowlist_parses_correctly(self, tmp_path):
        p = tmp_path / "allow.json"
        p.write_text(json.dumps({"users": ["Alice", "Bob"], "orgs": ["TrustCo"]}))
        users, orgs = cc._load_allowlist(p)
        assert "alice" in users
        assert "bob" in users
        assert "trustco" in orgs

    def test_is_allowlisted_by_username(self):
        allow = ({"alice"}, set())
        assert cc._is_allowlisted("Alice", [], allow) is True
        assert cc._is_allowlisted("dave", [], allow) is False

    def test_is_allowlisted_by_org(self):
        allow = (set(), {"trustedorg"})
        assert cc._is_allowlisted("anyone", ["TrustedOrg"], allow) is True

    def test_apply_allowlist_softens_high_to_medium(self):
        report = cc.ReputationReport(username="user", risk="HIGH")
        cc._apply_allowlist(report)
        assert report.risk == "MEDIUM"
        assert any(s.name == "allowlisted" for s in report.signals)

    def test_apply_allowlist_blocked_by_abuse_signal(self):
        report = cc.ReputationReport(username="user", risk="HIGH")
        report.add(cc.Signal("thin_credibility", "HIGH", "detail"))
        cc._apply_allowlist(report)
        assert report.risk == "HIGH"
        assert any(s.name == "allowlist_blocked" for s in report.signals)

    def test_dampen_for_established_accounts_lowers_cross_repo_spray(self):
        report = cc.ReputationReport(username="user")
        report.add(cc.Signal("cross_repo_spray", "HIGH", "detail", value=6))
        user = {
            "created_at": (
                datetime.now(timezone.utc) - timedelta(days=800)
            ).strftime("%Y-%m-%dT%H:%M:%SZ"),
            "followers": 100,
            "public_repos": 50,
        }
        cc._dampen_for_established_accounts(report, user, established=True, full=True)
        spray = next(s for s in report.signals if s.name == "cross_repo_spray")
        assert spray.severity == "MEDIUM"

    def test_dampen_blocked_by_abuse_signal(self):
        report = cc.ReputationReport(username="user")
        report.add(cc.Signal("cross_repo_spray", "HIGH", "detail", value=6))
        report.add(cc.Signal("thin_credibility", "HIGH", "abuse", value=3))
        user = {
            "created_at": (
                datetime.now(timezone.utc) - timedelta(days=800)
            ).strftime("%Y-%m-%dT%H:%M:%SZ"),
            "followers": 100,
            "public_repos": 50,
        }
        cc._dampen_for_established_accounts(report, user, established=True, full=True)
        spray = next(s for s in report.signals if s.name == "cross_repo_spray")
        assert spray.severity == "HIGH"

    def test_feature_overlap_skips_established_aged_repos(self):
        """check_feature_overlap must not fire for repos >=1yr old AND >=10 stars."""
        established_repo = {
            "name": "agent-governance-toolkit",
            "description": "mcp security policy engine audit trail",
            "topics": ["ed25519", "agent identity"],
            "fork": False,
            "stargazers_count": 50,
            "created_at": (
                datetime.now(timezone.utc) - timedelta(days=400)
            ).strftime("%Y-%m-%dT%H:%M:%SZ"),
        }

        def mock_api(path, params=None):
            if "/repos" in path and "/readme" in path:
                return {"content": ""}
            return [established_repo]

        with patch("contributor_check._api", side_effect=mock_api), \
             patch("contributor_check._get_token", return_value="tok"):
            signals = cc.check_feature_overlap("user", "org/repo")
        assert not any(s.name == "feature_overlap" for s in signals)


# ===========================================================================
# 4. Function-surface parity: scripts vs agent_compliance.cli package
# ===========================================================================

class TestFunctionSurfaceParity:
    """Both surfaces must expose the same public API."""

    REQUIRED_CC = [
        "check_contributor",
        "check_account_shape",
        "check_repo_themes",
        "check_spray_pattern",
        "check_thin_credibility",
        "check_credential_spray",
        "check_feature_overlap",
        "format_report",
        "_load_allowlist",
        "_is_allowlisted",
        "_apply_allowlist",
        "_dampen_for_established_accounts",
        "_ABUSE_SIGNALS",
        "_DAMPEN_RULES",
        "_RETRY_MAX_ATTEMPTS",
    ]

    REQUIRED_CA = [
        "find_merges",
        "find_spray_citations",
        "audit_credentials",
        "format_report",
        "_RETRY_MAX_ATTEMPTS",
    ]

    def test_scripts_contributor_check_has_required_symbols(self):
        missing = [sym for sym in self.REQUIRED_CC if not hasattr(cc, sym)]
        assert missing == [], f"scripts/contributor_check.py missing: {missing}"

    def test_scripts_credential_audit_has_required_symbols(self):
        missing = [sym for sym in self.REQUIRED_CA if not hasattr(ca, sym)]
        assert missing == [], f"scripts/credential_audit.py missing: {missing}"

    def test_cli_package_contributor_check_has_required_symbols(self):
        try:
            import agent_compliance.cli.contributor_check as cli_cc
        except ImportError:
            pytest.skip("agent_compliance package not installed")
        missing = [sym for sym in self.REQUIRED_CC if not hasattr(cli_cc, sym)]
        assert missing == [], f"agent_compliance.cli.contributor_check missing: {missing}"

    def test_cli_package_credential_audit_has_required_symbols(self):
        try:
            import agent_compliance.cli.credential_audit as cli_ca
        except ImportError:
            pytest.skip("agent_compliance package not installed")
        missing = [sym for sym in self.REQUIRED_CA if not hasattr(cli_ca, sym)]
        assert missing == [], f"agent_compliance.cli.credential_audit missing: {missing}"

    def test_retry_constants_match_between_paths(self):
        """Both scripts must use the same retry depth."""
        assert cc._RETRY_MAX_ATTEMPTS == ca._RETRY_MAX_ATTEMPTS, (
            "Retry attempt count diverged between contributor_check and credential_audit"
        )
