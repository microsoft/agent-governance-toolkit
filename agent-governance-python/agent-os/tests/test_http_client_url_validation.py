"""Tests for HttpClientTool._validate_url (SSRF prevention).

These tests exercise the URL validation logic directly to verify
that userinfo-based SSRF bypasses are blocked.
"""

from urllib.parse import urlparse

import pytest


class _MinimalHttpClient:
    """Minimal stand-in that replicates _validate_url and _is_private_domain
    from atr.tools.safe.http_client without importing the full module tree."""

    def __init__(self, allowed_domains=None, blocked_domains=None):
        self.allowed_domains = set(allowed_domains or [])
        self.blocked_domains = set(blocked_domains or [
            "localhost",
            "127.0.0.1",
            "0.0.0.0",
            "169.254.169.254",
            "metadata.google.internal",
        ])

    # --- copied from the patched http_client.py ---

    def _validate_url(self, url: str) -> str:
        """Validate and normalize URL."""
        parsed = urlparse(url)

        if not parsed.scheme:
            raise ValueError("URL must include scheme (http:// or https://)")

        if parsed.scheme not in ("http", "https"):
            raise ValueError(f"Scheme '{parsed.scheme}' not allowed. Use http or https.")

        if "@" in (parsed.netloc or ""):
            raise ValueError("URLs with userinfo (user:password@host) are not allowed")

        domain = (parsed.hostname or "").lower()

        if not domain:
            raise ValueError("URL must include a valid hostname")

        if domain in self.blocked_domains:
            raise ValueError(f"Domain '{domain}' is blocked")

        if self._is_private_domain(domain):
            raise ValueError(f"Private/internal domains not allowed: {domain}")

        if self.allowed_domains:
            if not any(domain.endswith(allowed) for allowed in self.allowed_domains):
                raise ValueError(
                    f"Domain '{domain}' not in allowed list. "
                    f"Allowed: {', '.join(self.allowed_domains)}"
                )

        return url

    def _is_private_domain(self, domain: str) -> bool:
        private_patterns = [
            "10.", "192.168.",
            "172.16.", "172.17.", "172.18.", "172.19.",
            "172.20.", "172.21.", "172.22.", "172.23.",
            "172.24.", "172.25.", "172.26.", "172.27.",
            "172.28.", "172.29.", "172.30.", "172.31.",
            "internal", ".local",
        ]
        return any(domain.startswith(p) or domain.endswith(p) for p in private_patterns)


@pytest.fixture
def client():
    return _MinimalHttpClient()


@pytest.fixture
def allowlist_client():
    return _MinimalHttpClient(
        allowed_domains=["example.com", "api.contoso.com"],
    )


class TestValidUrlsAccepted:
    """Legitimate URLs should pass validation."""

    def test_simple_https(self, client):
        assert client._validate_url("https://example.com") == "https://example.com"

    def test_https_with_path(self, client):
        url = "https://api.example.com/v1/data"
        assert client._validate_url(url) == url

    def test_http_with_port(self, client):
        url = "http://example.com:8080/health"
        assert client._validate_url(url) == url

    def test_https_with_query(self, client):
        url = "https://example.com/search?q=test&page=1"
        assert client._validate_url(url) == url


class TestSchemeValidation:
    """Only http and https schemes are allowed."""

    def test_no_scheme_rejected(self, client):
        with pytest.raises(ValueError, match="must include scheme"):
            client._validate_url("example.com/path")

    def test_ftp_rejected(self, client):
        with pytest.raises(ValueError, match="not allowed"):
            client._validate_url("ftp://example.com/file")

    def test_file_rejected(self, client):
        with pytest.raises(ValueError, match="not allowed"):
            client._validate_url("file:///etc/passwd")


class TestUserinfoSSRFBypass:
    """URLs with userinfo must be rejected to prevent SSRF bypass.

    Attack: http://whitelisted.com:80@127.0.0.1:6666
    The netloc is 'whitelisted.com:80@127.0.0.1:6666'. Naive parsing
    extracts 'whitelisted.com' as the host, bypassing blocklists.
    The actual request goes to 127.0.0.1:6666.
    """

    def test_userinfo_basic(self, client):
        with pytest.raises(ValueError, match="userinfo"):
            client._validate_url("http://user:pass@example.com")

    def test_userinfo_ssrf_bypass_localhost(self, client):
        with pytest.raises(ValueError, match="userinfo"):
            client._validate_url("http://microsoft.com:80@127.0.0.1:6666")

    def test_userinfo_ssrf_bypass_metadata(self, client):
        with pytest.raises(ValueError, match="userinfo"):
            client._validate_url("http://example.com@169.254.169.254/latest/meta-data/")

    def test_userinfo_ssrf_bypass_private(self, client):
        with pytest.raises(ValueError, match="userinfo"):
            client._validate_url("https://allowed.com:443@192.168.1.1:8080")

    def test_userinfo_user_only(self, client):
        with pytest.raises(ValueError, match="userinfo"):
            client._validate_url("http://admin@10.0.0.1")

    def test_userinfo_with_allowlist(self, allowlist_client):
        with pytest.raises(ValueError, match="userinfo"):
            allowlist_client._validate_url("https://example.com:443@10.0.0.1")


class TestBlockedDomains:
    """Blocked domains (localhost, metadata endpoints) must be rejected."""

    def test_localhost_blocked(self, client):
        with pytest.raises(ValueError, match="blocked"):
            client._validate_url("http://localhost/admin")

    def test_127_blocked(self, client):
        with pytest.raises(ValueError, match="blocked"):
            client._validate_url("http://127.0.0.1:8080")

    def test_aws_metadata_blocked(self, client):
        with pytest.raises(ValueError, match="blocked"):
            client._validate_url("http://169.254.169.254/latest/meta-data/")

    def test_gcp_metadata_blocked(self, client):
        with pytest.raises(ValueError, match="blocked"):
            client._validate_url("http://metadata.google.internal/computeMetadata/v1/")

    def test_zero_ip_blocked(self, client):
        with pytest.raises(ValueError, match="blocked"):
            client._validate_url("http://0.0.0.0:80")


class TestPrivateIPRanges:
    """Private/internal IP ranges must be rejected."""

    def test_10_range(self, client):
        with pytest.raises(ValueError, match="Private"):
            client._validate_url("http://10.0.0.1/api")

    def test_192_168_range(self, client):
        with pytest.raises(ValueError, match="Private"):
            client._validate_url("http://192.168.1.1:3000")

    def test_172_16_range(self, client):
        with pytest.raises(ValueError, match="Private"):
            client._validate_url("http://172.16.0.1")

    def test_internal_suffix(self, client):
        with pytest.raises(ValueError, match="Private"):
            client._validate_url("http://service.internal:8080")

    def test_local_suffix(self, client):
        with pytest.raises(ValueError, match="Private"):
            client._validate_url("http://printer.local")


class TestAllowlist:
    """When an allowlist is set, only matching domains are permitted."""

    def test_allowed_domain_passes(self, allowlist_client):
        url = "https://example.com/api/v1"
        assert allowlist_client._validate_url(url) == url

    def test_allowed_subdomain_passes(self, allowlist_client):
        url = "https://api.contoso.com/data"
        assert allowlist_client._validate_url(url) == url

    def test_unlisted_domain_rejected(self, allowlist_client):
        with pytest.raises(ValueError, match="not in allowed list"):
            allowlist_client._validate_url("https://evil.com/steal")

    def test_port_does_not_affect_domain_check(self, allowlist_client):
        url = "https://example.com:8443/secure"
        assert allowlist_client._validate_url(url) == url


class TestEmptyHostname:
    """URLs without a valid hostname must be rejected."""

    def test_scheme_only(self, client):
        with pytest.raises(ValueError):
            client._validate_url("http://")

    def test_scheme_with_port_only(self, client):
        with pytest.raises(ValueError):
            client._validate_url("http://:8080")
