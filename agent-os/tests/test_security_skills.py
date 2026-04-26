# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""Tests for security_skills static analysis checks."""

import textwrap

import pytest

from agent_os.security_skills import (
    SecurityFinding,
    Severity,
    check_error_info_leak,
    check_hardcoded_denylist,
    check_hardcoded_secrets,
    check_missing_circuit_breaker,
    check_redos_patterns,
    check_ssrf_urls,
    check_stub_security,
    check_trust_without_crypto,
    check_unbounded_collections,
    check_unsafe_pickle,
    format_findings,
    scan_source,
)


# ---------------------------------------------------------------------------
# SKILL-001: Stub security implementations
# ---------------------------------------------------------------------------

class TestStubSecurity:
    def test_detects_verify_stub(self):
        src = textwrap.dedent("""\
            def verify(self, peer_did):
                return True
        """)
        findings = check_stub_security(src)
        assert len(findings) == 1
        assert findings[0].rule_id == "SKILL-001"
        assert findings[0].severity == Severity.CRITICAL

    def test_detects_validate_stub(self):
        src = textwrap.dedent("""\
            def validate(self, token):
                return True
        """)
        findings = check_stub_security(src)
        assert len(findings) == 1
        assert findings[0].title.startswith("Stub security function: validate")

    def test_detects_authenticate_stub(self):
        src = textwrap.dedent("""\
            def authenticate(request):
                return True
        """)
        findings = check_stub_security(src)
        assert len(findings) == 1

    def test_ignores_real_implementation(self):
        src = textwrap.dedent("""\
            def verify(self, peer_did):
                peer = self.registry.get(peer_did)
                if not peer:
                    return False
                return self._check_signature(peer)
        """)
        findings = check_stub_security(src)
        assert len(findings) == 0

    def test_ignores_non_security_functions(self):
        src = textwrap.dedent("""\
            def process(self, data):
                return True
        """)
        findings = check_stub_security(src)
        assert len(findings) == 0


# ---------------------------------------------------------------------------
# SKILL-002: Unsafe pickle
# ---------------------------------------------------------------------------

class TestUnsafePickle:
    def test_detects_bare_pickle_loads(self):
        src = "data = pickle.loads(raw_bytes)"
        findings = check_unsafe_pickle(src)
        assert len(findings) == 1
        assert findings[0].rule_id == "SKILL-002"
        assert findings[0].severity == Severity.CRITICAL

    def test_ignores_pickle_with_hmac(self):
        src = textwrap.dedent("""\
            sig = hmac.new(key, raw, hashlib.sha256).hexdigest()
            if not hmac.compare_digest(sig, expected):
                raise ValueError()
            data = pickle.loads(raw)
        """)
        findings = check_unsafe_pickle(src)
        assert len(findings) == 0

    def test_no_findings_without_pickle(self):
        src = "data = json.loads(raw)"
        findings = check_unsafe_pickle(src)
        assert len(findings) == 0


# ---------------------------------------------------------------------------
# SKILL-003: Hardcoded deny-lists
# ---------------------------------------------------------------------------

class TestHardcodedDenylist:
    def test_detects_dangerous_patterns_list(self):
        src = 'dangerous_patterns = ["DROP TABLE", "DELETE FROM"]'
        findings = check_hardcoded_denylist(src)
        assert len(findings) == 1
        assert findings[0].rule_id == "SKILL-003"
        assert findings[0].severity == Severity.HIGH

    def test_detects_harm_patterns(self):
        src = 'HARM_PATTERNS = ["violence", "weapons"]'
        findings = check_hardcoded_denylist(src)
        assert len(findings) == 1

    def test_no_findings_for_normal_lists(self):
        src = 'my_items = ["apple", "banana"]'
        findings = check_hardcoded_denylist(src)
        assert len(findings) == 0


# ---------------------------------------------------------------------------
# SKILL-004: Unbounded collections
# ---------------------------------------------------------------------------

class TestUnboundedCollections:
    def test_detects_unbounded_cache(self):
        src = "self._cache = {}"
        findings = check_unbounded_collections(src)
        assert len(findings) == 1
        assert findings[0].rule_id == "SKILL-004"
        assert findings[0].severity == Severity.MEDIUM

    def test_detects_unbounded_sessions(self):
        src = "self._sessions = dict()"
        findings = check_unbounded_collections(src)
        assert len(findings) == 1

    def test_ignores_with_eviction(self):
        src = textwrap.dedent("""\
            self._cache = {}
            if len(self._cache) >= self._MAX_ENTRIES:
                self._cache.popitem()
        """)
        findings = check_unbounded_collections(src)
        assert len(findings) == 0

    def test_ignores_with_max_size(self):
        src = textwrap.dedent("""\
            self._sessions = {}
            self._max_sessions = 1000
        """)
        findings = check_unbounded_collections(src)
        assert len(findings) == 0


# ---------------------------------------------------------------------------
# SKILL-005: SSRF URLs
# ---------------------------------------------------------------------------

class TestSsrfUrls:
    def test_detects_url_from_input(self):
        src = "server_url = config['endpoint']"
        findings = check_ssrf_urls(src)
        assert len(findings) == 1
        assert findings[0].rule_id == "SKILL-005"
        assert findings[0].severity == Severity.HIGH

    def test_ignores_with_ssrf_guard(self):
        src = textwrap.dedent("""\
            server_url = config['endpoint']
            validate_url(server_url)
        """)
        findings = check_ssrf_urls(src)
        assert len(findings) == 0

    def test_no_findings_for_hardcoded_url(self):
        src = 'url = "https://api.microsoft.com"'
        findings = check_ssrf_urls(src)
        assert len(findings) == 0


# ---------------------------------------------------------------------------
# SKILL-006: Missing circuit breaker
# ---------------------------------------------------------------------------

class TestMissingCircuitBreaker:
    def test_detects_bare_requests(self):
        src = "resp = requests.get(url)"
        findings = check_missing_circuit_breaker(src)
        assert len(findings) == 1
        assert findings[0].rule_id == "SKILL-006"

    def test_detects_bare_httpx(self):
        src = "resp = await httpx.AsyncClient().get(url)"
        findings = check_missing_circuit_breaker(src)
        assert len(findings) == 1

    def test_ignores_with_circuit_breaker(self):
        src = textwrap.dedent("""\
            resp = requests.get(url)
            self._failures_threshold = 5
        """)
        findings = check_missing_circuit_breaker(src)
        assert len(findings) == 0

    def test_ignores_with_tenacity(self):
        src = textwrap.dedent("""\
            import tenacity
            resp = requests.get(url)
        """)
        findings = check_missing_circuit_breaker(src)
        assert len(findings) == 0

    def test_no_findings_without_external_calls(self):
        src = "result = compute_locally(data)"
        findings = check_missing_circuit_breaker(src)
        assert len(findings) == 0


# ---------------------------------------------------------------------------
# SKILL-007: ReDoS patterns
# ---------------------------------------------------------------------------

class TestRedosPatterns:
    def test_detects_nested_quantifiers(self):
        src = """pattern = re.compile(".+.+dangerous")"""
        findings = check_redos_patterns(src)
        assert len(findings) == 1
        assert findings[0].rule_id == "SKILL-007"

    def test_ignores_safe_patterns(self):
        src = """pattern = re.compile("[a-z]+@[a-z]+\\.com")"""
        findings = check_redos_patterns(src)
        assert len(findings) == 0


# ---------------------------------------------------------------------------
# SKILL-008: Hardcoded secrets
# ---------------------------------------------------------------------------

class TestHardcodedSecrets:
    def test_detects_api_key(self):
        src = 'api_key = "sk-abcdefghijklmnopqrstuvwxyz123456"'
        findings = check_hardcoded_secrets(src, path="config.py")
        assert len(findings) >= 1
        assert any(f.rule_id == "SKILL-008" for f in findings)

    def test_detects_aws_key(self):
        src = 'aws_key = "AKIAIOSFODNN7EXAMPLE"'
        findings = check_hardcoded_secrets(src, path="deploy.py")
        assert len(findings) == 1
        assert findings[0].severity == Severity.CRITICAL

    def test_detects_github_token(self):
        src = 'token = "ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghij"'
        findings = check_hardcoded_secrets(src, path="ci.py")
        assert len(findings) >= 1
        assert any(f.title == "Hardcoded secret: GitHub token" for f in findings)

    def test_skips_test_files(self):
        src = 'api_key = "sk-abcdefghijklmnopqrstuvwxyz123456"'
        findings = check_hardcoded_secrets(src, path="test_auth.py")
        assert len(findings) == 0

    def test_skips_placeholders(self):
        src = 'api_key = "YOUR_API_KEY_HERE"'
        findings = check_hardcoded_secrets(src, path="config.py")
        assert len(findings) == 0


# ---------------------------------------------------------------------------
# SKILL-009: Trust without crypto
# ---------------------------------------------------------------------------

class TestTrustWithoutCrypto:
    def test_detects_hardcoded_trust(self):
        src = 'trust_score = 750'
        findings = check_trust_without_crypto(src)
        assert len(findings) == 1
        assert findings[0].rule_id == "SKILL-009"
        assert findings[0].severity == Severity.HIGH

    def test_detects_verified_true(self):
        src = 'verified = True'
        findings = check_trust_without_crypto(src)
        assert len(findings) == 1

    def test_ignores_with_crypto(self):
        src = textwrap.dedent("""\
            trust_score = 750
            from nacl.signing import VerifyKey
        """)
        findings = check_trust_without_crypto(src)
        assert len(findings) == 0

    def test_ignores_with_ed25519(self):
        src = textwrap.dedent("""\
            verified = True
            sig = ed25519.verify(data, signature)
        """)
        findings = check_trust_without_crypto(src)
        assert len(findings) == 0


# ---------------------------------------------------------------------------
# SKILL-010: Error info leak
# ---------------------------------------------------------------------------

class TestErrorInfoLeak:
    def test_detects_str_exception(self):
        src = textwrap.dedent("""\
            except Exception as e:
                return {"error": str(e)}
        """)
        findings = check_error_info_leak(src)
        assert len(findings) == 1
        assert findings[0].rule_id == "SKILL-010"

    def test_detects_repr_exception(self):
        src = textwrap.dedent("""\
            except Exception as err:
                return repr(err)
        """)
        findings = check_error_info_leak(src)
        assert len(findings) == 1

    def test_ignores_with_sanitization(self):
        src = textwrap.dedent("""\
            except Exception as e:
                return {"error": type(e).__name__}
        """)
        findings = check_error_info_leak(src)
        assert len(findings) == 0


# ---------------------------------------------------------------------------
# Aggregate scan
# ---------------------------------------------------------------------------

class TestScanSource:
    def test_finds_multiple_issues(self):
        src = textwrap.dedent("""\
            dangerous_patterns = ["DROP TABLE"]
            data = pickle.loads(raw_bytes)
            def verify(self, peer):
                return True
        """)
        findings = scan_source(src, "bad_code.py")
        rule_ids = {f.rule_id for f in findings}
        assert "SKILL-001" in rule_ids
        assert "SKILL-002" in rule_ids
        assert "SKILL-003" in rule_ids

    def test_clean_code_passes(self):
        src = textwrap.dedent("""\
            def process_data(items):
                return [item.strip() for item in items]
        """)
        findings = scan_source(src)
        assert len(findings) == 0


# ---------------------------------------------------------------------------
# Format output
# ---------------------------------------------------------------------------

class TestFormatFindings:
    def test_no_findings(self):
        result = format_findings([])
        assert "passed" in result
        assert "✅" in result

    def test_with_findings(self):
        findings = [
            SecurityFinding(
                rule_id="SKILL-001",
                title="Test finding",
                severity=Severity.CRITICAL,
                description="A critical issue",
                file_path="test.py",
                line_number=10,
            ),
        ]
        result = format_findings(findings)
        assert "SKILL-001" in result
        assert "critical" in result.lower()
        assert "❌" in result
