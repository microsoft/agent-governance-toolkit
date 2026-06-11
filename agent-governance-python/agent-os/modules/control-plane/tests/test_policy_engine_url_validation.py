# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""URL/domain validation tests for the PolicyEngine risk policies.

These tests pin the security-review fixes that replaced substring-based
domain matching with parsed, normalized hostname checks. Bypass cases
from the original implementation are captured explicitly so regressions
fail loudly.
"""

from __future__ import annotations

import uuid
from datetime import datetime

import pytest

from agent_control_plane.agent_kernel import (
    ActionType,
    AgentContext,
    ExecutionRequest,
)
from agent_control_plane.policy_engine import (
    PolicyEngine,
    RiskPolicy,
    _extract_host,
    _host_matches,
)


def _make_request(parameters: dict) -> ExecutionRequest:
    return ExecutionRequest(
        request_id=str(uuid.uuid4()),
        agent_context=AgentContext(
            agent_id="test-agent",
            session_id="sess-1",
            created_at=datetime.utcnow(),
        ),
        action_type=ActionType.API_CALL,
        parameters=parameters,
        timestamp=datetime.utcnow(),
    )


def _engine_with_policy(policy: RiskPolicy) -> PolicyEngine:
    engine = PolicyEngine()
    engine.risk_policies["default"] = policy
    return engine


# --- _extract_host / _host_matches unit cases -------------------------------


@pytest.mark.parametrize(
    "value,expected",
    [
        ("https://example.com/path?q=1", "example.com"),
        ("https://Example.COM:8443/x", "example.com"),
        ("example.com", "example.com"),
        ("example.com.", "example.com"),
        ("user:pass@example.com", "example.com"),
        ("https://user@evil.com@trusted.com/x", "trusted.com"),
        ("", None),
        (None, None),
        ("://", None),
        ("not a url", None),
        (12345, None),
    ],
)
def test_extract_host(value, expected):
    assert _extract_host(value) == expected


@pytest.mark.parametrize(
    "host,rule,expected",
    [
        ("example.com", "example.com", True),
        ("api.example.com", "example.com", True),
        ("example.com", "api.example.com", False),
        ("evil-example.com", "example.com", False),
        ("safe.com", "evil.com", False),
        ("example.com.attacker.io", "example.com", False),
        ("example.com", "Example.COM", True),
    ],
)
def test_host_matches(host, rule, expected):
    assert _host_matches(host, rule) is expected


# --- PolicyEngine.validate_risk: blocked domains ----------------------------


def test_blocked_domain_does_not_match_via_substring_in_query():
    """Regression: 'evil.com' must not match 'https://safe.com/?ref=evil.com'."""
    engine = _engine_with_policy(RiskPolicy(blocked_domains=["evil.com"]))
    request = _make_request({"url": "https://safe.com/?ref=evil.com"})
    assert engine.validate_risk(request, risk_score=0.1) is True


def test_blocked_domain_does_not_match_lookalike_hostname():
    """Regression: 'evil.com' must not match 'https://safe-evil.com/'."""
    engine = _engine_with_policy(RiskPolicy(blocked_domains=["evil.com"]))
    request = _make_request({"url": "https://safe-evil.com/path"})
    assert engine.validate_risk(request, risk_score=0.1) is True


def test_blocked_domain_blocks_exact_host():
    engine = _engine_with_policy(RiskPolicy(blocked_domains=["evil.com"]))
    request = _make_request({"url": "https://evil.com/payload"})
    assert engine.validate_risk(request, risk_score=0.1) is False


def test_blocked_domain_blocks_subdomain():
    engine = _engine_with_policy(RiskPolicy(blocked_domains=["evil.com"]))
    request = _make_request({"url": "https://api.evil.com/payload"})
    assert engine.validate_risk(request, risk_score=0.1) is False


# --- PolicyEngine.validate_risk: allowed domains ----------------------------


def test_allowed_domain_does_not_match_lookalike_hostname():
    """Regression: allowed='good.com' must not permit 'attacker-good.com.evil/'."""
    engine = _engine_with_policy(RiskPolicy(allowed_domains=["good.com"]))
    request = _make_request({"url": "https://attacker-good.com.evil/"})
    assert engine.validate_risk(request, risk_score=0.1) is False


def test_allowed_domain_does_not_match_substring_in_path():
    engine = _engine_with_policy(RiskPolicy(allowed_domains=["good.com"]))
    request = _make_request({"url": "https://attacker.io/redirect?to=good.com"})
    assert engine.validate_risk(request, risk_score=0.1) is False


def test_allowed_domain_permits_exact_host():
    engine = _engine_with_policy(RiskPolicy(allowed_domains=["good.com"]))
    request = _make_request({"url": "https://good.com/api"})
    assert engine.validate_risk(request, risk_score=0.1) is True


def test_allowed_domain_permits_subdomain():
    engine = _engine_with_policy(RiskPolicy(allowed_domains=["good.com"]))
    request = _make_request({"url": "https://api.good.com/v1"})
    assert engine.validate_risk(request, risk_score=0.1) is True


def test_allowlist_denies_unparseable_url_value():
    """Fail closed when an allowlist is configured but the URL is junk."""
    engine = _engine_with_policy(RiskPolicy(allowed_domains=["good.com"]))
    request = _make_request({"url": "not a url at all"})
    assert engine.validate_risk(request, risk_score=0.1) is False


def test_blocklist_denies_unparseable_url_value():
    """Fail closed for unparseable URLs even when only a blocklist is set."""
    engine = _engine_with_policy(RiskPolicy(blocked_domains=["evil.com"]))
    request = _make_request({"url": "not a url at all"})
    assert engine.validate_risk(request, risk_score=0.1) is False


def test_bare_domain_parameter_is_validated():
    engine = _engine_with_policy(RiskPolicy(allowed_domains=["good.com"]))
    request = _make_request({"domain": "api.good.com"})
    assert engine.validate_risk(request, risk_score=0.1) is True


def test_userinfo_in_url_does_not_bypass_allowlist():
    """Regression: 'good.com@evil.com' must resolve to host 'evil.com'."""
    engine = _engine_with_policy(RiskPolicy(allowed_domains=["good.com"]))
    request = _make_request({"url": "https://good.com@evil.com/"})
    assert engine.validate_risk(request, risk_score=0.1) is False
