# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""Tests for network egress policy enforcement."""
from __future__ import annotations

import pytest

from agent_os.egress_policy import EgressDecision, EgressPolicy, EgressRule


# ── EgressRule unit tests ────────────────────────────────────────────


class TestEgressRule:
    def test_exact_domain_match(self):
        rule = EgressRule(domain="api.github.com", ports=[443])
        assert rule.matches("api.github.com", 443, "tcp")

    def test_exact_domain_no_match(self):
        rule = EgressRule(domain="api.github.com", ports=[443])
        assert not rule.matches("evil.example.com", 443, "tcp")

    def test_wildcard_domain_match(self):
        rule = EgressRule(domain="*.openai.com", ports=[443])
        assert rule.matches("api.openai.com", 443, "tcp")
        assert rule.matches("models.openai.com", 443, "tcp")

    def test_wildcard_domain_no_match_root(self):
        rule = EgressRule(domain="*.openai.com", ports=[443])
        assert not rule.matches("openai.com", 443, "tcp")

    def test_port_mismatch(self):
        rule = EgressRule(domain="api.github.com", ports=[443])
        assert not rule.matches("api.github.com", 80, "tcp")

    def test_protocol_mismatch(self):
        rule = EgressRule(domain="api.github.com", ports=[443], protocol="tcp")
        assert not rule.matches("api.github.com", 443, "udp")

    def test_multiple_ports(self):
        rule = EgressRule(domain="example.com", ports=[80, 443])
        assert rule.matches("example.com", 80, "tcp")
        assert rule.matches("example.com", 443, "tcp")

    def test_case_insensitive_domain(self):
        rule = EgressRule(domain="API.GitHub.COM", ports=[443])
        assert rule.matches("api.github.com", 443, "tcp")

    def test_invalid_action(self):
        with pytest.raises(ValueError, match="action"):
            EgressRule(domain="x.com", ports=[443], action="block")

    def test_invalid_protocol(self):
        with pytest.raises(ValueError, match="protocol"):
            EgressRule(domain="x.com", ports=[443], protocol="icmp")


# ── EgressPolicy check tests ────────────────────────────────────────


class TestEgressPolicyCheck:
    def test_default_deny(self):
        policy = EgressPolicy(default_action="deny")
        decision = policy.check("evil.example.com", 443)
        assert not decision.allowed
        assert decision.matched_rule is None
        assert "default" in decision.reason

    def test_default_allow(self):
        policy = EgressPolicy(default_action="allow")
        decision = policy.check("anything.example.com", 443)
        assert decision.allowed

    def test_allow_rule(self):
        policy = EgressPolicy()
        policy.add_rule("*.openai.com", [443], action="allow")
        decision = policy.check("api.openai.com", 443)
        assert decision.allowed
        assert decision.matched_rule is not None

    def test_deny_rule(self):
        policy = EgressPolicy(default_action="allow")
        policy.add_rule("*.evil.com", [443], action="deny")
        decision = policy.check("malware.evil.com", 443)
        assert not decision.allowed

    def test_first_match_wins(self):
        policy = EgressPolicy()
        policy.add_rule("*.openai.com", [443], action="deny")
        policy.add_rule("api.openai.com", [443], action="allow")
        decision = policy.check("api.openai.com", 443)
        assert not decision.allowed  # first rule matched

    def test_multiple_rules_second_matches(self):
        policy = EgressPolicy()
        policy.add_rule("*.github.com", [443], action="allow")
        policy.add_rule("*.openai.com", [443], action="allow")
        decision = policy.check("api.openai.com", 443)
        assert decision.allowed
        assert decision.matched_rule is not None
        assert decision.matched_rule.domain == "*.openai.com"

    def test_invalid_default_action(self):
        with pytest.raises(ValueError, match="default_action"):
            EgressPolicy(default_action="block")


# ── EgressPolicy.check_url tests ────────────────────────────────────


class TestCheckUrl:
    def test_https_url(self):
        policy = EgressPolicy()
        policy.add_rule("api.openai.com", [443], action="allow")
        decision = policy.check_url("https://api.openai.com/v1/chat")
        assert decision.allowed

    def test_http_url_default_port(self):
        policy = EgressPolicy()
        policy.add_rule("example.com", [80], action="allow")
        decision = policy.check_url("http://example.com/path")
        assert decision.allowed

    def test_explicit_port_in_url(self):
        policy = EgressPolicy()
        policy.add_rule("example.com", [8080], action="allow")
        decision = policy.check_url("https://example.com:8080/api")
        assert decision.allowed

    def test_url_denied(self):
        policy = EgressPolicy()
        decision = policy.check_url("https://evil.example.com/steal")
        assert not decision.allowed


# ── YAML loading tests ──────────────────────────────────────────────


class TestLoadFromYaml:
    YAML_POLICY = """\
rules:
  - domain: "*.openai.com"
    ports: [443]
    protocol: tcp
    action: allow
  - domain: "api.github.com"
    ports: [443]
    protocol: tcp
    action: allow
  - domain: "*.evil.com"
    ports: [80, 443]
    protocol: tcp
    action: deny
"""

    def test_load_rules_count(self):
        policy = EgressPolicy()
        policy.load_from_yaml(self.YAML_POLICY)
        assert len(policy.rules) == 3

    def test_loaded_allow(self):
        policy = EgressPolicy()
        policy.load_from_yaml(self.YAML_POLICY)
        assert policy.check("api.openai.com", 443).allowed
        assert policy.check("api.github.com", 443).allowed

    def test_loaded_deny(self):
        policy = EgressPolicy()
        policy.load_from_yaml(self.YAML_POLICY)
        assert not policy.check("malware.evil.com", 443).allowed

    def test_empty_yaml(self):
        policy = EgressPolicy()
        policy.load_from_yaml("")
        assert len(policy.rules) == 0

    def test_yaml_with_comments(self):
        yaml = """\
# Egress whitelist
rules:
  # Allow OpenAI
  - domain: "*.openai.com"
    ports: [443]
    action: allow
"""
        policy = EgressPolicy()
        policy.load_from_yaml(yaml)
        assert len(policy.rules) == 1


# ── EgressDecision / dataclass tests ────────────────────────────────


class TestEgressDecision:
    def test_fields(self):
        rule = EgressRule(domain="a.com", ports=[443])
        d = EgressDecision(allowed=True, matched_rule=rule, reason="ok")
        assert d.allowed is True
        assert d.matched_rule is rule
        assert d.reason == "ok"

    def test_no_matched_rule(self):
        d = EgressDecision(allowed=False, matched_rule=None, reason="blocked")
        assert d.matched_rule is None
