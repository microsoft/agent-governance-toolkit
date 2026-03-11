"""Tests for langflow-agentmesh package.

Tests governance policy, governance component, trust router,
audit logger, and compliance checker. No Langflow dependency
required — tests the governance engine directly.
"""

import json
import tempfile
import os

import pytest

from langflow_agentmesh.policy import (
    GovernancePolicy,
    GovernanceEventType,
    PatternType,
    PolicyCheckResult,
)
from langflow_agentmesh.governance_component import (
    GovernanceComponent,
    GovernanceResult,
)
from langflow_agentmesh.trust_router import (
    TrustRouter,
    TrustScore,
    RouteDecision,
    RouteResult,
)
from langflow_agentmesh.audit_logger import (
    AuditLogger,
    AuditEntry,
    GENESIS_HASH,
)
from langflow_agentmesh.compliance_checker import (
    ComplianceChecker,
    ComplianceFramework,
    ComplianceStatus,
    RiskLevel,
)


# ─── GovernancePolicy ────────────────────────────────────────────────


class TestGovernancePolicy:
    def test_default_policy(self):
        policy = GovernancePolicy()
        assert policy.max_tool_calls_per_request == 10
        assert policy.blocked_patterns == []
        assert policy.allowed_tools == []
        assert policy.blocked_tools == []

    def test_check_content_no_patterns(self):
        policy = GovernancePolicy()
        result = policy.check_content("hello world")
        assert result.allowed is True

    def test_check_content_substring_match(self):
        policy = GovernancePolicy(
            blocked_patterns=[("rm -rf", PatternType.SUBSTRING)]
        )
        result = policy.check_content("please run rm -rf /tmp")
        assert result.allowed is False
        assert "rm -rf" in result.reason

    def test_check_content_regex_match(self):
        policy = GovernancePolicy(
            blocked_patterns=[(r"password\s*=\s*\w+", PatternType.REGEX)]
        )
        result = policy.check_content("set password = secret123")
        assert result.allowed is False

    def test_check_content_glob_match(self):
        policy = GovernancePolicy(
            blocked_patterns=[("*.exe", PatternType.GLOB)]
        )
        result = policy.check_content("download malware.exe")
        assert result.allowed is False

    def test_check_tool_blocklist(self):
        policy = GovernancePolicy(blocked_tools=["delete", "drop"])
        assert policy.check_tool("delete").allowed is False
        assert policy.check_tool("search").allowed is True

    def test_check_tool_allowlist(self):
        policy = GovernancePolicy(allowed_tools=["search", "read"])
        assert policy.check_tool("search").allowed is True
        assert policy.check_tool("delete").allowed is False

    def test_check_tool_blocklist_overrides_allowlist(self):
        policy = GovernancePolicy(
            allowed_tools=["search", "delete"],
            blocked_tools=["delete"],
        )
        assert policy.check_tool("delete").allowed is False

    def test_check_arguments_blocks_patterns(self):
        policy = GovernancePolicy(
            blocked_patterns=[("DROP TABLE", PatternType.SUBSTRING)]
        )
        result = policy.check_arguments({"query": "DROP TABLE users"})
        assert result.allowed is False
        assert result.metadata.get("argument_key") == "query"

    def test_check_call_count(self):
        policy = GovernancePolicy(max_tool_calls_per_request=3)
        assert policy.check_call_count(3).allowed is True
        assert policy.check_call_count(4).allowed is False

    def test_enforce_allowed(self):
        policy = GovernancePolicy()
        result = policy.enforce("search", {"query": "hello"}, agent_id="a1")
        assert result.allowed is True

    def test_enforce_blocked_tool(self):
        policy = GovernancePolicy(blocked_tools=["delete"])
        result = policy.enforce("delete", {}, agent_id="a1")
        assert result.allowed is False

    def test_to_dict_roundtrip(self):
        policy = GovernancePolicy(
            allowed_tools=["search"],
            blocked_tools=["delete"],
            blocked_patterns=[("rm -rf", PatternType.SUBSTRING)],
        )
        d = policy.to_dict()
        restored = GovernancePolicy.from_dict(d)
        assert restored.allowed_tools == ["search"]
        assert restored.blocked_tools == ["delete"]
        assert len(restored.blocked_patterns) == 1

    def test_yaml_roundtrip(self):
        policy = GovernancePolicy(
            allowed_tools=["search", "read"],
            blocked_tools=["delete"],
            blocked_patterns=[
                ("rm -rf", PatternType.SUBSTRING),
                (r".*secret.*", PatternType.REGEX),
            ],
            confidence_threshold=0.9,
        )
        yaml_str = policy.to_yaml()
        restored = GovernancePolicy.from_yaml(yaml_str)
        assert restored.confidence_threshold == 0.9
        assert len(restored.blocked_patterns) == 2
        assert restored.allowed_tools == ["search", "read"]
        assert restored.blocked_tools == ["delete"]


# ─── GovernanceComponent ─────────────────────────────────────────────


class TestGovernanceComponent:
    def test_allowed_action(self):
        comp = GovernanceComponent()
        result = comp.process("search", {"query": "hello"}, agent_id="a1")
        assert result.allowed is True
        assert result.action == "search"

    def test_blocked_tool(self):
        comp = GovernanceComponent(blocked_tools=["delete"])
        result = comp.process("delete", {}, agent_id="a1")
        assert result.allowed is False
        assert "blocklist" in result.violation_reason

    def test_blocked_pattern(self):
        comp = GovernanceComponent(
            blocked_patterns=[("rm -rf", "substring")]
        )
        result = comp.process("execute", {"cmd": "rm -rf /"}, agent_id="a1")
        assert result.allowed is False

    def test_call_count_limit(self):
        comp = GovernanceComponent(max_calls=2)
        assert comp.process("a", {}).allowed is True
        assert comp.process("b", {}).allowed is True
        assert comp.process("c", {}).allowed is False

    def test_reset(self):
        comp = GovernanceComponent(max_calls=1)
        assert comp.process("a", {}).allowed is True
        assert comp.process("b", {}).allowed is False
        comp.reset()
        assert comp.process("c", {}).allowed is True

    def test_policy_yaml_init(self):
        yaml_str = """
max_tool_calls_per_request: 5
allowed_tools:
  - search
blocked_patterns:
  - pattern: "danger"
    type: substring
"""
        comp = GovernanceComponent(policy_yaml=yaml_str)
        assert comp.policy.max_tool_calls_per_request == 5
        assert comp.process("search", {"q": "safe"}).allowed is True
        assert comp.process("delete", {}).allowed is False

    def test_result_to_dict(self):
        comp = GovernanceComponent()
        result = comp.process("search", {"q": "test"}, agent_id="a1")
        d = result.to_dict()
        assert d["allowed"] is True
        assert d["action"] == "search"
        assert "violation_reason" not in d


# ─── TrustRouter ─────────────────────────────────────────────────────


class TestTrustRouter:
    def test_default_routes_to_review(self):
        router = TrustRouter()
        result = router.route("agent-1", payload="data")
        # Default trust is 0.5 — between 0.3 (review) and 0.7 (trusted)
        assert result.decision == RouteDecision.REVIEW

    def test_trusted_route(self):
        router = TrustRouter(trusted_threshold=0.4)
        result = router.route("agent-1", payload="data")
        assert result.decision == RouteDecision.TRUSTED
        assert router.get_trusted_output(result) == "data"
        assert router.get_review_output(result) is None
        assert router.get_blocked_output(result) is None

    def test_blocked_route(self):
        router = TrustRouter(review_threshold=0.6, trusted_threshold=0.8)
        result = router.route("agent-1")
        assert result.decision == RouteDecision.BLOCKED

    def test_record_success_boosts_trust(self):
        router = TrustRouter(reward_rate=0.1)
        router.record_success("agent-1", dimensions=["reliability"])
        score = router.get_score("agent-1")
        assert score.reliability == 0.6

    def test_record_failure_lowers_trust(self):
        router = TrustRouter(penalty_rate=0.2)
        router.record_failure("agent-1", dimensions=["security"])
        score = router.get_score("agent-1")
        assert score.security == 0.3

    def test_asymmetric_reward_penalty(self):
        router = TrustRouter(reward_rate=0.05, penalty_rate=0.10)
        router.record_success("agent-1", dimensions=["reliability"])
        router.record_failure("agent-1", dimensions=["reliability"])
        score = router.get_score("agent-1")
        # 0.5 + 0.05 - 0.10 = 0.45
        assert score.reliability == 0.45

    def test_decay(self):
        router = TrustRouter(decay_rate=0.1)
        router.get_score("agent-1")  # Create default
        router.apply_decay("agent-1", hours_elapsed=2.0)
        score = router.get_score("agent-1")
        assert score.reliability == 0.3  # 0.5 - 0.1*2

    def test_trust_capped_at_1(self):
        router = TrustRouter(reward_rate=0.9)
        router.record_success("a1", dimensions=["reliability"])
        router.record_success("a1", dimensions=["reliability"])
        assert router.get_score("a1").reliability == 1.0

    def test_trust_floored_at_0(self):
        router = TrustRouter(penalty_rate=0.9)
        router.record_failure("a1", dimensions=["reliability"])
        assert router.get_score("a1").reliability == 0.0

    def test_invalid_thresholds(self):
        with pytest.raises(ValueError):
            TrustRouter(trusted_threshold=0.3, review_threshold=0.7)

    def test_route_result_to_dict(self):
        router = TrustRouter()
        result = router.route("agent-1")
        d = result.to_dict()
        assert "decision" in d
        assert "trust_score" in d

    def test_trust_score_to_dict(self):
        score = TrustScore()
        d = score.to_dict()
        assert len(d) == 6
        assert "overall" in d


# ─── AuditLogger ─────────────────────────────────────────────────────


class TestAuditLogger:
    def test_empty_logger(self):
        logger = AuditLogger()
        assert logger.chain_length == 0
        assert logger.verify_chain() is True

    def test_log_entry(self):
        logger = AuditLogger()
        entry = logger.log(
            agent_id="a1", action="search", decision="allowed",
            context={"query": "hello"}, timestamp=1000.0,
        )
        assert entry.agent_id == "a1"
        assert entry.previous_hash == GENESIS_HASH
        assert entry.entry_hash != ""
        assert logger.chain_length == 1

    def test_chain_linkage(self):
        logger = AuditLogger()
        e1 = logger.log("a1", "search", "allowed", timestamp=1000.0)
        e2 = logger.log("a1", "read", "allowed", timestamp=1001.0)
        assert e2.previous_hash == e1.entry_hash

    def test_verify_chain_valid(self):
        logger = AuditLogger()
        logger.log("a1", "search", "allowed", timestamp=1000.0)
        logger.log("a2", "read", "blocked", timestamp=1001.0)
        logger.log("a1", "write", "allowed", timestamp=1002.0)
        assert logger.verify_chain() is True

    def test_verify_chain_detects_tampering(self):
        logger = AuditLogger()
        logger.log("a1", "search", "allowed", timestamp=1000.0)
        logger.log("a1", "read", "allowed", timestamp=1001.0)
        # Tamper with an entry
        logger._entries[0].action = "tampered"
        assert logger.verify_chain() is False

    def test_export_jsonl(self):
        logger = AuditLogger()
        logger.log("a1", "search", "allowed", timestamp=1000.0)
        logger.log("a2", "read", "blocked", timestamp=1001.0)
        jsonl = logger.export_jsonl()
        lines = jsonl.strip().split("\n")
        assert len(lines) == 2
        parsed = json.loads(lines[0])
        assert parsed["agent_id"] == "a1"

    def test_export_jsonl_to_file(self):
        logger = AuditLogger()
        logger.log("a1", "search", "allowed", timestamp=1000.0)
        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".jsonl", delete=False
        ) as f:
            path = f.name
        try:
            count = logger.export_jsonl_to_file(path)
            assert count == 1
            with open(path) as f:
                content = f.read()
            assert "a1" in content
        finally:
            os.unlink(path)

    def test_summary(self):
        logger = AuditLogger()
        logger.log("a1", "search", "allowed", timestamp=1000.0)
        logger.log("a2", "read", "blocked", timestamp=1001.0)
        logger.log("a1", "write", "allowed", timestamp=1002.0)
        summary = logger.summary()
        assert summary["total_entries"] == 3
        assert summary["unique_agents"] == 2
        assert summary["decisions"]["allowed"] == 2
        assert summary["decisions"]["blocked"] == 1
        assert summary["chain_valid"] is True

    def test_entry_to_dict(self):
        logger = AuditLogger()
        entry = logger.log("a1", "search", "allowed", timestamp=1000.0)
        d = entry.to_dict()
        assert d["agent_id"] == "a1"
        assert d["entry_hash"] != ""


# ─── ComplianceChecker ───────────────────────────────────────────────


class TestComplianceChecker:
    def test_all_frameworks_checked(self):
        checker = ComplianceChecker()
        result = checker.check(
            "search", {"query": "hello"}, agent_id="a1",
            context={"audit_enabled": True, "access_logged": True},
        )
        assert "eu_ai_act" in result.frameworks_checked
        assert "soc2" in result.frameworks_checked
        assert "hipaa" in result.frameworks_checked

    def test_compliant_action(self):
        checker = ComplianceChecker()
        result = checker.check(
            "search", {"query": "hello"}, agent_id="a1",
            context={"audit_enabled": True, "access_logged": True},
        )
        assert result.compliance_status == ComplianceStatus.COMPLIANT

    def test_eu_ai_act_unacceptable_risk(self):
        checker = ComplianceChecker(frameworks=[ComplianceFramework.EU_AI_ACT])
        result = checker.check(
            "social_scoring", {}, agent_id="a1",
        )
        assert result.compliance_status == ComplianceStatus.NON_COMPLIANT
        assert any("Article 5" in v.rule for v in result.violations)

    def test_eu_ai_act_high_risk_missing_transparency(self):
        checker = ComplianceChecker(frameworks=[ComplianceFramework.EU_AI_ACT])
        result = checker.check(
            "classify", {}, agent_id="a1",
            context={"domain": "employment"},
        )
        assert result.compliance_status == ComplianceStatus.REQUIRES_REVIEW
        assert any("Transparency" in v.rule for v in result.violations)

    def test_eu_ai_act_high_risk_with_oversight(self):
        checker = ComplianceChecker(frameworks=[ComplianceFramework.EU_AI_ACT])
        result = checker.check(
            "classify", {}, agent_id="a1",
            context={
                "domain": "employment",
                "transparency_notice": True,
                "human_oversight": True,
            },
        )
        assert result.compliance_status == ComplianceStatus.COMPLIANT

    def test_soc2_missing_agent_id(self):
        checker = ComplianceChecker(frameworks=[ComplianceFramework.SOC2])
        result = checker.check(
            "search", {}, agent_id=None,
            context={"audit_enabled": True},
        )
        assert any("CC6.1" in v.rule for v in result.violations)

    def test_soc2_missing_audit(self):
        checker = ComplianceChecker(frameworks=[ComplianceFramework.SOC2])
        result = checker.check(
            "search", {}, agent_id="a1",
            context={"audit_enabled": False},
        )
        assert any("CC7.2" in v.rule for v in result.violations)

    def test_soc2_sensitive_action_unapproved(self):
        checker = ComplianceChecker(frameworks=[ComplianceFramework.SOC2])
        result = checker.check(
            "delete", {}, agent_id="a1",
            context={"audit_enabled": True},
        )
        assert any("CC8.1" in v.rule for v in result.violations)

    def test_hipaa_phi_ssn_detected(self):
        checker = ComplianceChecker(frameworks=[ComplianceFramework.HIPAA])
        result = checker.check(
            "query", {"data": "SSN: 123-45-6789"}, agent_id="a1",
            context={"access_logged": True},
        )
        assert result.compliance_status == ComplianceStatus.NON_COMPLIANT
        assert any("PHI" in v.rule for v in result.violations)

    def test_hipaa_phi_mrn_detected(self):
        checker = ComplianceChecker(frameworks=[ComplianceFramework.HIPAA])
        result = checker.check(
            "query", {"patient": "MRN: 12345"}, agent_id="a1",
            context={"access_logged": True},
        )
        assert result.compliance_status == ComplianceStatus.NON_COMPLIANT

    def test_hipaa_minimum_necessary(self):
        checker = ComplianceChecker(frameworks=[ComplianceFramework.HIPAA])
        result = checker.check(
            "query", {}, agent_id="a1",
            context={"data_scope": "full", "access_logged": True},
        )
        assert any("Minimum Necessary" in v.rule for v in result.violations)

    def test_hipaa_compliant(self):
        checker = ComplianceChecker(frameworks=[ComplianceFramework.HIPAA])
        result = checker.check(
            "search", {"query": "hello"}, agent_id="a1",
            context={"access_logged": True},
        )
        assert result.compliance_status == ComplianceStatus.COMPLIANT

    def test_single_framework(self):
        checker = ComplianceChecker(frameworks=[ComplianceFramework.EU_AI_ACT])
        result = checker.check("search", {}, agent_id="a1")
        assert result.frameworks_checked == ["eu_ai_act"]

    def test_result_to_dict(self):
        checker = ComplianceChecker()
        result = checker.check(
            "search", {}, agent_id="a1",
            context={"audit_enabled": True, "access_logged": True},
        )
        d = result.to_dict()
        assert "compliance_status" in d
        assert "frameworks_checked" in d
        assert "violations" in d
        assert "required_actions" in d

    def test_violation_to_dict(self):
        checker = ComplianceChecker(frameworks=[ComplianceFramework.SOC2])
        result = checker.check("search", {}, agent_id=None)
        assert len(result.violations) > 0
        v = result.violations[0].to_dict()
        assert "framework" in v
        assert "rule" in v
        assert "severity" in v
