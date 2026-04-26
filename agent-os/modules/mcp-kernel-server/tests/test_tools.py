# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""Tests for MCP Kernel Server tools."""

import sys
import os
import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'src'))

from mcp_kernel_server.tools import (
    VerifyCodeSafetyTool,
    CMVKVerifyTool,
    KernelExecuteTool,
    IATPSignTool,
    IATPVerifyTool,
    IATPReputationTool,
    CMVKReviewCodeTool,
    GetAuditLogTool,
    ToolResult,
)


# =============================================================================
# VerifyCodeSafetyTool Tests
# =============================================================================

class TestVerifyCodeSafetyTool:
    def setup_method(self):
        self.tool = VerifyCodeSafetyTool()

    @pytest.mark.asyncio
    async def test_safe_python_code(self):
        result = await self.tool.execute({"code": "print('hello world')", "language": "python"})
        assert result.success is True
        assert result.data["safe"] is True
        assert result.data["violations"] == []

    @pytest.mark.asyncio
    async def test_safe_js_code(self):
        result = await self.tool.execute({"code": "console.log('hi')", "language": "javascript"})
        assert result.data["safe"] is True

    @pytest.mark.asyncio
    async def test_detects_eval(self):
        result = await self.tool.execute({"code": "eval('malicious')", "language": "python"})
        assert result.data["safe"] is False
        violations = [v["rule"] for v in result.data["violations"]]
        assert "eval" in violations

    @pytest.mark.asyncio
    async def test_detects_exec(self):
        result = await self.tool.execute({"code": "exec('import os')", "language": "python"})
        assert result.data["safe"] is False
        violations = [v["rule"] for v in result.data["violations"]]
        assert "exec" in violations

    @pytest.mark.asyncio
    async def test_detects_drop_table(self):
        result = await self.tool.execute({"code": "DROP TABLE users", "language": "sql"})
        assert result.data["safe"] is False
        violations = [v["rule"] for v in result.data["violations"]]
        assert "drop_table" in violations

    @pytest.mark.asyncio
    async def test_detects_hardcoded_password(self):
        result = await self.tool.execute({"code": "password = 'secret123'", "language": "python"})
        assert result.data["safe"] is False
        violations = [v["rule"] for v in result.data["violations"]]
        assert "hardcoded_password" in violations

    @pytest.mark.asyncio
    async def test_detects_rm_rf(self):
        result = await self.tool.execute({"code": "rm -rf /tmp/data", "language": "bash"})
        assert result.data["safe"] is False

    @pytest.mark.asyncio
    async def test_detects_sudo(self):
        result = await self.tool.execute({"code": "sudo apt-get install foo", "language": "bash"})
        assert result.data["safe"] is False
        violations = [v["rule"] for v in result.data["violations"]]
        assert "sudo" in violations

    @pytest.mark.asyncio
    async def test_detects_chmod_777(self):
        result = await self.tool.execute({"code": "chmod 777 /var/log", "language": "bash"})
        assert result.data["safe"] is False

    @pytest.mark.asyncio
    async def test_blocked_reason_present(self):
        result = await self.tool.execute({"code": "eval('x')", "language": "python"})
        assert "blocked_reason" in result.data
        assert result.error is not None
        assert "BLOCKED" in result.error

    @pytest.mark.asyncio
    async def test_metadata_includes_tool_name(self):
        result = await self.tool.execute({"code": "x = 1", "language": "python"})
        assert result.metadata["tool"] == "verify_code_safety"

    @pytest.mark.asyncio
    async def test_rules_checked_count(self):
        result = await self.tool.execute({"code": "x = 1", "language": "python"})
        assert result.data["rules_checked"] > 0

    @pytest.mark.asyncio
    async def test_code_length_in_result(self):
        code = "print('hello')"
        result = await self.tool.execute({"code": code, "language": "python"})
        assert result.data["code_length"] == len(code)


# =============================================================================
# CMVKVerifyTool Tests
# =============================================================================

class TestCMVKVerifyTool:
    def setup_method(self):
        self.tool = CMVKVerifyTool({"threshold": 0.85})

    @pytest.mark.asyncio
    async def test_basic_claim_verification(self):
        result = await self.tool.execute({"claim": "The sky is blue", "context": "weather"})
        assert result.success is True
        assert "verified" in result.data
        assert "confidence" in result.data
        assert "drift_score" in result.data

    @pytest.mark.asyncio
    async def test_threshold_is_used(self):
        result = await self.tool.execute({"claim": "test claim", "threshold": 0.5})
        assert result.metadata["threshold_used"] == 0.5

    @pytest.mark.asyncio
    async def test_default_threshold(self):
        result = await self.tool.execute({"claim": "test claim"})
        assert result.metadata["threshold_used"] == 0.85

    @pytest.mark.asyncio
    async def test_models_checked_list(self):
        result = await self.tool.execute({"claim": "test"})
        assert len(result.data["models_checked"]) == 3

    @pytest.mark.asyncio
    async def test_drift_details_present(self):
        result = await self.tool.execute({"claim": "test"})
        assert "drift_details" in result.data
        assert len(result.data["drift_details"]) > 0

    def test_interpret_result_strong_consensus(self):
        msg = self.tool._interpret_result(True, 0.95, 0.05)
        assert "Strong consensus" in msg

    def test_interpret_result_moderate_consensus(self):
        msg = self.tool._interpret_result(True, 0.8, 0.1)
        assert "moderate confidence" in msg

    def test_interpret_result_significant_disagreement(self):
        msg = self.tool._interpret_result(False, 0.5, 0.3)
        assert "Significant disagreement" in msg

    def test_interpret_result_weak_consensus(self):
        msg = self.tool._interpret_result(False, 0.5, 0.1)
        assert "Weak consensus" in msg


# =============================================================================
# KernelExecuteTool Tests
# =============================================================================

class TestKernelExecuteTool:
    def setup_method(self):
        self.tool = KernelExecuteTool({"policy_mode": "strict"})

    @pytest.mark.asyncio
    async def test_allowed_database_query(self):
        result = await self.tool.execute({
            "action": "database_query",
            "params": {"query": "SELECT 1"},
            "agent_id": "test-agent",
            "policies": [],
        })
        assert result.success is True
        assert result.data["action"] == "database_query"

    @pytest.mark.asyncio
    async def test_allowed_api_call(self):
        result = await self.tool.execute({
            "action": "api_call",
            "params": {"url": "https://example.com"},
            "agent_id": "test-agent",
            "policies": [],
        })
        assert result.success is True

    @pytest.mark.asyncio
    async def test_read_only_blocks_file_write(self):
        result = await self.tool.execute({
            "action": "file_write",
            "params": {"path": "/tmp/test.txt"},
            "agent_id": "test-agent",
            "policies": ["read_only"],
        })
        assert result.success is False
        assert "SIGKILL" in result.error
        assert result.metadata["signal"] == "SIGKILL"

    @pytest.mark.asyncio
    async def test_read_only_blocks_send_email(self):
        result = await self.tool.execute({
            "action": "send_email",
            "params": {},
            "agent_id": "test-agent",
            "policies": ["read_only"],
        })
        assert result.success is False
        assert "read_only" in result.error

    @pytest.mark.asyncio
    async def test_read_only_blocks_write_query(self):
        result = await self.tool.execute({
            "action": "database_query",
            "params": {"query": "INSERT INTO users VALUES (1)"},
            "agent_id": "test-agent",
            "policies": ["read_only"],
        })
        assert result.success is False

    @pytest.mark.asyncio
    async def test_no_pii_blocks_ssn(self):
        result = await self.tool.execute({
            "action": "api_call",
            "params": {"data": "ssn: 123-45-6789"},
            "agent_id": "test-agent",
            "policies": ["no_pii"],
        })
        assert result.success is False
        assert "PII" in result.error or "pii" in result.error.lower()

    @pytest.mark.asyncio
    async def test_no_pii_blocks_credit_card(self):
        result = await self.tool.execute({
            "action": "api_call",
            "params": {"credit_card": "4111111111111111"},
            "agent_id": "test-agent",
            "policies": ["no_pii"],
        })
        assert result.success is False

    @pytest.mark.asyncio
    async def test_requires_approval_blocks_unapproved(self):
        result = await self.tool.execute({
            "action": "file_write",
            "params": {"path": "/tmp/test.txt"},
            "agent_id": "test-agent",
            "policies": [],
        })
        assert result.success is False
        assert "requires approval" in result.error

    @pytest.mark.asyncio
    async def test_requires_approval_passes_with_approval(self):
        result = await self.tool.execute({
            "action": "file_write",
            "params": {"path": "/tmp/test.txt", "approved": True},
            "agent_id": "test-agent",
            "policies": [],
        })
        assert result.success is True

    def test_check_policies_read_only(self):
        result = self.tool._check_policies("file_write", {}, ["read_only"])
        assert result["allowed"] is False

    def test_check_policies_allowed(self):
        result = self.tool._check_policies("database_query", {"query": "SELECT 1"}, [])
        assert result["allowed"] is True

    def test_check_policies_no_pii_password(self):
        result = self.tool._check_policies("api_call", {"password": "secret"}, ["no_pii"])
        assert result["allowed"] is False

    @pytest.mark.asyncio
    async def test_metadata_includes_agent_id(self):
        result = await self.tool.execute({
            "action": "database_query",
            "params": {"query": "SELECT 1"},
            "agent_id": "agent-42",
            "policies": [],
        })
        assert result.metadata["agent_id"] == "agent-42"


# =============================================================================
# IATPSignTool Tests
# =============================================================================

class TestIATPSignTool:
    def setup_method(self):
        self.tool = IATPSignTool()

    @pytest.mark.asyncio
    async def test_sign_content(self):
        result = await self.tool.execute({
            "content": "hello world",
            "agent_id": "agent-1",
            "capabilities": ["reversible"],
        })
        assert result.success is True
        assert "signature" in result.data
        assert "content_hash" in result.data

    @pytest.mark.asyncio
    async def test_signature_deterministic(self):
        args = {"content": "same content", "agent_id": "agent-1", "capabilities": ["x"]}
        r1 = await self.tool.execute(args)
        r2 = await self.tool.execute(args)
        assert r1.data["signature"] == r2.data["signature"]

    @pytest.mark.asyncio
    async def test_signature_changes_with_different_content(self):
        r1 = await self.tool.execute({"content": "content-a", "agent_id": "agent-1"})
        r2 = await self.tool.execute({"content": "content-b", "agent_id": "agent-1"})
        assert r1.data["signature"] != r2.data["signature"]

    @pytest.mark.asyncio
    async def test_content_hash_included(self):
        result = await self.tool.execute({"content": "test", "agent_id": "agent-1"})
        assert len(result.data["content_hash"]) == 16

    @pytest.mark.asyncio
    async def test_protocol_version(self):
        result = await self.tool.execute({"content": "test", "agent_id": "agent-1"})
        assert result.data["protocol_version"] == "iatp-1.0"


# =============================================================================
# IATPVerifyTool Tests
# =============================================================================

class TestIATPVerifyTool:
    def setup_method(self):
        self.tool = IATPVerifyTool()

    @pytest.mark.asyncio
    async def test_verify_standard_agent(self):
        result = await self.tool.execute({
            "remote_agent_id": "remote-agent-1",
            "required_trust_level": "standard",
        })
        assert result.success is True
        assert result.data["verified"] is True

    @pytest.mark.asyncio
    async def test_verify_any_trust_level(self):
        result = await self.tool.execute({
            "remote_agent_id": "remote-agent-1",
            "required_trust_level": "any",
        })
        assert result.success is True

    @pytest.mark.asyncio
    async def test_verify_trusted_requires_higher_score(self):
        # Default simulated manifest has trust_level="standard" (score=5) + modifiers
        # Need trust score >= 7 for "trusted"
        result = await self.tool.execute({
            "remote_agent_id": "test-agent",
            "required_trust_level": "trusted",
        })
        # Default manifest gives standard(5) + reversibility(2) + ephemeral(1) = 8
        assert result.success is True

    @pytest.mark.asyncio
    async def test_verify_verified_partner_default_manifest(self):
        # verified_partner requires score >= 10
        result = await self.tool.execute({
            "remote_agent_id": "test-agent",
            "required_trust_level": "verified_partner",
        })
        # Default: standard(5) + reversibility(2) + ephemeral(1) = 8 < 10
        assert result.success is False

    @pytest.mark.asyncio
    async def test_pii_requires_ephemeral(self):
        # Default manifest has ephemeral retention, so PII should pass
        result = await self.tool.execute({
            "remote_agent_id": "test-agent",
            "data_classification": "pii",
        })
        assert result.success is True

    @pytest.mark.asyncio
    async def test_pii_blocked_non_ephemeral(self):
        tool = IATPVerifyTool({
            "agent_registry": {
                "non-ephemeral-agent": {
                    "agent_id": "non-ephemeral-agent",
                    "trust_level": "trusted",
                    "scopes": ["data:read"],
                    "reversibility": {"level": "full"},
                    "privacy": {"retention_policy": "permanent", "human_in_loop": False, "training_consent": False},
                }
            }
        })
        result = await tool.execute({
            "remote_agent_id": "non-ephemeral-agent",
            "data_classification": "pii",
        })
        assert result.success is False
        assert "PII" in result.error or "ephemeral" in result.error

    def test_calculate_trust_score_standard(self):
        manifest = {
            "trust_level": "standard",
            "reversibility": {"level": "none"},
            "privacy": {"retention_policy": "temporary", "human_in_loop": False, "training_consent": False},
        }
        score = self.tool._calculate_trust_score(manifest)
        assert score == 5  # standard base

    def test_calculate_trust_score_with_reversibility(self):
        manifest = {
            "trust_level": "standard",
            "reversibility": {"level": "full"},
            "privacy": {"retention_policy": "temporary", "human_in_loop": False, "training_consent": False},
        }
        score = self.tool._calculate_trust_score(manifest)
        assert score == 7  # standard(5) + reversibility(2)

    def test_calculate_trust_score_capped_at_10(self):
        manifest = {
            "trust_level": "verified_partner",
            "reversibility": {"level": "full"},
            "privacy": {"retention_policy": "ephemeral", "human_in_loop": False, "training_consent": False},
        }
        score = self.tool._calculate_trust_score(manifest)
        assert score <= 10

    @pytest.mark.asyncio
    async def test_missing_scopes_rejected(self):
        result = await self.tool.execute({
            "remote_agent_id": "test-agent",
            "required_scopes": ["admin:delete"],
        })
        assert result.success is False
        assert "scopes" in result.error.lower()


# =============================================================================
# IATPReputationTool Tests
# =============================================================================

class TestIATPReputationTool:
    def setup_method(self):
        self.tool = IATPReputationTool()

    @pytest.mark.asyncio
    async def test_query_default_reputation(self):
        result = await self.tool.execute({"action": "query", "agent_id": "new-agent"})
        assert result.success is True
        assert result.data["reputation_score"] == 5.0
        assert result.data["trust_level"] == "standard"

    @pytest.mark.asyncio
    async def test_slash_high_severity(self):
        result = await self.tool.execute({
            "action": "slash",
            "agent_id": "bad-agent",
            "slash_reason": "hallucination",
            "slash_severity": "high",
        })
        assert result.success is True
        assert result.data["penalty_applied"] == 1.0
        assert result.data["new_score"] == 4.0  # 5.0 - 1.0

    @pytest.mark.asyncio
    async def test_slash_critical_severity(self):
        result = await self.tool.execute({
            "action": "slash",
            "agent_id": "very-bad-agent",
            "slash_reason": "data breach",
            "slash_severity": "critical",
        })
        assert result.data["penalty_applied"] == 2.0
        assert result.data["new_score"] == 3.0  # 5.0 - 2.0

    @pytest.mark.asyncio
    async def test_slash_medium_severity(self):
        result = await self.tool.execute({
            "action": "slash",
            "agent_id": "med-agent",
            "slash_reason": "minor issue",
            "slash_severity": "medium",
        })
        assert result.data["penalty_applied"] == 0.5

    @pytest.mark.asyncio
    async def test_slash_low_severity(self):
        result = await self.tool.execute({
            "action": "slash",
            "agent_id": "low-agent",
            "slash_reason": "typo",
            "slash_severity": "low",
        })
        assert result.data["penalty_applied"] == 0.25

    @pytest.mark.asyncio
    async def test_slash_score_floor_at_zero(self):
        # Slash multiple times to drive below zero
        for _ in range(5):
            await self.tool.execute({
                "action": "slash",
                "agent_id": "floor-agent",
                "slash_reason": "repeated",
                "slash_severity": "critical",
            })
        result = await self.tool.execute({"action": "query", "agent_id": "floor-agent"})
        assert result.data["reputation_score"] >= 0.0

    @pytest.mark.asyncio
    async def test_unknown_action(self):
        result = await self.tool.execute({"action": "invalid", "agent_id": "x"})
        assert result.success is False

    @pytest.mark.asyncio
    async def test_query_after_slash_reflects_change(self):
        await self.tool.execute({
            "action": "slash",
            "agent_id": "tracked-agent",
            "slash_reason": "test",
            "slash_severity": "high",
        })
        result = await self.tool.execute({"action": "query", "agent_id": "tracked-agent"})
        assert result.data["reputation_score"] == 4.0


# =============================================================================
# CMVKReviewCodeTool Tests
# =============================================================================

class TestCMVKReviewCodeTool:
    def setup_method(self):
        self.tool = CMVKReviewCodeTool()

    @pytest.mark.asyncio
    async def test_clean_code(self):
        result = await self.tool.execute({"code": "x = 1", "language": "python"})
        assert result.success is True
        assert "consensus" in result.data

    @pytest.mark.asyncio
    async def test_detects_sql_injection(self):
        code = 'q = base + "SELECT+1"'
        result = await self.tool.execute({"code": code, "language": "python", "focus": ["security"]})
        issues = [i["issue"] for i in result.data["issues"]]
        assert any("SQL injection" in i for i in issues)

    @pytest.mark.asyncio
    async def test_detects_eval_usage(self):
        result = await self.tool.execute({"code": "eval(user_input)", "language": "python", "focus": ["security"]})
        issues = [i["issue"] for i in result.data["issues"]]
        assert any("eval" in i.lower() for i in issues)

    @pytest.mark.asyncio
    async def test_detects_innerhtml(self):
        code = 'element.innerHTML = userInput;'
        result = await self.tool.execute({"code": code, "language": "javascript", "focus": ["security"]})
        issues = [i["issue"] for i in result.data["issues"]]
        assert any("innerHTML" in i or "XSS" in i for i in issues)

    @pytest.mark.asyncio
    async def test_focus_filtering_security_only(self):
        code = 'x = 1'
        result = await self.tool.execute({"code": code, "language": "python", "focus": ["security"]})
        assert result.data["focus_areas"] == ["security"]

    @pytest.mark.asyncio
    async def test_models_used(self):
        result = await self.tool.execute({"code": "x = 1", "language": "python"})
        assert len(result.data["models_used"]) == 3


# =============================================================================
# GetAuditLogTool Tests
# =============================================================================

class TestGetAuditLogTool:
    def setup_method(self):
        # Clear the class-level audit log before each test
        GetAuditLogTool._audit_log.clear()
        self.tool = GetAuditLogTool()

    def test_log_entry_class_method(self):
        GetAuditLogTool.log_entry({"type": "test", "agent_id": "a1", "message": "hello"})
        assert len(GetAuditLogTool._audit_log) == 1
        assert GetAuditLogTool._audit_log[0]["type"] == "test"
        assert "timestamp" in GetAuditLogTool._audit_log[0]

    @pytest.mark.asyncio
    async def test_retrieve_entries(self):
        GetAuditLogTool.log_entry({"type": "test", "agent_id": "a1"})
        GetAuditLogTool.log_entry({"type": "blocked", "agent_id": "a2"})
        result = await self.tool.execute({"limit": 10})
        assert result.success is True
        assert result.data["returned"] == 2

    @pytest.mark.asyncio
    async def test_filter_by_agent_id(self):
        GetAuditLogTool.log_entry({"type": "test", "agent_id": "a1"})
        GetAuditLogTool.log_entry({"type": "test", "agent_id": "a2"})
        result = await self.tool.execute({"limit": 10, "filter": {"agent_id": "a1"}})
        assert result.data["returned"] == 1
        assert result.data["logs"][0]["agent_id"] == "a1"

    @pytest.mark.asyncio
    async def test_filter_by_type(self):
        GetAuditLogTool.log_entry({"type": "blocked", "agent_id": "a1"})
        GetAuditLogTool.log_entry({"type": "allowed", "agent_id": "a2"})
        result = await self.tool.execute({"limit": 10, "filter": {"type": "blocked"}})
        assert result.data["returned"] == 1

    @pytest.mark.asyncio
    async def test_limit_applied(self):
        for i in range(20):
            GetAuditLogTool.log_entry({"type": "test", "agent_id": f"a{i}"})
        result = await self.tool.execute({"limit": 5})
        assert result.data["returned"] == 5

    @pytest.mark.asyncio
    async def test_stats_include_blocked_count(self):
        GetAuditLogTool.log_entry({"type": "blocked", "agent_id": "a1"})
        GetAuditLogTool.log_entry({"type": "allowed", "agent_id": "a2"})
        result = await self.tool.execute({"limit": 10})
        assert result.data["stats"]["blocked_total"] == 1
        assert result.data["stats"]["allowed_total"] == 1

    @pytest.mark.asyncio
    async def test_empty_log(self):
        result = await self.tool.execute({"limit": 10})
        assert result.data["returned"] == 0
        assert result.data["logs"] == []


# =============================================================================
# ToolResult Tests
# =============================================================================

class TestToolResult:
    def test_tool_result_creation(self):
        result = ToolResult(success=True, data={"key": "value"})
        assert result.success is True
        assert result.data == {"key": "value"}
        assert result.error is None
        assert result.metadata == {}

    def test_tool_result_with_error(self):
        result = ToolResult(success=False, data=None, error="something failed")
        assert result.success is False
        assert result.error == "something failed"
