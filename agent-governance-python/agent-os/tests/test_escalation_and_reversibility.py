# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""Tests for human escalation workflows and reversibility checker."""

import asyncio
import pytest

from agent_os.escalation import (
    EscalationDecision,
    EscalationManager,
    EscalationOutcome,
    EscalationPolicy,
    EscalationRequest,
)
from agent_os.reversibility import (
    CompensatingAction,
    ReversibilityChecker,
    ReversibilityLevel,
)


class TestEscalationPolicy:
    def test_requires_approval_exact_match(self):
        policy = EscalationPolicy(actions_requiring_approval=["deploy", "delete_file"])
        manager = EscalationManager(policy)
        assert manager.requires_approval("deploy")
        assert manager.requires_approval("delete_file")
        assert not manager.requires_approval("read_file")

    def test_requires_approval_pattern(self):
        policy = EscalationPolicy(action_patterns_requiring_approval=[r"^delete_"])
        manager = EscalationManager(policy)
        assert manager.requires_approval("delete_file")
        assert manager.requires_approval("delete_record")
        assert not manager.requires_approval("read_file")

    def test_requires_approval_classification(self):
        policy = EscalationPolicy(classifications_requiring_approval=["RESTRICTED"])
        manager = EscalationManager(policy)
        assert manager.requires_approval("read_file", classification="RESTRICTED")
        assert not manager.requires_approval("read_file", classification="PUBLIC")


class TestEscalationManager:
    @pytest.mark.asyncio
    async def test_auto_approve_non_escalated(self):
        policy = EscalationPolicy(actions_requiring_approval=["deploy"])
        manager = EscalationManager(policy)
        decision = await manager.request_approval("agent-1", "read_file")
        assert decision.approved
        assert decision.outcome == EscalationOutcome.AUTO_APPROVED

    @pytest.mark.asyncio
    async def test_timeout_deny_default(self):
        policy = EscalationPolicy(
            actions_requiring_approval=["deploy"],
            timeout_seconds=1,
            default_on_timeout="deny",
        )
        manager = EscalationManager(policy)
        decision = await manager.request_approval("agent-1", "deploy")
        assert not decision.approved
        assert decision.outcome == EscalationOutcome.TIMED_OUT

    @pytest.mark.asyncio
    async def test_timeout_approve_if_configured(self):
        policy = EscalationPolicy(
            actions_requiring_approval=["deploy"],
            timeout_seconds=1,
            default_on_timeout="approve",
        )
        manager = EscalationManager(policy)
        decision = await manager.request_approval("agent-1", "deploy")
        assert decision.approved
        assert decision.outcome == EscalationOutcome.TIMED_OUT

    @pytest.mark.asyncio
    async def test_human_approve(self):
        policy = EscalationPolicy(
            actions_requiring_approval=["deploy"],
            timeout_seconds=5,
        )
        manager = EscalationManager(policy)

        async def approve_after_delay():
            await asyncio.sleep(0.2)
            for req in manager.pending_requests:
                manager.approve(req.request_id, decided_by="alice@co.com")

        asyncio.create_task(approve_after_delay())
        decision = await manager.request_approval("agent-1", "deploy")
        assert decision.approved
        assert decision.outcome == EscalationOutcome.APPROVED
        assert decision.decided_by == "alice@co.com"

    @pytest.mark.asyncio
    async def test_human_deny(self):
        policy = EscalationPolicy(
            actions_requiring_approval=["deploy"],
            timeout_seconds=5,
        )
        manager = EscalationManager(policy)

        async def deny_after_delay():
            await asyncio.sleep(0.2)
            for req in manager.pending_requests:
                manager.deny(req.request_id, decided_by="bob@co.com")

        asyncio.create_task(deny_after_delay())
        decision = await manager.request_approval("agent-1", "deploy")
        assert not decision.approved
        assert decision.outcome == EscalationOutcome.DENIED

    @pytest.mark.asyncio
    async def test_audit_trail_populated(self):
        policy = EscalationPolicy(actions_requiring_approval=["deploy"], timeout_seconds=1)
        manager = EscalationManager(policy)
        await manager.request_approval("agent-1", "deploy")
        assert len(manager.audit_trail) >= 2  # escalated + decided

    @pytest.mark.asyncio
    async def test_notification_handler_called(self):
        notified = []

        async def handler(req: EscalationRequest):
            notified.append(req.request_id)

        policy = EscalationPolicy(actions_requiring_approval=["deploy"], timeout_seconds=1)
        manager = EscalationManager(policy, approval_handler=handler)
        await manager.request_approval("agent-1", "deploy")
        assert len(notified) == 1


class TestReversibilityChecker:
    def setup_method(self):
        self.checker = ReversibilityChecker()

    def test_fully_reversible(self):
        assessment = self.checker.assess("write_file")
        assert assessment.level == ReversibilityLevel.FULLY_REVERSIBLE
        assert not assessment.requires_extra_approval

    def test_partially_reversible(self):
        assessment = self.checker.assess("send_email")
        assert assessment.level == ReversibilityLevel.PARTIALLY_REVERSIBLE
        assert len(assessment.compensating_actions) > 0

    def test_irreversible(self):
        assessment = self.checker.assess("deploy")
        assert assessment.level == ReversibilityLevel.IRREVERSIBLE
        assert assessment.requires_extra_approval

    def test_unknown_action(self):
        assessment = self.checker.assess("unknown_action_xyz")
        assert assessment.level == ReversibilityLevel.UNKNOWN
        assert assessment.requires_extra_approval

    def test_is_safe(self):
        assert self.checker.is_safe("write_file")
        assert self.checker.is_safe("create_file")
        assert not self.checker.is_safe("deploy")
        assert not self.checker.is_safe("delete_file")

    def test_block_irreversible(self):
        checker = ReversibilityChecker(block_irreversible=True)
        assert checker.should_block("deploy")
        assert checker.should_block("execute_code")
        assert not checker.should_block("write_file")

    def test_compensation_plan(self):
        plan = self.checker.get_compensation_plan("send_email")
        assert len(plan) >= 1
        assert any("recall" in a.action for a in plan)

    def test_custom_rules(self):
        checker = ReversibilityChecker(custom_rules={
            "my_action": {
                "level": ReversibilityLevel.FULLY_REVERSIBLE,
                "reason": "Custom action is safe",
                "compensating": [],
            }
        })
        assessment = checker.assess("my_action")
        assert assessment.level == ReversibilityLevel.FULLY_REVERSIBLE

    def test_delete_is_irreversible(self):
        for action in ["delete_file", "delete_record", "execute_code", "ssh_connect"]:
            assessment = self.checker.assess(action)
            assert assessment.level == ReversibilityLevel.IRREVERSIBLE, f"{action} should be irreversible"
