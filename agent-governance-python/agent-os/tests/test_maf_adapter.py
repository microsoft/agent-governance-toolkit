# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""Tests for Microsoft Agent Framework (MAF) governance adapter."""

from __future__ import annotations

import time
from unittest.mock import AsyncMock, MagicMock

import pytest

pytest.importorskip("agentmesh", reason="agentmesh not installed")
pytest.importorskip("agent_sre", reason="agent_sre not installed")

from agentmesh.governance import AuditLog
from agent_os.policies import PolicyDecision, PolicyEvaluator
from agent_sre.anomaly import RiskLevel, RogueAgentDetector, RogueDetectorConfig

from agent_os.integrations.maf_adapter import (
    AuditTrailMiddleware,
    CapabilityGuardMiddleware,
    GovernancePolicyMiddleware,
    MiddlewareTermination,
    RogueDetectionMiddleware,
    create_governance_middleware,
)


# ── Helpers ──────────────────────────────────────────────────────────────


def _make_agent_context(
    agent_name: str = "test-agent",
    messages: list | None = None,
    metadata: dict | None = None,
) -> MagicMock:
    """Create a mock AgentContext."""
    ctx = MagicMock()
    ctx.agent = MagicMock()
    ctx.agent.name = agent_name
    # Build realistic Message mocks.
    ctx.messages = messages or []
    ctx.stream = False
    ctx.metadata = metadata if metadata is not None else {}
    ctx.result = None
    return ctx


def _make_message(role: str = "user", text: str = "Hello") -> MagicMock:
    """Create a mock MAF Message with a .text property."""
    msg = MagicMock()
    msg.role = role
    msg.text = text
    return msg


def _make_function_context(
    func_name: str = "web_search",
    arguments: dict | None = None,
    metadata: dict | None = None,
) -> MagicMock:
    """Create a mock FunctionInvocationContext."""
    ctx = MagicMock()
    ctx.function = MagicMock()
    ctx.function.name = func_name
    ctx.arguments = arguments or {"query": "test"}
    ctx.metadata = metadata if metadata is not None else {}
    ctx.result = None
    return ctx


# ── GovernancePolicyMiddleware ───────────────────────────────────────────


class TestGovernancePolicyMiddleware:
    @pytest.fixture
    def allow_evaluator(self) -> PolicyEvaluator:
        """An evaluator with no loaded policies → allows everything."""
        return PolicyEvaluator()

    @pytest.fixture
    def deny_evaluator(self, monkeypatch) -> PolicyEvaluator:
        """An evaluator that always denies."""
        evaluator = PolicyEvaluator()
        monkeypatch.setattr(
            evaluator,
            "evaluate",
            lambda ctx: PolicyDecision(
                allowed=False,
                matched_rule="test-deny-all",
                action="deny",
                reason="Denied by test policy",
            ),
        )
        return evaluator

    @pytest.mark.asyncio
    async def test_allows_when_policy_passes(self, allow_evaluator):
        mw = GovernancePolicyMiddleware(evaluator=allow_evaluator)
        msg = _make_message(text="What is the weather?")
        ctx = _make_agent_context(messages=[msg])
        call_next = AsyncMock()

        await mw.process(ctx, call_next)

        call_next.assert_awaited_once()
        assert ctx.metadata["governance_decision"].allowed is True

    @pytest.mark.asyncio
    async def test_denies_when_policy_fails(self, deny_evaluator):
        audit = AuditLog()
        mw = GovernancePolicyMiddleware(evaluator=deny_evaluator, audit_log=audit)
        msg = _make_message(text="Do something bad")
        ctx = _make_agent_context(messages=[msg])
        call_next = AsyncMock()

        with pytest.raises(MiddlewareTermination, match="Denied by test policy"):
            await mw.process(ctx, call_next)

        call_next.assert_not_awaited()
        # Result should be set to an AgentResponse with the violation message.
        assert ctx.result is not None
        assert ctx.metadata["governance_decision"].allowed is False

    @pytest.mark.asyncio
    async def test_logs_denial_to_audit(self, deny_evaluator):
        audit = AuditLog()
        mw = GovernancePolicyMiddleware(evaluator=deny_evaluator, audit_log=audit)
        ctx = _make_agent_context(messages=[_make_message()])
        call_next = AsyncMock()

        with pytest.raises(MiddlewareTermination):
            await mw.process(ctx, call_next)

        entries = audit.get_entries_by_type("policy_violation")
        assert len(entries) == 1
        assert entries[0].outcome == "denied"

    @pytest.mark.asyncio
    async def test_logs_allow_to_audit(self, allow_evaluator):
        audit = AuditLog()
        mw = GovernancePolicyMiddleware(evaluator=allow_evaluator, audit_log=audit)
        ctx = _make_agent_context(messages=[_make_message()])
        call_next = AsyncMock()

        await mw.process(ctx, call_next)

        entries = audit.get_entries_by_type("policy_evaluation")
        assert len(entries) == 1
        assert entries[0].outcome == "success"

    @pytest.mark.asyncio
    async def test_handles_empty_messages(self, allow_evaluator):
        mw = GovernancePolicyMiddleware(evaluator=allow_evaluator)
        ctx = _make_agent_context(messages=[])
        call_next = AsyncMock()

        await mw.process(ctx, call_next)

        call_next.assert_awaited_once()

    @pytest.mark.asyncio
    async def test_works_without_audit_log(self, deny_evaluator):
        mw = GovernancePolicyMiddleware(evaluator=deny_evaluator, audit_log=None)
        ctx = _make_agent_context(messages=[_make_message()])
        call_next = AsyncMock()

        with pytest.raises(MiddlewareTermination):
            await mw.process(ctx, call_next)


# ── CapabilityGuardMiddleware ────────────────────────────────────────────


class TestCapabilityGuardMiddleware:
    @pytest.mark.asyncio
    async def test_allows_tool_in_allowed_list(self):
        mw = CapabilityGuardMiddleware(allowed_tools=["web_search", "file_read"])
        ctx = _make_function_context(func_name="web_search")
        call_next = AsyncMock()

        await mw.process(ctx, call_next)

        call_next.assert_awaited_once()

    @pytest.mark.asyncio
    async def test_blocks_tool_not_in_allowed_list(self):
        mw = CapabilityGuardMiddleware(allowed_tools=["web_search", "file_read"])
        ctx = _make_function_context(func_name="shell_exec")
        call_next = AsyncMock()

        with pytest.raises(MiddlewareTermination, match="not permitted"):
            await mw.process(ctx, call_next)

        call_next.assert_not_awaited()
        assert "not permitted" in ctx.result

    @pytest.mark.asyncio
    async def test_blocks_tool_in_denied_list(self):
        mw = CapabilityGuardMiddleware(denied_tools=["dangerous_tool"])
        ctx = _make_function_context(func_name="dangerous_tool")
        call_next = AsyncMock()

        with pytest.raises(MiddlewareTermination, match="not permitted"):
            await mw.process(ctx, call_next)

    @pytest.mark.asyncio
    async def test_denied_list_takes_precedence_over_allowed(self):
        mw = CapabilityGuardMiddleware(
            allowed_tools=["tool_a", "tool_b"],
            denied_tools=["tool_a"],
        )
        ctx = _make_function_context(func_name="tool_a")
        call_next = AsyncMock()

        with pytest.raises(MiddlewareTermination, match="not permitted"):
            await mw.process(ctx, call_next)

    @pytest.mark.asyncio
    async def test_allows_all_when_no_lists(self):
        mw = CapabilityGuardMiddleware()
        ctx = _make_function_context(func_name="anything_goes")
        call_next = AsyncMock()

        await mw.process(ctx, call_next)

        call_next.assert_awaited_once()

    @pytest.mark.asyncio
    async def test_logs_tool_invocation_to_audit(self):
        audit = AuditLog()
        mw = CapabilityGuardMiddleware(audit_log=audit)
        ctx = _make_function_context(func_name="web_search")
        call_next = AsyncMock()

        await mw.process(ctx, call_next)

        entries = audit.get_entries_by_type("tool_invocation")
        assert len(entries) == 2  # start + complete
        assert entries[0].action == "start"
        assert entries[1].action == "complete"

    @pytest.mark.asyncio
    async def test_logs_denied_tool_to_audit(self):
        audit = AuditLog()
        mw = CapabilityGuardMiddleware(
            denied_tools=["bad_tool"], audit_log=audit,
        )
        ctx = _make_function_context(func_name="bad_tool")
        call_next = AsyncMock()

        with pytest.raises(MiddlewareTermination):
            await mw.process(ctx, call_next)

        entries = audit.get_entries_by_type("tool_blocked")
        assert len(entries) == 1
        assert entries[0].outcome == "denied"


# ── AuditTrailMiddleware ─────────────────────────────────────────────────


class TestAuditTrailMiddleware:
    @pytest.mark.asyncio
    async def test_records_start_and_complete(self):
        audit = AuditLog()
        mw = AuditTrailMiddleware(audit_log=audit, agent_did="agent-007")
        ctx = _make_agent_context(messages=[_make_message()])
        call_next = AsyncMock()

        await mw.process(ctx, call_next)

        entries = audit.get_entries_by_type("agent_invocation")
        assert len(entries) == 2
        assert entries[0].action == "start"
        assert entries[1].action == "complete"
        assert entries[1].outcome == "success"

    @pytest.mark.asyncio
    async def test_stores_entry_id_in_metadata(self):
        audit = AuditLog()
        mw = AuditTrailMiddleware(audit_log=audit)
        ctx = _make_agent_context()
        call_next = AsyncMock()

        await mw.process(ctx, call_next)

        assert "audit_entry_id" in ctx.metadata
        assert ctx.metadata["audit_entry_id"].startswith("audit_")

    @pytest.mark.asyncio
    async def test_records_timing(self):
        audit = AuditLog()
        mw = AuditTrailMiddleware(audit_log=audit)
        ctx = _make_agent_context()
        call_next = AsyncMock()

        await mw.process(ctx, call_next)

        entries = audit.get_entries_by_type("agent_invocation")
        complete = entries[1]
        assert "elapsed_seconds" in complete.data
        assert complete.data["elapsed_seconds"] >= 0

    @pytest.mark.asyncio
    async def test_records_error_outcome_on_exception(self):
        audit = AuditLog()
        mw = AuditTrailMiddleware(audit_log=audit)
        ctx = _make_agent_context()
        call_next = AsyncMock(side_effect=ValueError("boom"))

        with pytest.raises(ValueError, match="boom"):
            await mw.process(ctx, call_next)

        entries = audit.get_entries_by_type("agent_invocation")
        complete = entries[1]
        assert complete.outcome == "error"
        assert "ValueError: boom" in complete.data["error"]

    @pytest.mark.asyncio
    async def test_uses_agent_name_when_no_did(self):
        audit = AuditLog()
        mw = AuditTrailMiddleware(audit_log=audit, agent_did=None)
        ctx = _make_agent_context(agent_name="my-researcher")
        call_next = AsyncMock()

        await mw.process(ctx, call_next)

        entries = audit.get_entries_for_agent("my-researcher")
        assert len(entries) == 2


# ── RogueDetectionMiddleware ─────────────────────────────────────────────


class TestRogueDetectionMiddleware:
    @pytest.fixture
    def detector(self) -> RogueAgentDetector:
        return RogueAgentDetector(config=RogueDetectorConfig())

    @pytest.mark.asyncio
    async def test_allows_low_risk_invocations(self, detector):
        mw = RogueDetectionMiddleware(
            detector=detector, agent_id="good-agent",
        )
        ctx = _make_function_context(func_name="web_search")
        call_next = AsyncMock()

        await mw.process(ctx, call_next)

        call_next.assert_awaited_once()

    @pytest.mark.asyncio
    async def test_registers_capability_profile(self, detector):
        mw = RogueDetectionMiddleware(
            detector=detector,
            agent_id="profiled-agent",
            capability_profile={"allowed_tools": ["search", "read"]},
        )
        # The profile should be registered on the detector's capability checker.
        profile = detector.capability_checker._profiles.get("profiled-agent")
        assert profile is not None
        assert "search" in profile

    @pytest.mark.asyncio
    async def test_blocks_quarantined_agent(self, detector, monkeypatch):
        audit = AuditLog()
        mw = RogueDetectionMiddleware(
            detector=detector,
            agent_id="rogue-agent",
            audit_log=audit,
        )

        # Force the detector to recommend quarantine.
        from agent_sre.anomaly.rogue_detector import RogueAssessment

        monkeypatch.setattr(
            detector,
            "assess",
            lambda agent_id, timestamp=None: RogueAssessment(
                agent_id=agent_id,
                risk_level=RiskLevel.CRITICAL,
                composite_score=5.0,
                frequency_score=2.0,
                entropy_score=1.5,
                capability_score=1.5,
                quarantine_recommended=True,
            ),
        )

        ctx = _make_function_context(func_name="some_tool")
        call_next = AsyncMock()

        with pytest.raises(MiddlewareTermination, match="quarantined"):
            await mw.process(ctx, call_next)

        call_next.assert_not_awaited()
        assert "quarantined" in ctx.result

        entries = audit.get_entries_by_type("rogue_detection")
        assert len(entries) == 1
        assert entries[0].action == "quarantine"

    @pytest.mark.asyncio
    async def test_warns_on_medium_risk(self, detector, monkeypatch):
        audit = AuditLog()
        mw = RogueDetectionMiddleware(
            detector=detector,
            agent_id="iffy-agent",
            audit_log=audit,
        )

        from agent_sre.anomaly.rogue_detector import RogueAssessment

        monkeypatch.setattr(
            detector,
            "assess",
            lambda agent_id, timestamp=None: RogueAssessment(
                agent_id=agent_id,
                risk_level=RiskLevel.MEDIUM,
                composite_score=1.5,
                frequency_score=0.5,
                entropy_score=0.5,
                capability_score=0.5,
                quarantine_recommended=False,
            ),
        )

        ctx = _make_function_context()
        call_next = AsyncMock()

        await mw.process(ctx, call_next)

        call_next.assert_awaited_once()  # Allowed despite warning.
        entries = audit.get_entries_by_type("rogue_detection")
        assert len(entries) == 1
        assert entries[0].action == "warning"

    @pytest.mark.asyncio
    async def test_works_without_audit_log(self, detector):
        mw = RogueDetectionMiddleware(
            detector=detector, agent_id="quiet-agent", audit_log=None,
        )
        ctx = _make_function_context()
        call_next = AsyncMock()

        await mw.process(ctx, call_next)
        call_next.assert_awaited_once()


# ── create_governance_middleware factory ──────────────────────────────────


class TestCreateGovernanceMiddleware:
    def test_returns_list(self):
        stack = create_governance_middleware(agent_id="a1")
        assert isinstance(stack, list)
        assert len(stack) > 0

    def test_includes_rogue_detection_by_default(self):
        stack = create_governance_middleware()
        types = [type(m).__name__ for m in stack]
        assert "RogueDetectionMiddleware" in types

    def test_disables_rogue_detection(self):
        stack = create_governance_middleware(enable_rogue_detection=False)
        types = [type(m).__name__ for m in stack]
        assert "RogueDetectionMiddleware" not in types

    def test_includes_capability_guard_when_tools_specified(self):
        stack = create_governance_middleware(
            allowed_tools=["search"],
            enable_rogue_detection=False,
        )
        types = [type(m).__name__ for m in stack]
        assert "CapabilityGuardMiddleware" in types

    def test_includes_audit_trail(self):
        audit = AuditLog()
        stack = create_governance_middleware(
            audit_log=audit, enable_rogue_detection=False,
        )
        types = [type(m).__name__ for m in stack]
        assert "AuditTrailMiddleware" in types

    def test_shares_audit_log_across_layers(self):
        audit = AuditLog()
        stack = create_governance_middleware(
            allowed_tools=["search"],
            audit_log=audit,
        )
        # All middleware that has audit_log should share the same instance.
        for mw in stack:
            if hasattr(mw, "audit_log") and mw.audit_log is not None:
                assert mw.audit_log is audit

    def test_creates_default_audit_log_when_none(self):
        stack = create_governance_middleware(
            allowed_tools=["search"],
            enable_rogue_detection=False,
        )
        audit_mw = [m for m in stack if isinstance(m, AuditTrailMiddleware)]
        assert len(audit_mw) == 1
        assert audit_mw[0].audit_log is not None
