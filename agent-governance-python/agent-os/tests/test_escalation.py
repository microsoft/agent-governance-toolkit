# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""Tests for human-in-the-loop escalation policy."""

import threading
import time

import pytest

from agent_os.integrations.base import BaseIntegration, ExecutionContext, GovernancePolicy
from agent_os.integrations.escalation import (
    ApprovalBackend,
    DefaultTimeoutAction,
    EscalationDecision,
    EscalationHandler,
    EscalationPolicy,
    EscalationRequest,
    EscalationResult,
    InMemoryApprovalQueue,
    QuorumConfig,
)


class _StubIntegration(BaseIntegration):
    """Minimal concrete BaseIntegration for testing."""

    def wrap(self, agent):
        return agent

    def unwrap(self, governed):
        return governed


@pytest.fixture
def policy_requires_approval():
    return GovernancePolicy(name="strict", require_human_approval=True)


@pytest.fixture
def policy_no_approval():
    return GovernancePolicy(name="relaxed", require_human_approval=False)


@pytest.fixture
def make_context():
    def _make(policy):
        return ExecutionContext(agent_id="agent-1", session_id="sess-1", policy=policy)
    return _make


class TestInMemoryApprovalQueue:
    def test_submit_and_get(self):
        queue = InMemoryApprovalQueue()
        req = EscalationRequest(agent_id="a1", action="write_file", reason="needs review")
        queue.submit(req)
        retrieved = queue.get_decision(req.request_id)
        assert retrieved is not None
        assert retrieved.decision == EscalationDecision.PENDING

    def test_approve(self):
        queue = InMemoryApprovalQueue()
        req = EscalationRequest(agent_id="a1", action="call_api", reason="policy")
        queue.submit(req)
        assert queue.approve(req.request_id, approver="admin") is True
        retrieved = queue.get_decision(req.request_id)
        assert retrieved.decision == EscalationDecision.ALLOW
        assert retrieved.resolved_by == "admin"
        assert retrieved.resolved_at is not None

    def test_deny(self):
        queue = InMemoryApprovalQueue()
        req = EscalationRequest(agent_id="a1", action="delete", reason="dangerous")
        queue.submit(req)
        assert queue.deny(req.request_id, approver="sec-team") is True
        retrieved = queue.get_decision(req.request_id)
        assert retrieved.decision == EscalationDecision.DENY

    def test_double_approve_same_approver_rejected(self):
        queue = InMemoryApprovalQueue()
        req = EscalationRequest(agent_id="a1", action="x", reason="r")
        queue.submit(req)
        assert queue.approve(req.request_id, approver="admin") is True
        assert queue.approve(req.request_id, approver="admin") is False  # duplicate vote

    def test_second_approver_vote_recorded(self):
        queue = InMemoryApprovalQueue()
        req = EscalationRequest(agent_id="a1", action="x", reason="r")
        queue.submit(req)
        assert queue.approve(req.request_id, approver="admin-a") is True
        assert queue.approve(req.request_id, approver="admin-b") is True
        retrieved = queue.get_decision(req.request_id)
        assert len(retrieved.votes) == 2
        approvers = [a for a, _, _ in retrieved.votes]
        assert "admin-a" in approvers
        assert "admin-b" in approvers

    def test_votes_recorded_on_approve(self):
        queue = InMemoryApprovalQueue()
        req = EscalationRequest(agent_id="a1", action="x", reason="r")
        queue.submit(req)
        queue.approve(req.request_id, approver="reviewer-1")
        retrieved = queue.get_decision(req.request_id)
        assert len(retrieved.votes) == 1
        approver, verdict, _ = retrieved.votes[0]
        assert approver == "reviewer-1"
        assert verdict == "ALLOW"

    def test_votes_recorded_on_deny(self):
        queue = InMemoryApprovalQueue()
        req = EscalationRequest(agent_id="a1", action="x", reason="r")
        queue.submit(req)
        queue.deny(req.request_id, approver="sec-team")
        retrieved = queue.get_decision(req.request_id)
        assert len(retrieved.votes) == 1
        approver, verdict, _ = retrieved.votes[0]
        assert approver == "sec-team"
        assert verdict == "DENY"

    def test_approve_nonexistent(self):
        queue = InMemoryApprovalQueue()
        assert queue.approve("nonexistent", approver="admin") is False

    def test_list_pending(self):
        queue = InMemoryApprovalQueue()
        r1 = EscalationRequest(agent_id="a1", action="x", reason="r")
        r2 = EscalationRequest(agent_id="a2", action="y", reason="s")
        queue.submit(r1)
        queue.submit(r2)
        queue.approve(r1.request_id, approver="admin")
        pending = queue.list_pending()
        assert len(pending) == 1
        assert pending[0].request_id == r2.request_id

    def test_wait_for_decision_with_approval(self):
        queue = InMemoryApprovalQueue()
        req = EscalationRequest(agent_id="a1", action="x", reason="r")
        queue.submit(req)

        def approve_later():
            time.sleep(0.1)
            queue.approve(req.request_id, approver="user")

        t = threading.Thread(target=approve_later)
        t.start()
        decision = queue.wait_for_decision(req.request_id, timeout=5)
        t.join()
        assert decision == EscalationDecision.ALLOW

    def test_wait_for_decision_timeout(self):
        queue = InMemoryApprovalQueue()
        req = EscalationRequest(agent_id="a1", action="x", reason="r")
        queue.submit(req)
        decision = queue.wait_for_decision(req.request_id, timeout=0.1)
        assert decision == EscalationDecision.PENDING


class TestEscalationHandler:
    def test_escalate_creates_request(self):
        handler = EscalationHandler(timeout_seconds=1)
        request = handler.escalate("agent-1", "write_file", "policy requires approval")
        assert request.agent_id == "agent-1"
        assert request.decision == EscalationDecision.PENDING

    def test_resolve_with_approval(self):
        queue = InMemoryApprovalQueue()
        handler = EscalationHandler(backend=queue, timeout_seconds=5)
        request = handler.escalate("agent-1", "action", "reason")

        def approve():
            time.sleep(0.1)
            queue.approve(request.request_id, approver="admin")

        t = threading.Thread(target=approve)
        t.start()
        decision = handler.resolve(request.request_id)
        t.join()
        assert decision == EscalationDecision.ALLOW

    def test_resolve_timeout_defaults_to_deny(self):
        handler = EscalationHandler(
            timeout_seconds=0.1,
            default_action=DefaultTimeoutAction.DENY,
        )
        request = handler.escalate("agent-1", "action", "reason")
        decision = handler.resolve(request.request_id)
        assert decision == EscalationDecision.DENY

    def test_resolve_timeout_defaults_to_allow(self):
        handler = EscalationHandler(
            timeout_seconds=0.1,
            default_action=DefaultTimeoutAction.ALLOW,
        )
        request = handler.escalate("agent-1", "action", "reason")
        decision = handler.resolve(request.request_id)
        assert decision == EscalationDecision.ALLOW

    def test_on_escalate_callback(self):
        captured = []
        handler = EscalationHandler(
            timeout_seconds=1,
            on_escalate=lambda req: captured.append(req),
        )
        handler.escalate("agent-1", "action", "reason")
        assert len(captured) == 1
        assert captured[0].agent_id == "agent-1"


class TestEscalationPolicy:
    def test_allow_when_no_approval_required(self, policy_no_approval, make_context):
        integration = _StubIntegration(policy=policy_no_approval)
        ctx = make_context(policy_no_approval)
        ep = EscalationPolicy(integration)
        result = ep.evaluate("tool_call", ctx)
        assert result.decision == EscalationDecision.ALLOW
        assert result.request is None

    def test_escalate_when_approval_required(self, policy_requires_approval, make_context):
        integration = _StubIntegration(policy=policy_requires_approval)
        ctx = make_context(policy_requires_approval)
        ep = EscalationPolicy(integration)
        result = ep.evaluate("tool_call", ctx)
        assert result.decision == EscalationDecision.PENDING
        assert result.request is not None
        assert result.request.agent_id == "agent-1"

    def test_deny_for_non_approval_reasons(self, make_context):
        policy = GovernancePolicy(
            name="tight",
            max_tool_calls=0,
            require_human_approval=False,
        )
        integration = _StubIntegration(policy=policy)
        ctx = make_context(policy)
        ep = EscalationPolicy(integration)
        result = ep.evaluate("tool_call", ctx)
        assert result.decision == EscalationDecision.DENY

    def test_evaluate_and_wait_approved(self, policy_requires_approval, make_context):
        queue = InMemoryApprovalQueue()
        handler = EscalationHandler(backend=queue, timeout_seconds=5)
        integration = _StubIntegration(policy=policy_requires_approval)
        ctx = make_context(policy_requires_approval)
        ep = EscalationPolicy(integration, handler=handler)

        def approve_pending():
            time.sleep(0.1)
            pending = queue.list_pending()
            if pending:
                queue.approve(pending[0].request_id, approver="admin")

        t = threading.Thread(target=approve_pending)
        t.start()
        result = ep.evaluate_and_wait("tool_call", ctx)
        t.join()
        assert result.decision == EscalationDecision.ALLOW

    def test_evaluate_and_wait_timeout_deny(self, policy_requires_approval, make_context):
        handler = EscalationHandler(
            timeout_seconds=0.1,
            default_action=DefaultTimeoutAction.DENY,
        )
        integration = _StubIntegration(policy=policy_requires_approval)
        ctx = make_context(policy_requires_approval)
        ep = EscalationPolicy(integration, handler=handler)
        result = ep.evaluate_and_wait("tool_call", ctx)
        assert result.decision == EscalationDecision.DENY


class TestEscalationRequest:
    def test_default_fields(self):
        req = EscalationRequest()
        assert req.request_id  # UUID generated
        assert req.decision == EscalationDecision.PENDING
        assert req.resolved_by is None

    def test_custom_fields(self):
        req = EscalationRequest(
            agent_id="a1",
            action="deploy",
            reason="production change",
        )
        assert req.agent_id == "a1"
        assert req.action == "deploy"


class TestQuorumResolution:
    def test_quorum_met_resolves_allow(self):
        queue = InMemoryApprovalQueue()
        handler = EscalationHandler(
            backend=queue,
            timeout_seconds=5,
            quorum=QuorumConfig(required_approvals=1, total_approvers=1),
        )
        request = handler.escalate("agent-1", "action", "reason")

        def approve():
            time.sleep(0.05)
            queue.approve(request.request_id, approver="reviewer-1")

        t = threading.Thread(target=approve)
        t.start()
        decision = handler.resolve(request.request_id)
        t.join()
        assert decision == EscalationDecision.ALLOW

    def test_quorum_not_met_times_out(self):
        queue = InMemoryApprovalQueue()
        handler = EscalationHandler(
            backend=queue,
            timeout_seconds=0.2,
            default_action=DefaultTimeoutAction.DENY,
            quorum=QuorumConfig(required_approvals=2, total_approvers=3),
        )
        request = handler.escalate("agent-1", "action", "reason")
        queue.approve(request.request_id, approver="reviewer-1")
        decision = handler.resolve(request.request_id)
        assert decision == EscalationDecision.DENY

    def test_duplicate_approver_does_not_satisfy_quorum(self):
        queue = InMemoryApprovalQueue()
        handler = EscalationHandler(
            backend=queue,
            timeout_seconds=0.2,
            default_action=DefaultTimeoutAction.DENY,
            quorum=QuorumConfig(required_approvals=2, total_approvers=3),
        )
        request = handler.escalate("agent-1", "action", "reason")
        queue.approve(request.request_id, approver="reviewer-1")
        result = queue.approve(request.request_id, approver="reviewer-1")
        assert result is False
        retrieved = queue.get_decision(request.request_id)
        assert len(retrieved.votes) == 1

    def test_empty_approver_rejected_on_approve(self):
        queue = InMemoryApprovalQueue()
        req = EscalationRequest(agent_id="a1", action="x", reason="r")
        queue.submit(req)
        assert queue.approve(req.request_id) is False
        assert queue.approve(req.request_id, approver="") is False
        assert queue.approve(req.request_id, approver="   ") is False
        retrieved = queue.get_decision(req.request_id)
        assert len(retrieved.votes) == 0

    def test_empty_approver_rejected_on_deny(self):
        queue = InMemoryApprovalQueue()
        req = EscalationRequest(agent_id="a1", action="x", reason="r")
        queue.submit(req)
        assert queue.deny(req.request_id) is False
        assert queue.deny(req.request_id, approver="") is False
        assert queue.deny(req.request_id, approver="   ") is False
        retrieved = queue.get_decision(req.request_id)
        assert len(retrieved.votes) == 0


class TestQuorumWaitsFullTimeout:
    """Regression coverage for #3186.

    ``resolve()`` woke as soon as the *first* quorum vote's event fired
    and ran the quorum check exactly once, falling through to
    ``default_action`` instead of waiting out the rest of
    ``timeout_seconds`` for additional votes. (Line numbers in the
    original issue report -- escalation.py:176, :424-431 -- refer to
    the file as it stood before this fix; see ``resolve()`` and the new
    ``wait_for_quorum()`` below for the current locations.)

    ``TestQuorumResolution`` above (landed with #3126's vote-tracking fix)
    doesn't exercise this: its quorum-met case uses a single-vote quorum
    (``required_approvals=1``) and its timeout case never sends a second
    vote at all, so neither ever exercises a second, later vote arriving
    within the timeout window. This class adds that missing case.
    """

    def test_resolve_waits_for_a_late_second_vote_instead_of_defaulting_early(self):
        queue = InMemoryApprovalQueue()
        handler = EscalationHandler(
            backend=queue,
            timeout_seconds=2,
            default_action=DefaultTimeoutAction.DENY,
            quorum=QuorumConfig(required_approvals=2, required_denials=1),
        )
        request = handler.escalate("agent-1", "deploy", "needs review")

        def cast_votes():
            time.sleep(0.1)
            queue.approve(request.request_id, approver="reviewer-1")
            time.sleep(0.3)
            queue.approve(request.request_id, approver="reviewer-2")

        t = threading.Thread(target=cast_votes)
        t.start()
        started = time.monotonic()
        decision = handler.resolve(request.request_id)
        elapsed = time.monotonic() - started
        t.join()
        # Bug #3186: resolve() woke on reviewer-1's vote at t=0.1s, found
        # quorum (2) unmet with only 1 vote, and fell straight through to
        # default_action (DENY) instead of waiting out the remaining
        # ~1.9s of its 2s timeout for reviewer-2's vote at t=0.4s.
        assert decision == EscalationDecision.ALLOW
        # A decision-only assertion isn't enough: approve()/deny() only
        # fire the wakeup event on the vote that first sets req.decision.
        # A resolve()/wait_for_quorum() fix with no matching fix there
        # would still land on ALLOW, but only by blocking for the entire
        # timeout_seconds and re-checking votes at the deadline, exactly
        # the unresponsiveness #3186 exists to eliminate. Asserting on
        # elapsed time is what actually catches that regression.
        assert elapsed < 1.0, (
            f"resolved in {elapsed:.3f}s -- expected a prompt wakeup near "
            f"reviewer-2's vote at ~0.4s, not a wait out to the 2s timeout"
        )
