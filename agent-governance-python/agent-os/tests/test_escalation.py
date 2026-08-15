# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""Tests for human-in-the-loop escalation policy."""
import threading
import time
from agent_os.integrations.escalation import DefaultTimeoutAction, EscalationDecision, EscalationHandler, EscalationRequest, InMemoryApprovalQueue, QuorumConfig

class TestInMemoryApprovalQueue:

    def test_submit_and_get(self):
        queue = InMemoryApprovalQueue()
        req = EscalationRequest(agent_id='a1', action='write_file', reason='needs review')
        queue.submit(req)
        retrieved = queue.get_decision(req.request_id)
        assert retrieved is not None
        assert retrieved.decision == EscalationDecision.PENDING

    def test_approve(self):
        queue = InMemoryApprovalQueue()
        req = EscalationRequest(agent_id='a1', action='call_api', reason='policy')
        queue.submit(req)
        assert queue.approve(req.request_id, approver='admin') is True
        retrieved = queue.get_decision(req.request_id)
        assert retrieved.decision == EscalationDecision.ALLOW
        assert retrieved.resolved_by == 'admin'
        assert retrieved.resolved_at is not None

    def test_deny(self):
        queue = InMemoryApprovalQueue()
        req = EscalationRequest(agent_id='a1', action='delete', reason='dangerous')
        queue.submit(req)
        assert queue.deny(req.request_id, approver='sec-team') is True
        retrieved = queue.get_decision(req.request_id)
        assert retrieved.decision == EscalationDecision.DENY

    def test_double_approve_same_approver_rejected(self):
        queue = InMemoryApprovalQueue()
        req = EscalationRequest(agent_id='a1', action='x', reason='r')
        queue.submit(req)
        assert queue.approve(req.request_id, approver='admin') is True
        assert queue.approve(req.request_id, approver='admin') is False

    def test_second_approver_vote_recorded(self):
        queue = InMemoryApprovalQueue()
        req = EscalationRequest(agent_id='a1', action='x', reason='r')
        queue.submit(req)
        assert queue.approve(req.request_id, approver='admin-a') is True
        assert queue.approve(req.request_id, approver='admin-b') is True
        retrieved = queue.get_decision(req.request_id)
        assert len(retrieved.votes) == 2
        approvers = [a for a, _, _ in retrieved.votes]
        assert 'admin-a' in approvers
        assert 'admin-b' in approvers

    def test_votes_recorded_on_approve(self):
        queue = InMemoryApprovalQueue()
        req = EscalationRequest(agent_id='a1', action='x', reason='r')
        queue.submit(req)
        queue.approve(req.request_id, approver='reviewer-1')
        retrieved = queue.get_decision(req.request_id)
        assert len(retrieved.votes) == 1
        approver, verdict, _ = retrieved.votes[0]
        assert approver == 'reviewer-1'
        assert verdict == 'ALLOW'

    def test_votes_recorded_on_deny(self):
        queue = InMemoryApprovalQueue()
        req = EscalationRequest(agent_id='a1', action='x', reason='r')
        queue.submit(req)
        queue.deny(req.request_id, approver='sec-team')
        retrieved = queue.get_decision(req.request_id)
        assert len(retrieved.votes) == 1
        approver, verdict, _ = retrieved.votes[0]
        assert approver == 'sec-team'
        assert verdict == 'DENY'

    def test_approve_nonexistent(self):
        queue = InMemoryApprovalQueue()
        assert queue.approve('nonexistent', approver='admin') is False

    def test_list_pending(self):
        queue = InMemoryApprovalQueue()
        r1 = EscalationRequest(agent_id='a1', action='x', reason='r')
        r2 = EscalationRequest(agent_id='a2', action='y', reason='s')
        queue.submit(r1)
        queue.submit(r2)
        queue.approve(r1.request_id, approver='admin')
        pending = queue.list_pending()
        assert len(pending) == 1
        assert pending[0].request_id == r2.request_id

    def test_wait_for_decision_with_approval(self):
        queue = InMemoryApprovalQueue()
        req = EscalationRequest(agent_id='a1', action='x', reason='r')
        queue.submit(req)

        def approve_later():
            time.sleep(0.1)
            queue.approve(req.request_id, approver='user')
        t = threading.Thread(target=approve_later)
        t.start()
        decision = queue.wait_for_decision(req.request_id, timeout=5)
        t.join()
        assert decision == EscalationDecision.ALLOW

    def test_wait_for_decision_timeout(self):
        queue = InMemoryApprovalQueue()
        req = EscalationRequest(agent_id='a1', action='x', reason='r')
        queue.submit(req)
        decision = queue.wait_for_decision(req.request_id, timeout=0.1)
        assert decision == EscalationDecision.PENDING

class TestEscalationHandler:

    def test_escalate_creates_request(self):
        handler = EscalationHandler(timeout_seconds=1)
        request = handler.escalate('agent-1', 'write_file', 'policy requires approval')
        assert request.agent_id == 'agent-1'
        assert request.decision == EscalationDecision.PENDING

    def test_resolve_with_approval(self):
        queue = InMemoryApprovalQueue()
        handler = EscalationHandler(backend=queue, timeout_seconds=5)
        request = handler.escalate('agent-1', 'action', 'reason')

        def approve():
            time.sleep(0.1)
            queue.approve(request.request_id, approver='admin')
        t = threading.Thread(target=approve)
        t.start()
        decision = handler.resolve(request.request_id)
        t.join()
        assert decision == EscalationDecision.ALLOW

    def test_resolve_timeout_defaults_to_deny(self):
        handler = EscalationHandler(timeout_seconds=0.1, default_action=DefaultTimeoutAction.DENY)
        request = handler.escalate('agent-1', 'action', 'reason')
        decision = handler.resolve(request.request_id)
        assert decision == EscalationDecision.DENY

    def test_resolve_timeout_defaults_to_allow(self):
        handler = EscalationHandler(timeout_seconds=0.1, default_action=DefaultTimeoutAction.ALLOW)
        request = handler.escalate('agent-1', 'action', 'reason')
        decision = handler.resolve(request.request_id)
        assert decision == EscalationDecision.ALLOW

    def test_on_escalate_callback(self):
        captured = []
        handler = EscalationHandler(timeout_seconds=1, on_escalate=lambda req: captured.append(req))
        handler.escalate('agent-1', 'action', 'reason')
        assert len(captured) == 1
        assert captured[0].agent_id == 'agent-1'

class TestEscalationRequest:

    def test_default_fields(self):
        req = EscalationRequest()
        assert req.request_id
        assert req.decision == EscalationDecision.PENDING
        assert req.resolved_by is None

    def test_custom_fields(self):
        req = EscalationRequest(agent_id='a1', action='deploy', reason='production change')
        assert req.agent_id == 'a1'
        assert req.action == 'deploy'

class TestQuorumResolution:

    def test_quorum_met_resolves_allow(self):
        queue = InMemoryApprovalQueue()
        handler = EscalationHandler(backend=queue, timeout_seconds=5, quorum=QuorumConfig(required_approvals=1, total_approvers=1))
        request = handler.escalate('agent-1', 'action', 'reason')

        def approve():
            time.sleep(0.05)
            queue.approve(request.request_id, approver='reviewer-1')
        t = threading.Thread(target=approve)
        t.start()
        decision = handler.resolve(request.request_id)
        t.join()
        assert decision == EscalationDecision.ALLOW

    def test_quorum_not_met_times_out(self):
        queue = InMemoryApprovalQueue()
        handler = EscalationHandler(backend=queue, timeout_seconds=0.2, default_action=DefaultTimeoutAction.DENY, quorum=QuorumConfig(required_approvals=2, total_approvers=3))
        request = handler.escalate('agent-1', 'action', 'reason')
        queue.approve(request.request_id, approver='reviewer-1')
        decision = handler.resolve(request.request_id)
        assert decision == EscalationDecision.DENY

    def test_duplicate_approver_does_not_satisfy_quorum(self):
        queue = InMemoryApprovalQueue()
        handler = EscalationHandler(backend=queue, timeout_seconds=0.2, default_action=DefaultTimeoutAction.DENY, quorum=QuorumConfig(required_approvals=2, total_approvers=3))
        request = handler.escalate('agent-1', 'action', 'reason')
        queue.approve(request.request_id, approver='reviewer-1')
        result = queue.approve(request.request_id, approver='reviewer-1')
        assert result is False
        retrieved = queue.get_decision(request.request_id)
        assert len(retrieved.votes) == 1

    def test_empty_approver_rejected_on_approve(self):
        queue = InMemoryApprovalQueue()
        req = EscalationRequest(agent_id='a1', action='x', reason='r')
        queue.submit(req)
        assert queue.approve(req.request_id) is False
        assert queue.approve(req.request_id, approver='') is False
        assert queue.approve(req.request_id, approver='   ') is False
        retrieved = queue.get_decision(req.request_id)
        assert len(retrieved.votes) == 0

    def test_empty_approver_rejected_on_deny(self):
        queue = InMemoryApprovalQueue()
        req = EscalationRequest(agent_id='a1', action='x', reason='r')
        queue.submit(req)
        assert queue.deny(req.request_id) is False
        assert queue.deny(req.request_id, approver='') is False
        assert queue.deny(req.request_id, approver='   ') is False
        retrieved = queue.get_decision(req.request_id)
        assert len(retrieved.votes) == 0
