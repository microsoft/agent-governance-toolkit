"""Tests for agent lifecycle management."""

import pytest
import tempfile
from datetime import datetime, timedelta, timezone
from pathlib import Path

from agentmesh.lifecycle import (
    AgentLifecycleState,
    CredentialPolicy,
    CredentialRotator,
    LifecycleEvent,
    LifecycleEventType,
    LifecycleManager,
    LifecyclePolicy,
    ManagedAgent,
    OrphanDetector,
)
from agentmesh.lifecycle.manager import LifecycleError


class TestManagedAgent:
    def test_create_agent(self):
        agent = ManagedAgent(agent_id="test-1", name="Test", owner="user@co.com")
        assert agent.state == AgentLifecycleState.PENDING_APPROVAL
        assert not agent.is_active
        assert agent.credential_expired

    def test_record_event(self):
        agent = ManagedAgent(agent_id="test-1", name="Test", owner="user@co.com")
        event = LifecycleEvent(
            event_type=LifecycleEventType.APPROVED,
            agent_id="test-1",
            new_state=AgentLifecycleState.PROVISIONED,
        )
        agent.record_event(event)
        assert agent.state == AgentLifecycleState.PROVISIONED
        assert len(agent.events) == 1


class TestLifecycleManager:
    def setup_method(self):
        self.manager = LifecycleManager(policy=LifecyclePolicy(require_approval=True))

    def test_request_provisioning(self):
        agent = self.manager.request_provisioning(
            name="Test Agent", owner="user@co.com", purpose="Testing"
        )
        assert agent.state == AgentLifecycleState.PENDING_APPROVAL
        assert agent.owner == "user@co.com"
        assert len(agent.events) == 1

    def test_request_without_owner_fails(self):
        with pytest.raises(LifecycleError, match="Owner is required"):
            self.manager.request_provisioning(name="No Owner", owner="")

    def test_full_lifecycle(self):
        # Request → Approve → Activate → Heartbeat → Decommission
        agent = self.manager.request_provisioning(name="Full", owner="admin@co.com")
        agent = self.manager.approve(agent.agent_id, actor="admin")
        assert agent.state == AgentLifecycleState.PROVISIONED

        agent = self.manager.activate(agent.agent_id)
        assert agent.state == AgentLifecycleState.ACTIVE
        assert agent.credential_id is not None

        agent = self.manager.heartbeat(agent.agent_id)
        assert agent.heartbeat_count == 1

        agent = self.manager.decommission(agent.agent_id, reason="End of life")
        assert agent.state == AgentLifecycleState.DECOMMISSIONED
        assert agent.decommissioned_at is not None
        assert agent.credential_id is None  # revoked

    def test_invalid_transition(self):
        agent = self.manager.request_provisioning(name="Test", owner="user@co.com")
        with pytest.raises(LifecycleError, match="Invalid transition"):
            self.manager.activate(agent.agent_id)  # can't skip approve

    def test_suspend_and_resume(self):
        agent = self.manager.request_provisioning(name="Test", owner="user@co.com")
        self.manager.approve(agent.agent_id)
        self.manager.activate(agent.agent_id)

        agent = self.manager.suspend(agent.agent_id, reason="Maintenance")
        assert agent.state == AgentLifecycleState.SUSPENDED

        agent = self.manager.resume(agent.agent_id)
        assert agent.state == AgentLifecycleState.ACTIVE

    def test_reject_request(self):
        agent = self.manager.request_provisioning(name="Bad", owner="user@co.com")
        agent = self.manager.reject(agent.agent_id, reason="Not needed")
        assert agent.state == AgentLifecycleState.DECOMMISSIONED

    def test_change_owner(self):
        agent = self.manager.request_provisioning(name="Test", owner="old@co.com")
        agent = self.manager.change_owner(agent.agent_id, "new@co.com")
        assert agent.owner == "new@co.com"

    def test_auto_provision_without_approval(self):
        manager = LifecycleManager(policy=LifecyclePolicy(require_approval=False))
        agent = manager.request_provisioning(name="Auto", owner="user@co.com")
        assert agent.state == AgentLifecycleState.PROVISIONED

    def test_credential_rotation(self):
        agent = self.manager.request_provisioning(name="Rotate", owner="user@co.com")
        self.manager.approve(agent.agent_id)
        self.manager.activate(agent.agent_id)
        old_cred = agent.credential_id

        agent = self.manager.rotate_credentials(agent.agent_id)
        assert agent.credential_id != old_cred
        assert not agent.credential_expired

    def test_list_by_state(self):
        self.manager.request_provisioning(name="A", owner="user@co.com")
        self.manager.request_provisioning(name="B", owner="user@co.com")
        pending = self.manager.list_by_state(AgentLifecycleState.PENDING_APPROVAL)
        assert len(pending) == 2

    def test_list_by_owner(self):
        self.manager.request_provisioning(name="A", owner="alice@co.com")
        self.manager.request_provisioning(name="B", owner="bob@co.com")
        alice_agents = self.manager.list_by_owner("alice@co.com")
        assert len(alice_agents) == 1

    def test_audit_trail(self):
        agent = self.manager.request_provisioning(name="Audit", owner="user@co.com")
        self.manager.approve(agent.agent_id)
        self.manager.activate(agent.agent_id)
        trail = self.manager.get_audit_trail(agent.agent_id)
        assert len(trail) >= 3
        assert trail[0].event_type == LifecycleEventType.REQUESTED
        assert trail[1].event_type == LifecycleEventType.APPROVED

    def test_persistence(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            path = Path(tmpdir) / "lifecycle.json"
            mgr1 = LifecycleManager(storage_path=path)
            agent = mgr1.request_provisioning(name="Persistent", owner="user@co.com")
            agent_id = agent.agent_id

            mgr2 = LifecycleManager(storage_path=path)
            loaded = mgr2.get(agent_id)
            assert loaded is not None
            assert loaded.name == "Persistent"

    def test_summary(self):
        self.manager.request_provisioning(name="A", owner="alice@co.com")
        self.manager.request_provisioning(name="B", owner="bob@co.com")
        s = self.manager.summary()
        assert s["total_agents"] == 2
        assert s["by_state"]["pending_approval"] == 2


class TestCredentialRotator:
    def test_rotate_expiring(self):
        manager = LifecycleManager(policy=LifecyclePolicy(
            require_approval=False,
            credential_policy=CredentialPolicy(max_credential_ttl=timedelta(seconds=1)),
        ))
        agent = manager.request_provisioning(name="Expire", owner="user@co.com")
        manager.activate(agent.agent_id)

        # Force credential to be expired
        agent.credential_expires_at = datetime.now(timezone.utc) - timedelta(hours=1)

        rotator = CredentialRotator(manager)
        results = rotator.check_and_rotate()
        rotated = [r for r in results if r["action"] == "rotated"]
        assert len(rotated) == 1

    def test_valid_credentials_ok(self):
        manager = LifecycleManager(policy=LifecyclePolicy(require_approval=False))
        agent = manager.request_provisioning(name="Valid", owner="user@co.com")
        manager.activate(agent.agent_id)

        rotator = CredentialRotator(manager)
        results = rotator.check_and_rotate()
        ok = [r for r in results if r["action"] == "ok"]
        assert len(ok) == 1

    def test_revoke_all(self):
        manager = LifecycleManager(policy=LifecyclePolicy(require_approval=False))
        agent = manager.request_provisioning(name="Revoke", owner="user@co.com")
        manager.activate(agent.agent_id)
        assert agent.credential_id is not None

        rotator = CredentialRotator(manager)
        rotator.revoke_all(agent.agent_id)
        assert agent.credential_id is None


class TestOrphanDetector:
    def test_detect_silent_agent(self):
        policy = LifecyclePolicy(
            require_approval=False,
            orphan_threshold=timedelta(hours=1),
        )
        manager = LifecycleManager(policy=policy)
        agent = manager.request_provisioning(name="Silent", owner="user@co.com")
        manager.activate(agent.agent_id)

        # Simulate old heartbeat
        agent.last_heartbeat = datetime.now(timezone.utc) - timedelta(hours=2)

        detector = OrphanDetector(manager)
        candidates = detector.detect()
        assert len(candidates) >= 1
        assert any("heartbeat" in c.reason.lower() for c in candidates)

    def test_no_orphans_with_recent_heartbeat(self):
        policy = LifecyclePolicy(require_approval=False)
        manager = LifecycleManager(policy=policy)
        agent = manager.request_provisioning(name="Active", owner="user@co.com")
        manager.activate(agent.agent_id)
        manager.heartbeat(agent.agent_id)

        detector = OrphanDetector(manager)
        candidates = detector.detect()
        heartbeat_orphans = [c for c in candidates if "heartbeat" in c.reason.lower()]
        assert len(heartbeat_orphans) == 0

    def test_mark_orphaned(self):
        policy = LifecyclePolicy(require_approval=False)
        manager = LifecycleManager(policy=policy)
        agent = manager.request_provisioning(name="Orphan", owner="user@co.com")
        manager.activate(agent.agent_id)

        detector = OrphanDetector(manager)
        agent = detector.mark_orphaned(agent.agent_id)
        assert agent.state == AgentLifecycleState.ORPHANED

    def test_reclaim_orphan(self):
        policy = LifecyclePolicy(require_approval=False)
        manager = LifecycleManager(policy=policy)
        agent = manager.request_provisioning(name="Reclaim", owner="old@co.com")
        manager.activate(agent.agent_id)

        detector = OrphanDetector(manager)
        detector.mark_orphaned(agent.agent_id)

        agent = detector.reclaim(agent.agent_id, "new@co.com")
        assert agent.state == AgentLifecycleState.ACTIVE
        assert agent.owner == "new@co.com"

    def test_detect_no_owner(self):
        policy = LifecyclePolicy(require_approval=False, require_owner=False)
        manager = LifecycleManager(policy=policy)
        agent = manager.request_provisioning(name="NoOwner", owner="")
        manager.activate(agent.agent_id)

        detector = OrphanDetector(manager)
        candidates = detector.detect()
        assert any("No owner" in c.reason for c in candidates)
