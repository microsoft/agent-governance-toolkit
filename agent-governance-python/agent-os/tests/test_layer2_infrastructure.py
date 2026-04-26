# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""
Test Layer 2: Infrastructure packages.
"""

import asyncio

import pytest


# Check if optional packages are installed
try:
    import iatp
    HAS_IATP = True
except ImportError:
    HAS_IATP = False


@pytest.mark.skipif(not HAS_IATP, reason="iatp not installed")
class TestIATP:
    """Test inter-agent-trust-protocol package."""
    
    def test_import_iatp_models(self):
        """Test importing IATP models."""
        from iatp import (
            CapabilityManifest,
            TrustLevel,
            ReversibilityLevel,
            RetentionPolicy,
        )
        assert TrustLevel is not None
        assert ReversibilityLevel is not None
    
    def test_trust_levels(self):
        """Test trust level enum values."""
        from iatp import TrustLevel
        assert hasattr(TrustLevel, 'UNTRUSTED')
        assert hasattr(TrustLevel, 'TRUSTED')
        assert hasattr(TrustLevel, 'VERIFIED_PARTNER')
    
    def test_import_ipc_pipes(self):
        """Test importing IPC pipes (v0.4.0 feature)."""
        from iatp import (
            TypedPipe,
            Pipeline,
            PipeMessage,
            PipeConfig,
            PolicyCheckPipe,
        )
        assert TypedPipe is not None
        assert Pipeline is not None
        assert PipeMessage is not None
    
    def test_create_pipe_message(self):
        """Test creating a pipe message."""
        from iatp import PipeMessage
        
        msg = PipeMessage(
            payload={"query": "test"},
            source_agent="agent-a",
            target_agent="agent-b",
        )
        
        assert msg.payload == {"query": "test"}
        assert msg.source_agent == "agent-a"
        assert msg.policy_checked is False
    
    def test_create_pipeline(self):
        """Test creating a pipeline."""
        from iatp import Pipeline, PolicyCheckPipe
        
        pipeline = Pipeline(name="test-pipeline")
        assert pipeline.name == "test-pipeline"
        assert len(pipeline.stages) == 0


class TestAMB:
    """Test agent-message-bus package."""
    
    def test_import_amb(self):
        """Test basic import."""
        try:
            from amb_core import MessageBus, Message
            assert MessageBus is not None
        except ImportError:
            pytest.skip("amb not installed")


class TestATR:
    """Test agent-tool-registry package."""
    
    def test_import_atr(self):
        """Test basic import."""
        try:
            from atr import ToolRegistry
            assert ToolRegistry is not None
        except ImportError:
            pytest.skip("atr not installed")


# =========================================================================
# AMB message bus tests (#166)
# =========================================================================


try:
    from amb_core import MessageBus, Message, InMemoryBroker, Priority
    HAS_AMB = True
except ImportError:
    HAS_AMB = False


@pytest.mark.skipif(not HAS_AMB, reason="amb_core not installed")
class TestAMBMessageBus:
    """Test AMB message publishing, subscription, filtering, and multiple subscribers."""

    @pytest.fixture
    def broker(self):
        return InMemoryBroker(use_priority_delivery=False)

    async def test_publish_and_subscribe(self, broker):
        """Publish a message and verify the subscriber receives it."""
        received = []

        async def handler(msg):
            received.append(msg)

        bus = MessageBus(adapter=broker)
        async with bus:
            await bus.subscribe("test.topic", handler)
            await bus.publish("test.topic", {"key": "value"})
            await asyncio.sleep(0.05)

        assert len(received) == 1
        assert received[0].payload == {"key": "value"}

    async def test_publish_returns_message_id(self, broker):
        """publish() returns a non-empty message ID string."""
        bus = MessageBus(adapter=broker)
        async with bus:
            msg_id = await bus.publish("id.topic", {"data": 1})
            assert isinstance(msg_id, str)
            assert len(msg_id) > 0

    async def test_multiple_subscribers_same_topic(self, broker):
        """All subscribers on the same topic receive the message."""
        results_a, results_b = [], []

        async def handler_a(msg):
            results_a.append(msg.payload)

        async def handler_b(msg):
            results_b.append(msg.payload)

        bus = MessageBus(adapter=broker)
        async with bus:
            await bus.subscribe("multi.topic", handler_a)
            await bus.subscribe("multi.topic", handler_b)
            await bus.publish("multi.topic", {"n": 42})
            await asyncio.sleep(0.05)

        assert results_a == [{"n": 42}]
        assert results_b == [{"n": 42}]

    async def test_subscriber_filtering_by_topic(self, broker):
        """Subscribers only receive messages for their subscribed topic."""
        received = []

        async def handler(msg):
            received.append(msg.payload)

        bus = MessageBus(adapter=broker)
        async with bus:
            await bus.subscribe("yes.topic", handler)
            await bus.publish("yes.topic", {"match": True})
            await bus.publish("no.topic", {"match": False})
            await asyncio.sleep(0.05)

        assert len(received) == 1
        assert received[0]["match"] is True

    async def test_unsubscribe_stops_delivery(self, broker):
        """After unsubscribe, no further messages are delivered."""
        received = []

        async def handler(msg):
            received.append(msg)

        bus = MessageBus(adapter=broker)
        async with bus:
            sub_id = await bus.subscribe("unsub.topic", handler)
            await bus.publish("unsub.topic", {"before": True})
            await asyncio.sleep(0.05)
            await bus.unsubscribe(sub_id)
            await bus.publish("unsub.topic", {"after": True})
            await asyncio.sleep(0.05)

        assert len(received) == 1

    async def test_publish_without_connect_raises(self):
        """Publishing on a disconnected bus raises ConnectionError."""
        bus = MessageBus()
        with pytest.raises(ConnectionError):
            await bus.publish("t", {"x": 1})

    async def test_priority_ordering(self, broker):
        """Higher-priority messages appear first in pending queue."""
        bus = MessageBus(adapter=broker)
        async with bus:
            await bus.publish("prio.topic", {"level": "low"}, priority=Priority.LOW)
            await bus.publish("prio.topic", {"level": "critical"}, priority=Priority.CRITICAL)

            pending = await broker.get_pending_messages("prio.topic", limit=10)
            if len(pending) >= 2:
                assert pending[0].priority >= pending[1].priority


# =========================================================================
# VFS virtual filesystem tests (#167)
# =========================================================================


try:
    from agent_control_plane.vfs import AgentVFS, MemoryBackend, FileMode
    HAS_VFS = True
except ImportError:
    HAS_VFS = False


@pytest.mark.skipif(not HAS_VFS, reason="agent_control_plane not installed")
class TestAgentVFS:
    """Test VFS file create/read/update/delete, path resolution, and permissions."""

    @pytest.fixture
    def vfs(self):
        return AgentVFS(agent_id="test-agent")

    def test_write_and_read(self, vfs):
        """Write data and read it back."""
        vfs.write("/mem/working/hello.txt", b"hello world")
        data = vfs.read("/mem/working/hello.txt")
        assert data == b"hello world"

    def test_write_text_and_read_text(self, vfs):
        """Write a string and read it back as text."""
        vfs.write("/mem/working/note.txt", "some text")
        assert vfs.read_text("/mem/working/note.txt") == "some text"

    def test_write_json_and_read_json(self, vfs):
        """Write JSON and read it back as a dict."""
        vfs.write_json("/mem/working/data.json", {"k": "v"})
        assert vfs.read_json("/mem/working/data.json") == {"k": "v"}

    def test_update_overwrites(self, vfs):
        """Writing to the same path overwrites previous content."""
        vfs.write("/mem/working/f.txt", b"old")
        vfs.write("/mem/working/f.txt", b"new")
        assert vfs.read("/mem/working/f.txt") == b"new"

    def test_append_mode(self, vfs):
        """Appending adds to existing content."""
        vfs.write("/mem/working/log.txt", b"line1\n")
        vfs.append("/mem/working/log.txt", b"line2\n")
        assert vfs.read("/mem/working/log.txt") == b"line1\nline2\n"

    def test_delete_file(self, vfs):
        """Deleting a file makes it no longer exist."""
        vfs.write("/mem/working/tmp.txt", b"data")
        assert vfs.exists("/mem/working/tmp.txt")
        assert vfs.delete("/mem/working/tmp.txt") is True
        assert not vfs.exists("/mem/working/tmp.txt")

    def test_delete_nonexistent_returns_false(self, vfs):
        """Deleting a nonexistent file returns False."""
        assert vfs.delete("/mem/working/nope.txt") is False

    def test_read_nonexistent_raises(self, vfs):
        """Reading a file that does not exist raises FileNotFoundError."""
        with pytest.raises(FileNotFoundError):
            vfs.read("/mem/working/missing.txt")

    def test_exists(self, vfs):
        """exists() returns True for written files, False otherwise."""
        assert not vfs.exists("/mem/working/check.txt")
        vfs.write("/mem/working/check.txt", b"x")
        assert vfs.exists("/mem/working/check.txt")

    def test_stat_returns_inode(self, vfs):
        """stat() returns an INode with correct size after write."""
        vfs.write("/mem/working/sized.txt", b"12345")
        inode = vfs.stat("/mem/working/sized.txt")
        assert inode is not None
        assert inode.size == 5

    def test_path_resolution_longest_mount(self, vfs):
        """Paths resolve to the longest matching mount point."""
        vfs.write("/mem/working/a.txt", b"working")
        vfs.write("/mem/episodic/b.txt", b"episodic")
        assert vfs.read("/mem/working/a.txt") == b"working"
        assert vfs.read("/mem/episodic/b.txt") == b"episodic"

    def test_no_mount_raises(self, vfs):
        """Accessing a path with no mount raises FileNotFoundError."""
        with pytest.raises(FileNotFoundError):
            vfs.read("/nonexistent/path.txt")

    def test_policy_mount_is_read_only(self, vfs):
        """Writing to /policy raises PermissionError."""
        with pytest.raises(PermissionError):
            vfs.write("/policy/secret.txt", b"nope")

    def test_read_only_mount_blocks_delete(self, vfs):
        """Deleting from a read-only mount raises PermissionError."""
        with pytest.raises(PermissionError):
            vfs.delete("/policy/file.txt")

    def test_checkpoint_save_and_load(self, vfs):
        """save_checkpoint / load_checkpoint roundtrip."""
        vfs.save_checkpoint("cp-1", {"step": 5, "score": 0.9})
        state = vfs.load_checkpoint("cp-1")
        assert state["step"] == 5
        assert state["score"] == 0.9

    def test_clear_working_memory(self, vfs):
        """clear_working_memory removes all files under /mem/working."""
        vfs.write("/mem/working/a.txt", b"a")
        vfs.write("/mem/working/b.txt", b"b")
        count = vfs.clear_working_memory()
        assert count == 2
        assert not vfs.exists("/mem/working/a.txt")

    def test_mount_and_unmount(self, vfs):
        """Custom backend can be mounted and unmounted."""
        backend = MemoryBackend()
        vfs.mount("/custom", backend, read_only=True)
        assert vfs.unmount("/custom") is True
        assert vfs.unmount("/custom") is False


# =========================================================================
# IATP trust protocol edge cases (#165)
# =========================================================================


@pytest.mark.skipif(not HAS_IATP, reason="iatp not installed")
class TestIATPTrustProtocol:
    """Test IATP trust establishment, revocation, and score calculation."""

    def test_trust_establishment_between_agents(self):
        """Two agents exchange manifests and calculate trust scores."""
        from iatp import (
            CapabilityManifest, AgentCapabilities, PrivacyContract,
            TrustLevel, ReversibilityLevel, RetentionPolicy,
        )

        agent_a = CapabilityManifest(
            agent_id="agent-a",
            trust_level=TrustLevel.TRUSTED,
            capabilities=AgentCapabilities(
                reversibility=ReversibilityLevel.FULL, idempotency=True,
            ),
            privacy_contract=PrivacyContract(retention=RetentionPolicy.EPHEMERAL),
        )
        agent_b = CapabilityManifest(
            agent_id="agent-b",
            trust_level=TrustLevel.STANDARD,
            capabilities=AgentCapabilities(reversibility=ReversibilityLevel.NONE),
            privacy_contract=PrivacyContract(retention=RetentionPolicy.TEMPORARY),
        )

        score_a = agent_a.calculate_trust_score()
        score_b = agent_b.calculate_trust_score()

        # Agent A should score higher (trusted, full reversibility, ephemeral)
        assert score_a > score_b
        assert 0 <= score_a <= 10
        assert 0 <= score_b <= 10

    def test_trust_revocation_via_reputation(self):
        """Record hallucinations to slash reputation below trust threshold."""
        from iatp import ReputationManager, TrustLevel

        mgr = ReputationManager()
        score = mgr.get_or_create_score("bad-agent")
        assert score.score == 5.0  # initial

        # Slash reputation with critical hallucinations
        mgr.record_hallucination("bad-agent", severity="critical")
        mgr.record_hallucination("bad-agent", severity="critical")
        mgr.record_hallucination("bad-agent", severity="critical")

        updated = mgr.get_score("bad-agent")
        assert updated.score < 2.0
        assert updated.get_trust_level() == TrustLevel.UNTRUSTED

    def test_trust_score_calculation_verified_partner(self):
        """Verified partner with best practices gets maximum score."""
        from iatp import (
            CapabilityManifest, AgentCapabilities, PrivacyContract,
            TrustLevel, ReversibilityLevel, RetentionPolicy,
        )

        manifest = CapabilityManifest(
            agent_id="perfect-agent",
            trust_level=TrustLevel.VERIFIED_PARTNER,
            capabilities=AgentCapabilities(
                reversibility=ReversibilityLevel.FULL, idempotency=True,
            ),
            privacy_contract=PrivacyContract(
                retention=RetentionPolicy.EPHEMERAL, human_review=False,
            ),
        )
        score = manifest.calculate_trust_score()
        assert score == 10  # 5 + 3 + 1 + 1 + 2 - 0 + 1 = clamped to 10

    def test_untrusted_agent_low_score(self):
        """Untrusted agent with poor practices gets very low score."""
        from iatp import (
            CapabilityManifest, AgentCapabilities, PrivacyContract,
            TrustLevel, ReversibilityLevel, RetentionPolicy,
        )

        manifest = CapabilityManifest(
            agent_id="sketchy-agent",
            trust_level=TrustLevel.UNTRUSTED,
            capabilities=AgentCapabilities(
                reversibility=ReversibilityLevel.NONE, idempotency=False,
            ),
            privacy_contract=PrivacyContract(
                retention=RetentionPolicy.PERMANENT, human_review=True,
            ),
        )
        score = manifest.calculate_trust_score()
        # 5 - 5 + 0 + 0 - 2 + 0 = -2 -> clamped to 0
        assert score == 0

    def test_reputation_recovery_with_successes(self):
        """Agent can recover reputation through successful operations."""
        from iatp import ReputationManager

        mgr = ReputationManager()
        mgr.record_hallucination("recovering-agent", severity="high")
        assert mgr.get_score("recovering-agent").score < 5.0

        # Record many successes to recover
        for _ in range(20):
            mgr.record_success("recovering-agent")

        updated = mgr.get_score("recovering-agent")
        assert updated.score > 4.0  # Recovered from the slash

    def test_reputation_score_clamped_0_to_10(self):
        """Reputation score never goes below 0 or above 10."""
        from iatp import ReputationManager

        mgr = ReputationManager()
        # Slash heavily
        for _ in range(10):
            mgr.record_hallucination("floor-agent", severity="critical")
        assert mgr.get_score("floor-agent").score == 0.0

        # Boost heavily
        mgr2 = ReputationManager()
        for _ in range(200):
            mgr2.record_success("ceiling-agent")
        assert mgr2.get_score("ceiling-agent").score <= 10.0
