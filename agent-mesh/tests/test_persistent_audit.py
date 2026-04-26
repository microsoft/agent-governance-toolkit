# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""Tests for persistent audit log."""

import pytest

pytestmark = pytest.mark.skip(
    reason="persistent_audit.py not included"
)


@pytest.fixture
def storage():
    """Create a connected in-memory storage provider."""
    config = StorageConfig(backend="memory")
    provider = MemoryStorageProvider(config)
    asyncio.get_event_loop().run_until_complete(provider.connect())
    return provider


@pytest.fixture
def audit_log(storage):
    """Create a persistent audit log."""
    return PersistentAuditLog(storage, namespace="test")


class TestPersistentAuditAppend:
    """Test appending entries to persistent audit."""

    @pytest.mark.asyncio
    async def test_append_single_entry(self, audit_log):
        entry = await audit_log.append(
            event_type="tool_invocation",
            agent_did="did:mesh:a1",
            action="database_query",
        )
        assert entry.entry_id.startswith("audit_")
        assert entry.agent_did == "did:mesh:a1"
        assert len(audit_log) == 1

    @pytest.mark.asyncio
    async def test_append_multiple_entries(self, audit_log):
        for i in range(5):
            await audit_log.append(
                event_type="tool_invocation",
                agent_did=f"did:mesh:a{i}",
                action=f"action_{i}",
            )
        assert len(audit_log) == 5

    @pytest.mark.asyncio
    async def test_chain_root_updates(self, audit_log):
        assert audit_log.chain_root is None
        await audit_log.append(
            event_type="test", agent_did="did:mesh:a1", action="read"
        )
        root1 = audit_log.chain_root
        assert root1 is not None

        await audit_log.append(
            event_type="test", agent_did="did:mesh:a1", action="write"
        )
        root2 = audit_log.chain_root
        assert root2 != root1

    @pytest.mark.asyncio
    async def test_entry_with_data(self, audit_log):
        entry = await audit_log.append(
            event_type="policy_violation",
            agent_did="did:mesh:a1",
            action="export",
            resource="users_table",
            data={"reason": "PII detected"},
            outcome="denied",
            policy_decision="deny",
        )
        assert entry.outcome == "denied"
        assert entry.data["reason"] == "PII detected"


class TestPersistentAuditLoad:
    """Test loading entries from storage."""

    @pytest.mark.asyncio
    async def test_load_empty(self, storage):
        audit = PersistentAuditLog(storage, namespace="empty")
        count = await audit.load()
        assert count == 0
        assert len(audit) == 0

    @pytest.mark.asyncio
    async def test_load_persisted_entries(self, storage):
        # Write entries with one instance
        audit1 = PersistentAuditLog(storage, namespace="persist")
        await audit1.append(event_type="test", agent_did="did:mesh:a1", action="read")
        await audit1.append(event_type="test", agent_did="did:mesh:a2", action="write")

        # Load with a new instance
        audit2 = PersistentAuditLog(storage, namespace="persist")
        count = await audit2.load()
        assert count == 2
        assert len(audit2) == 2

    @pytest.mark.asyncio
    async def test_integrity_verified_on_load(self, storage):
        audit1 = PersistentAuditLog(storage, namespace="verify")
        await audit1.append(event_type="test", agent_did="did:mesh:a1", action="read")
        await audit1.append(event_type="test", agent_did="did:mesh:a1", action="write")

        audit2 = PersistentAuditLog(storage, namespace="verify", verify_on_load=True)
        count = await audit2.load()
        assert count == 2


class TestPersistentAuditQuery:
    """Test querying persisted entries."""

    @pytest.mark.asyncio
    async def test_get_entry_by_id(self, audit_log):
        entry = await audit_log.append(
            event_type="test", agent_did="did:mesh:a1", action="read"
        )
        found = await audit_log.get_entry(entry.entry_id)
        assert found is not None
        assert found.entry_id == entry.entry_id

    @pytest.mark.asyncio
    async def test_get_entries_for_agent(self, audit_log):
        await audit_log.append(event_type="test", agent_did="did:mesh:a1", action="read")
        await audit_log.append(event_type="test", agent_did="did:mesh:a2", action="write")
        await audit_log.append(event_type="test", agent_did="did:mesh:a1", action="delete")

        entries = await audit_log.get_entries_for_agent("did:mesh:a1")
        assert len(entries) == 2
        assert all(e.agent_did == "did:mesh:a1" for e in entries)

    @pytest.mark.asyncio
    async def test_query_by_event_type(self, audit_log):
        await audit_log.append(event_type="tool_invocation", agent_did="did:mesh:a1", action="read")
        await audit_log.append(event_type="policy_violation", agent_did="did:mesh:a1", action="write")

        results = await audit_log.query(event_type="policy_violation")
        assert len(results) == 1
        assert results[0].event_type == "policy_violation"

    @pytest.mark.asyncio
    async def test_query_by_outcome(self, audit_log):
        await audit_log.append(event_type="test", agent_did="did:mesh:a1", action="read", outcome="success")
        await audit_log.append(event_type="test", agent_did="did:mesh:a1", action="write", outcome="denied")

        results = await audit_log.query(outcome="denied")
        assert len(results) == 1


class TestPersistentAuditIntegrity:
    """Test integrity verification."""

    @pytest.mark.asyncio
    async def test_verify_integrity(self, audit_log):
        await audit_log.append(event_type="test", agent_did="did:mesh:a1", action="read")
        await audit_log.append(event_type="test", agent_did="did:mesh:a1", action="write")

        valid, error = await audit_log.verify_integrity()
        assert valid is True
        assert error is None

    @pytest.mark.asyncio
    async def test_verify_against_storage(self, audit_log):
        await audit_log.append(event_type="test", agent_did="did:mesh:a1", action="read")

        valid, error = await audit_log.verify_against_storage()
        assert valid is True

    @pytest.mark.asyncio
    async def test_verify_empty_log(self, audit_log):
        valid, error = await audit_log.verify_integrity()
        assert valid is True


class TestPersistentAuditExport:
    """Test export functionality."""

    @pytest.mark.asyncio
    async def test_export(self, audit_log):
        await audit_log.append(event_type="test", agent_did="did:mesh:a1", action="read")
        result = await audit_log.export()
        assert result["entry_count"] == 1
        assert result["chain_root"] is not None

    @pytest.mark.asyncio
    async def test_export_cloudevents(self, audit_log):
        await audit_log.append(event_type="tool_invocation", agent_did="did:mesh:a1", action="read")
        events = await audit_log.export_cloudevents()
        assert len(events) == 1
        assert events[0]["specversion"] == "1.0"
        assert events[0]["type"] == "ai.agentmesh.tool.invoked"


class TestNamespaceIsolation:
    """Test that namespaces are isolated."""

    @pytest.mark.asyncio
    async def test_different_namespaces_isolated(self, storage):
        audit_a = PersistentAuditLog(storage, namespace="ns_a")
        audit_b = PersistentAuditLog(storage, namespace="ns_b")

        await audit_a.append(event_type="test", agent_did="did:mesh:a1", action="read")
        await audit_b.append(event_type="test", agent_did="did:mesh:a2", action="write")
        await audit_b.append(event_type="test", agent_did="did:mesh:a3", action="delete")

        assert len(audit_a) == 1
        assert len(audit_b) == 2
