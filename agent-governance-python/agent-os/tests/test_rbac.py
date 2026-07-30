# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""Tests for the RBAC module."""
import os
import tempfile
import pytest
from agent_os.integrations.rbac import DEFAULT_ROLE, Role, RBACManager

@pytest.fixture
def mgr() -> RBACManager:
    return RBACManager()

def test_assign_and_get_role(mgr: RBACManager) -> None:
    mgr.assign_role('agent-1', Role.WRITER)
    assert mgr.get_role('agent-1') is Role.WRITER

def test_reader_permissions(mgr: RBACManager) -> None:
    mgr.assign_role('r', Role.READER)
    assert mgr.has_permission('r', 'read') is True
    assert mgr.has_permission('r', 'write') is False
    assert mgr.has_permission('r', 'admin') is False

def test_writer_permissions(mgr: RBACManager) -> None:
    mgr.assign_role('w', Role.WRITER)
    assert mgr.has_permission('w', 'read') is True
    assert mgr.has_permission('w', 'write') is True
    assert mgr.has_permission('w', 'search') is True
    assert mgr.has_permission('w', 'admin') is False

def test_admin_permissions(mgr: RBACManager) -> None:
    mgr.assign_role('a', Role.ADMIN)
    for action in ('read', 'write', 'search', 'admin', 'delete', 'audit'):
        assert mgr.has_permission('a', action) is True

def test_auditor_permissions(mgr: RBACManager) -> None:
    mgr.assign_role('au', Role.AUDITOR)
    assert mgr.has_permission('au', 'read') is True
    assert mgr.has_permission('au', 'search') is True
    assert mgr.has_permission('au', 'audit') is True
    assert mgr.has_permission('au', 'write') is False

def test_unknown_agent_default_role(mgr: RBACManager) -> None:
    assert mgr.get_role('unknown-agent') is DEFAULT_ROLE
    assert mgr.get_role('unknown-agent') is Role.READER

def test_unknown_agent_permissions(mgr: RBACManager) -> None:
    assert mgr.has_permission('unknown-agent', 'read') is True
    assert mgr.has_permission('unknown-agent', 'write') is False

def test_remove_role(mgr: RBACManager) -> None:
    mgr.assign_role('agent-1', Role.ADMIN)
    assert mgr.get_role('agent-1') is Role.ADMIN
    mgr.remove_role('agent-1')
    assert mgr.get_role('agent-1') is Role.READER

def test_remove_nonexistent_role(mgr: RBACManager) -> None:
    mgr.remove_role('no-such-agent')

def test_yaml_roundtrip(mgr: RBACManager) -> None:
    mgr.assign_role('a1', Role.WRITER)
    mgr.assign_role('a2', Role.ADMIN)
    with tempfile.NamedTemporaryFile(suffix='.yaml', delete=False) as f:
        path = f.name
    try:
        mgr.to_yaml(path)
        loaded = RBACManager.from_yaml(path)
        assert loaded.get_role('a1') is Role.WRITER
        assert loaded.get_role('a2') is Role.ADMIN
    finally:
        os.unlink(path)

def test_yaml_with_custom_permissions(mgr: RBACManager) -> None:
    mgr._custom_permissions[Role.READER] = {'read', 'custom_action'}
    mgr.assign_role('agent-y', Role.READER)
    with tempfile.NamedTemporaryFile(suffix='.yaml', delete=False) as f:
        path = f.name
    try:
        mgr.to_yaml(path)
        loaded = RBACManager.from_yaml(path)
        assert loaded.has_permission('agent-y', 'custom_action') is True
        assert loaded.has_permission('agent-y', 'read') is True
    finally:
        os.unlink(path)

def test_multiple_agents(mgr: RBACManager) -> None:
    mgr.assign_role('reader-bot', Role.READER)
    mgr.assign_role('writer-bot', Role.WRITER)
    mgr.assign_role('admin-bot', Role.ADMIN)
    mgr.assign_role('auditor-bot', Role.AUDITOR)
    assert mgr.get_role('reader-bot') is Role.READER
    assert mgr.get_role('writer-bot') is Role.WRITER
    assert mgr.get_role('admin-bot') is Role.ADMIN
    assert mgr.get_role('auditor-bot') is Role.AUDITOR
    assert mgr.has_permission('writer-bot', 'write') is True
    assert mgr.has_permission('reader-bot', 'write') is False
    assert mgr.has_permission('admin-bot', 'delete') is True
    assert mgr.has_permission('auditor-bot', 'audit') is True

def test_reassign_role(mgr: RBACManager) -> None:
    mgr.assign_role('agent-1', Role.READER)
    assert mgr.get_role('agent-1') is Role.READER
    assert mgr.has_permission('agent-1', 'write') is False
    mgr.assign_role('agent-1', Role.ADMIN)
    assert mgr.get_role('agent-1') is Role.ADMIN
    assert mgr.has_permission('agent-1', 'write') is True
