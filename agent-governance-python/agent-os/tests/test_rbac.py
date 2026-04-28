# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""Tests for the RBAC module."""

import os
import tempfile

import pytest

from agent_os.integrations.base import GovernancePolicy
from agent_os.integrations.rbac import DEFAULT_ROLE, Role, RBACManager


# ── Fixtures ──────────────────────────────────────────────────


@pytest.fixture
def mgr() -> RBACManager:
    return RBACManager()


# ── 1. Role assignment and retrieval ─────────────────────────


def test_assign_and_get_role(mgr: RBACManager) -> None:
    mgr.assign_role("agent-1", Role.WRITER)
    assert mgr.get_role("agent-1") is Role.WRITER


# ── 2. Policy lookup per role ─────────────────────────────────


def test_reader_policy(mgr: RBACManager) -> None:
    mgr.assign_role("r", Role.READER)
    p = mgr.get_policy("r")
    assert p.max_tool_calls == 0
    assert p.allowed_tools == []
    assert p.require_human_approval is True


def test_writer_policy(mgr: RBACManager) -> None:
    mgr.assign_role("w", Role.WRITER)
    p = mgr.get_policy("w")
    assert p.max_tool_calls == 5
    assert p.allowed_tools == ["read", "write", "search"]
    assert p.require_human_approval is False


def test_admin_policy(mgr: RBACManager) -> None:
    mgr.assign_role("a", Role.ADMIN)
    p = mgr.get_policy("a")
    assert p.max_tool_calls == 50
    assert p.allowed_tools == []
    assert p.max_tokens == 16384
    assert p.require_human_approval is False


def test_auditor_policy(mgr: RBACManager) -> None:
    mgr.assign_role("au", Role.AUDITOR)
    p = mgr.get_policy("au")
    assert p.max_tool_calls == 5
    assert p.allowed_tools == ["read", "search", "audit"]
    assert p.log_all_calls is True
    assert p.require_human_approval is False


# ── 3. Permission checking ───────────────────────────────────


def test_reader_permissions(mgr: RBACManager) -> None:
    mgr.assign_role("r", Role.READER)
    assert mgr.has_permission("r", "read") is True
    assert mgr.has_permission("r", "write") is False
    assert mgr.has_permission("r", "admin") is False


def test_writer_permissions(mgr: RBACManager) -> None:
    mgr.assign_role("w", Role.WRITER)
    assert mgr.has_permission("w", "read") is True
    assert mgr.has_permission("w", "write") is True
    assert mgr.has_permission("w", "search") is True
    assert mgr.has_permission("w", "admin") is False


def test_admin_permissions(mgr: RBACManager) -> None:
    mgr.assign_role("a", Role.ADMIN)
    for action in ("read", "write", "search", "admin", "delete", "audit"):
        assert mgr.has_permission("a", action) is True


def test_auditor_permissions(mgr: RBACManager) -> None:
    mgr.assign_role("au", Role.AUDITOR)
    assert mgr.has_permission("au", "read") is True
    assert mgr.has_permission("au", "search") is True
    assert mgr.has_permission("au", "audit") is True
    assert mgr.has_permission("au", "write") is False


# ── 4. Unknown agent gets default READER role ────────────────


def test_unknown_agent_default_role(mgr: RBACManager) -> None:
    assert mgr.get_role("unknown-agent") is DEFAULT_ROLE
    assert mgr.get_role("unknown-agent") is Role.READER


def test_unknown_agent_default_policy(mgr: RBACManager) -> None:
    p = mgr.get_policy("unknown-agent")
    assert p.max_tool_calls == 0
    assert p.require_human_approval is True


def test_unknown_agent_permissions(mgr: RBACManager) -> None:
    assert mgr.has_permission("unknown-agent", "read") is True
    assert mgr.has_permission("unknown-agent", "write") is False


# ── 5. Role removal ──────────────────────────────────────────


def test_remove_role(mgr: RBACManager) -> None:
    mgr.assign_role("agent-1", Role.ADMIN)
    assert mgr.get_role("agent-1") is Role.ADMIN
    mgr.remove_role("agent-1")
    assert mgr.get_role("agent-1") is Role.READER


def test_remove_nonexistent_role(mgr: RBACManager) -> None:
    mgr.remove_role("no-such-agent")  # should not raise


# ── 6. Custom role definitions via YAML ──────────────────────


def test_yaml_roundtrip(mgr: RBACManager) -> None:
    mgr.assign_role("a1", Role.WRITER)
    mgr.assign_role("a2", Role.ADMIN)

    with tempfile.NamedTemporaryFile(suffix=".yaml", delete=False) as f:
        path = f.name
    try:
        mgr.to_yaml(path)
        loaded = RBACManager.from_yaml(path)
        assert loaded.get_role("a1") is Role.WRITER
        assert loaded.get_role("a2") is Role.ADMIN
    finally:
        os.unlink(path)


def test_yaml_with_custom_policy(mgr: RBACManager) -> None:
    custom = GovernancePolicy(max_tool_calls=99, allowed_tools=["custom_tool"])
    mgr._custom_policies[Role.WRITER] = custom
    mgr.assign_role("agent-x", Role.WRITER)

    with tempfile.NamedTemporaryFile(suffix=".yaml", delete=False) as f:
        path = f.name
    try:
        mgr.to_yaml(path)
        loaded = RBACManager.from_yaml(path)
        p = loaded.get_policy("agent-x")
        assert p.max_tool_calls == 99
        assert p.allowed_tools == ["custom_tool"]
    finally:
        os.unlink(path)


def test_yaml_with_custom_permissions(mgr: RBACManager) -> None:
    mgr._custom_permissions[Role.READER] = {"read", "custom_action"}
    mgr.assign_role("agent-y", Role.READER)

    with tempfile.NamedTemporaryFile(suffix=".yaml", delete=False) as f:
        path = f.name
    try:
        mgr.to_yaml(path)
        loaded = RBACManager.from_yaml(path)
        assert loaded.has_permission("agent-y", "custom_action") is True
        assert loaded.has_permission("agent-y", "read") is True
    finally:
        os.unlink(path)


# ── 7. Multiple agents with different roles ──────────────────


def test_multiple_agents(mgr: RBACManager) -> None:
    mgr.assign_role("reader-bot", Role.READER)
    mgr.assign_role("writer-bot", Role.WRITER)
    mgr.assign_role("admin-bot", Role.ADMIN)
    mgr.assign_role("auditor-bot", Role.AUDITOR)

    assert mgr.get_role("reader-bot") is Role.READER
    assert mgr.get_role("writer-bot") is Role.WRITER
    assert mgr.get_role("admin-bot") is Role.ADMIN
    assert mgr.get_role("auditor-bot") is Role.AUDITOR

    assert mgr.has_permission("writer-bot", "write") is True
    assert mgr.has_permission("reader-bot", "write") is False
    assert mgr.has_permission("admin-bot", "delete") is True
    assert mgr.has_permission("auditor-bot", "audit") is True


# ── 8. Re-assigning a role updates correctly ─────────────────


def test_reassign_role(mgr: RBACManager) -> None:
    mgr.assign_role("agent-1", Role.READER)
    assert mgr.get_role("agent-1") is Role.READER
    assert mgr.has_permission("agent-1", "write") is False

    mgr.assign_role("agent-1", Role.ADMIN)
    assert mgr.get_role("agent-1") is Role.ADMIN
    assert mgr.has_permission("agent-1", "write") is True
    assert mgr.get_policy("agent-1").max_tokens == 16384
