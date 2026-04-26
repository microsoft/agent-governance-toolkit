# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""Tests for MCP session authentication."""

from __future__ import annotations

import threading
import time
from datetime import timedelta

import pytest

from agent_os.mcp_protocols import InMemorySessionStore
from agent_os.mcp_session_auth import MCPSessionAuthenticator


def test_create_and_validate_session():
    authenticator = MCPSessionAuthenticator()

    token = authenticator.create_session("did:mesh:agent-001", user_id="user@example.com")
    session = authenticator.validate_session("did:mesh:agent-001", token)

    assert session is not None
    assert session.user_id == "user@example.com"
    assert session.rate_limit_key == "user@example.com:did:mesh:agent-001"


def test_validate_rejects_wrong_agent():
    authenticator = MCPSessionAuthenticator()
    token = authenticator.create_session("did:mesh:agent-001")

    assert authenticator.validate_session("did:mesh:agent-002", token) is None


def test_expired_session_is_rejected():
    authenticator = MCPSessionAuthenticator(session_ttl=timedelta(milliseconds=10))
    token = authenticator.create_session("did:mesh:agent-001")

    time.sleep(0.05)

    assert authenticator.validate_session("did:mesh:agent-001", token) is None
    assert authenticator.active_session_count == 0


def test_revoke_session_and_revoke_all():
    authenticator = MCPSessionAuthenticator()
    token1 = authenticator.create_session("did:mesh:agent-001")
    token2 = authenticator.create_session("did:mesh:agent-001")
    other = authenticator.create_session("did:mesh:agent-002")

    assert authenticator.revoke_session(token1) is True
    assert authenticator.validate_session("did:mesh:agent-001", token1) is None
    assert authenticator.revoke_all_sessions("did:mesh:agent-001") == 1
    assert authenticator.validate_session("did:mesh:agent-001", token2) is None
    assert authenticator.validate_session("did:mesh:agent-002", other) is not None


def test_max_concurrent_sessions_enforced():
    authenticator = MCPSessionAuthenticator(max_concurrent_sessions=1)
    authenticator.create_session("did:mesh:agent-001")

    with pytest.raises(RuntimeError, match="maximum concurrent sessions"):
        authenticator.create_session("did:mesh:agent-001")


def test_concurrent_creation_respects_limit():
    authenticator = MCPSessionAuthenticator(max_concurrent_sessions=3)
    successes = 0
    failures = 0
    lock = threading.Lock()

    def worker():
        nonlocal successes, failures
        try:
            authenticator.create_session("did:mesh:race-agent")
            with lock:
                successes += 1
        except RuntimeError:
            with lock:
                failures += 1

    threads = [threading.Thread(target=worker) for _ in range(20)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()

    assert successes == 3
    assert failures == 17


def test_session_store_injection():
    store = InMemorySessionStore()
    authenticator = MCPSessionAuthenticator(session_store=store)

    token = authenticator.create_session("did:mesh:agent-001")

    assert store.get(token) is not None
    assert authenticator.revoke_session(token) is True
    assert store.get(token) is None


def test_concurrent_session_lifecycle_is_thread_safe():
    authenticator = MCPSessionAuthenticator(max_concurrent_sessions=50)
    tokens = [authenticator.create_session(f"did:mesh:agent-{index}") for index in range(20)]
    errors: list[Exception] = []
    error_lock = threading.Lock()

    def worker(agent_id: str, token: str):
        try:
            assert authenticator.validate_session(agent_id, token) is not None
            assert authenticator.revoke_session(token) is True
        except Exception as exc:  # pragma: no cover - assertion funnel
            with error_lock:
                errors.append(exc)

    threads = [
        threading.Thread(
            target=worker,
            args=(f"did:mesh:agent-{index}", token),
        )
        for index, token in enumerate(tokens)
    ]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()

    assert errors == []
    assert authenticator.active_session_count == 0
