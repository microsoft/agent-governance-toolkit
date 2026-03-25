# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""Tests for the VS Code bridge JSON-over-stdio protocol."""

from __future__ import annotations

import json
from typing import Any
from unittest.mock import MagicMock, patch

import pytest

from agent_os.extensions.vscode_bridge import (
    HANDLERS,
    _agent_to_dict,
    _build_slo_payload,
    _policy_to_dict,
    dispatch,
    error_response,
    main,
    ok_response,
)


# ---------------------------------------------------------------------------
# Response helpers
# ---------------------------------------------------------------------------


class TestResponseHelpers:
    """Verify ok_response and error_response shapes."""

    def test_ok_response_shape(self) -> None:
        result = ok_response({"key": "val"}, 42)
        assert result == {"ok": True, "data": {"key": "val"}, "durationMs": 42}

    def test_error_response_shape(self) -> None:
        result = error_response("boom", 10)
        assert result == {"ok": False, "data": None, "error": "boom", "durationMs": 10}


# ---------------------------------------------------------------------------
# Handler tests
# ---------------------------------------------------------------------------


def test_health_ping() -> None:
    """health.ping returns ok:true with status healthy."""
    result = dispatch({"module": "health", "command": "ping", "args": {}})

    assert result["ok"] is True
    assert result["data"]["status"] == "healthy"
    assert isinstance(result["durationMs"], int)


def test_slo_snapshot_with_dashboard() -> None:
    """SLO snapshot returns the expected payload when agent-sre is available."""
    mock_snapshot = MagicMock()
    mock_snapshot.indicator_values = {
        "task_success_rate": 0.97,
        "response_latency": 1.2,
        "policy_compliance": 0.99,
    }
    mock_dashboard_cls = MagicMock()
    mock_dashboard = mock_dashboard_cls.return_value
    mock_dashboard.take_snapshot.return_value = [mock_snapshot]
    mock_dashboard.health_summary.return_value = {"healthy": 1, "total_slos": 1}

    def fake_slo_handler(_args: dict[str, Any]) -> dict[str, Any]:
        snapshots = mock_dashboard.take_snapshot()
        summary = mock_dashboard.health_summary()
        return ok_response(_build_slo_payload(snapshots, summary), 0)

    with patch.dict(HANDLERS, {"agent_sre.slo.snapshot": fake_slo_handler}):
        result = dispatch({"module": "agent_sre.slo", "command": "snapshot", "args": {}})

    assert result["ok"] is True
    data = result["data"]
    assert "task_success_rate" in data
    assert "response_latency" in data
    assert "policy_compliance" in data
    assert data["task_success_rate"]["value"] == 0.97


def test_slo_snapshot_without_sre() -> None:
    """SLO snapshot returns ok:false when agent-sre is not installed."""
    original = __builtins__.__import__ if hasattr(__builtins__, "__import__") else __import__

    def block_sre(name: str, *args: Any, **kwargs: Any) -> Any:
        if name == "agent_sre.slo.dashboard":
            raise ImportError("No module named 'agent_sre.slo.dashboard'")
        return original(name, *args, **kwargs)

    with patch("builtins.__import__", side_effect=block_sre):
        result = dispatch({"module": "agent_sre.slo", "command": "snapshot", "args": {}})

    assert result["ok"] is False
    assert "agent-sre" in result["error"]


def test_topology_snapshot() -> None:
    """Topology snapshot returns agents and bridges from mocked mesh."""
    mock_agent = MagicMock()
    mock_agent.did = "did:mesh:abc123"
    mock_agent.trust_score = 750
    mock_agent.is_active.return_value = True
    mock_agent.created_at = "2026-01-01T00:00:00Z"
    mock_agent.last_activity = "2026-03-25T00:00:00Z"
    mock_agent.capabilities = ["read", "write"]

    def fake_topology_handler(_args: dict[str, Any]) -> dict[str, Any]:
        agents = [_agent_to_dict(mock_agent)]
        bridges = [{"protocol": "local", "connected": True, "peer_count": 0}]
        return ok_response({"agents": agents, "bridges": bridges, "delegations": []}, 0)

    with patch.dict(HANDLERS, {"agentmesh.topology.snapshot": fake_topology_handler}):
        result = dispatch({"module": "agentmesh.topology", "command": "snapshot", "args": {}})

    assert result["ok"] is True
    data = result["data"]
    assert len(data["agents"]) == 1
    assert data["agents"][0]["did"] == "did:mesh:abc123"
    assert data["agents"][0]["trust_score"] == 750
    assert isinstance(data["bridges"], list)
    assert isinstance(data["delegations"], list)


def test_policy_snapshot() -> None:
    """Policy snapshot returns rules list from mocked evaluator."""
    mock_policy = MagicMock()
    mock_policy.name = "default-policy"
    mock_policy.version = "1.0.0"
    mock_policy.rules = [MagicMock(), MagicMock()]

    def fake_policy_handler(_args: dict[str, Any]) -> dict[str, Any]:
        rules = [_policy_to_dict(mock_policy)]
        return ok_response({"rules": rules, "violations": [], "total_policies": len(rules)}, 0)

    with patch.dict(HANDLERS, {"agent_os.policies.snapshot": fake_policy_handler}):
        result = dispatch({"module": "agent_os.policies", "command": "snapshot", "args": {}})

    assert result["ok"] is True
    data = result["data"]
    assert data["total_policies"] == 1
    assert data["rules"][0]["name"] == "default-policy"
    assert data["rules"][0]["rules_count"] == 2


def test_unknown_module() -> None:
    """Unknown module.command returns ok:false with descriptive error."""
    result = dispatch({"module": "nonexistent", "command": "nope", "args": {}})

    assert result["ok"] is False
    assert "Unknown command" in result["error"]
    assert "nonexistent.nope" in result["error"]


def test_malformed_json_input(capsys: pytest.CaptureFixture[str]) -> None:
    """Invalid JSON input is handled gracefully without crashing."""
    with patch("sys.stdin") as mock_stdin:
        mock_stdin.readline.return_value = "not valid json{{"
        main()

    captured = capsys.readouterr()
    response = json.loads(captured.out.strip())
    assert response["ok"] is False
    assert "Malformed JSON" in response["error"]


def test_handler_exception_sanitized() -> None:
    """Internal exceptions produce a safe error without leaking tracebacks."""

    def exploding_handler(_args: dict[str, Any]) -> None:
        raise ValueError("secret internal detail")

    with patch.dict(HANDLERS, {"boom.explode": exploding_handler}):
        result = dispatch({"module": "boom", "command": "explode", "args": {}})

    assert result["ok"] is False
    assert result["error"] == "Internal handler error"
    assert "secret" not in result.get("error", "")
