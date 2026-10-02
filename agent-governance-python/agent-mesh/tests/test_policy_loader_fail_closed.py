# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""Regression tests for fail-closed policy directory loading."""

from __future__ import annotations

from pathlib import Path

import pytest
from fastapi.testclient import TestClient

_VALID_GOVERNANCE_POLICY = "\n".join(
    [
        "name: test-policy",
        'agents: ["*"]',
        "rules:",
        "  - name: deny-shell",
        "    condition: \"action == 'shell.execute'\"",
        "    action: deny",
        "",
    ]
)

_VALID_TRUST_POLICY = "\n".join(
    [
        "name: trust-policy",
        "rules:",
        "  - name: allow-trusted",
        "    condition:",
        "      field: trust_score",
        "      operator: gte",
        "      value: 500",
        "    action: allow",
        "",
    ]
)

_BAD_POLICY = "name: [\n"

_API_VERSION_KEY = "api" + "Version"
_KIND_KEY = "k" + "ind"
_GOVERNANCE_KIND = "Governance" + "Policy"
_GOVERNANCE_SHAPED_POLICY = "\n".join(
    [
        f"{_API_VERSION_KEY}: agentmesh.io/v1alpha1",
        f"{_KIND_KEY}: {_GOVERNANCE_KIND}",
        "name: default",
        "rules: []",
        "",
    ]
)

_TRUST_FALLBACK_WITHOUT_RULES = "\n".join(
    [
        "name: invalid-governance",
        "scope: Team",
        "rules: []",
        "",
    ]
)

_LEGACY_GOVERNANCE_POLICY = "\n".join(
    [
        "name: legacy-governance",
        'agents: ["*"]',
        "rules:",
        "  - name: deny-shell",
        "    condition:",
        "      field: action",
        "      operator: eq",
        "      value: shell.execute",
        "    action: deny",
        "",
    ]
)


@pytest.fixture
def policy_server(monkeypatch):
    """Provide an isolated policy-server module state."""
    import agentmesh.server.policy_server as server

    monkeypatch.setattr(server, "_engine", server.PolicyEngine())
    monkeypatch.setattr(server, "_trust_policies", [])
    monkeypatch.setattr(server, "_trust_evaluator", None)
    monkeypatch.setattr(server, "_loaded_count", 0)
    return server


@pytest.fixture
def sidecar():
    """Provide a sidecar module whose published state is restored afterward."""
    import agentmesh.server.sidecar as server

    previous_state = server._policy_state
    previous_dir = server._policy_dir
    yield server
    server._policy_state = previous_state
    server._policy_dir = previous_dir


def _write(path: Path, content: str) -> None:
    path.write_text(content, encoding="utf-8")


def test_policy_server_loads_trust_policy_from_path(policy_server, tmp_path, monkeypatch):
    _write(tmp_path / "trust.yaml", _VALID_TRUST_POLICY)
    monkeypatch.setattr(policy_server, "POLICY_DIR", str(tmp_path))

    policy_server._load_policies()

    assert policy_server._loaded_count == 1
    assert policy_server._trust_policies[0].name == "trust-policy"
    assert policy_server._trust_evaluator is not None


@pytest.mark.parametrize(
    "content",
    [_GOVERNANCE_SHAPED_POLICY, _TRUST_FALLBACK_WITHOUT_RULES, _LEGACY_GOVERNANCE_POLICY],
    ids=["governance-shaped", "without-rules", "governance-only-fields"],
)
def test_policy_server_rejects_silent_trust_fallback(policy_server, tmp_path, monkeypatch, content):
    _write(tmp_path / "invalid.yaml", content)
    monkeypatch.setattr(policy_server, "POLICY_DIR", str(tmp_path))

    with pytest.raises(RuntimeError, match="invalid.yaml"):
        policy_server._load_policies()

    assert policy_server._loaded_count == 0
    assert policy_server._trust_policies == []


def test_policy_server_rejects_missing_directory(policy_server, tmp_path, monkeypatch):
    monkeypatch.setattr(policy_server, "POLICY_DIR", str(tmp_path / "missing"))

    with pytest.raises(RuntimeError, match="does not exist"):
        policy_server._load_policies()


def test_policy_server_rejects_unreadable_directory(policy_server, tmp_path, monkeypatch):
    _write(tmp_path / "good.yaml", _VALID_GOVERNANCE_POLICY)
    monkeypatch.setattr(policy_server, "POLICY_DIR", str(tmp_path))
    policy_server._load_policies()
    previous_engine = policy_server._engine
    previous_count = policy_server._loaded_count

    def fail_scandir(_path):
        raise PermissionError("permission denied")

    monkeypatch.setattr(policy_server.os, "scandir", fail_scandir)

    with pytest.raises(RuntimeError, match="cannot be read"):
        policy_server._load_policies()

    assert policy_server._engine is previous_engine
    assert policy_server._loaded_count == previous_count


def test_policy_server_failed_reload_preserves_previous_state(policy_server, tmp_path, monkeypatch):
    _write(tmp_path / "good.yaml", _VALID_GOVERNANCE_POLICY)
    monkeypatch.setattr(policy_server, "POLICY_DIR", str(tmp_path))
    policy_server._load_policies()
    previous_engine = policy_server._engine
    previous_count = policy_server._loaded_count

    _write(tmp_path / "bad.yaml", _BAD_POLICY)
    with pytest.raises(RuntimeError, match="bad.yaml"):
        policy_server._load_policies()

    assert policy_server._engine is previous_engine
    assert policy_server._loaded_count == previous_count


def test_policy_server_reload_endpoint_rejects_failed_load(policy_server, tmp_path, monkeypatch):
    _write(tmp_path / "good.yaml", _VALID_GOVERNANCE_POLICY)
    monkeypatch.setattr(policy_server, "POLICY_DIR", str(tmp_path))
    policy_server._load_policies()
    previous_engine = policy_server._engine

    _write(tmp_path / "bad.yaml", _BAD_POLICY)
    response = TestClient(policy_server.app).post("/api/v1/policy/reload")

    assert response.status_code == 409
    assert "previous policy set retained" in response.json()["detail"]
    assert policy_server._engine is previous_engine


@pytest.mark.parametrize("read_error", ["unreadable", "non-utf8"])
def test_policy_server_reload_endpoint_rejects_read_errors(
    policy_server, tmp_path, monkeypatch, read_error
):
    _write(tmp_path / "good.yaml", _VALID_GOVERNANCE_POLICY)
    monkeypatch.setattr(policy_server, "POLICY_DIR", str(tmp_path))
    policy_server._load_policies()
    previous_engine = policy_server._engine

    bad_path = tmp_path / "bad.yaml"
    if read_error == "unreadable":
        _write(bad_path, _VALID_GOVERNANCE_POLICY)
        original_read_text = Path.read_text

        def fail_read_text(path, *args, **kwargs):
            if path == bad_path:
                raise OSError("permission denied")
            return original_read_text(path, *args, **kwargs)

        monkeypatch.setattr(Path, "read_text", fail_read_text)
    else:
        bad_path.write_bytes(b"\xff\xfe")

    response = TestClient(policy_server.app).post("/api/v1/policy/reload")

    assert response.status_code == 409
    assert "bad.yaml" in response.json()["detail"]
    assert policy_server._engine is previous_engine


def test_sidecar_denies_when_policy_directory_is_unavailable(sidecar, tmp_path, monkeypatch):
    monkeypatch.setenv("AGT_POLICY_DIR", str(tmp_path / "missing"))
    generation = sidecar._load_policies()
    client = TestClient(sidecar.create_sidecar_app())

    response = client.post(
        "/api/v1/policy/evaluate",
        json={"agent_did": "did:mesh:test", "action": "file.read"},
    )

    assert generation.directory_status == "unavailable"
    assert generation.policy_set_status == "degraded"
    assert response.status_code == 200
    assert response.json()["decision"] == "deny"
    assert "unavailable" in response.json()["reason"]


def test_sandbox_policy_targets_all_agents():
    from agentmesh.governance.policy import PolicyEngine

    policy_path = (
        Path(__file__).parents[1] / "docker" / "examples" / "policies" / "sandbox-policy.yaml"
    )
    engine = PolicyEngine()
    engine.load_yaml(policy_path.read_text(encoding="utf-8"))

    allow = engine.evaluate(
        agent_did="did:mesh:demo-agent",
        context={"action": "file.read", "resource": "/data/report.csv"},
    )
    deny = engine.evaluate(
        agent_did="did:mesh:demo-agent",
        context={"action": "shell.execute", "resource": "/bin/bash"},
    )

    assert allow.action == "allow"
    assert deny.action == "deny"
