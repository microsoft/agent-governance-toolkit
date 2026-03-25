# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""VS Code extension bridge for Agent OS.

JSON-over-stdio bridge spawned by SubprocessTransport as
``python -m agent_os.extensions.vscode_bridge --json``.
Request:  ``{"module": str, "command": str, "args": dict}``
Response: ``{"ok": bool, "data": ..., "durationMs": int}``
"""

from __future__ import annotations

import json
import sys
import time
from typing import Any

# ---------------------------------------------------------------------------
# Response helpers
# ---------------------------------------------------------------------------

ResponseDict = dict[str, Any]


def ok_response(data: Any, elapsed_ms: int) -> ResponseDict:
    """Build a successful response envelope."""
    return {"ok": True, "data": data, "durationMs": elapsed_ms}


def error_response(message: str, elapsed_ms: int = 0) -> ResponseDict:
    """Build an error response envelope."""
    return {"ok": False, "data": None, "error": message, "durationMs": elapsed_ms}


# ---------------------------------------------------------------------------
# Handlers
# ---------------------------------------------------------------------------

def handle_health_ping(_args: dict[str, Any]) -> ResponseDict:
    """Return a simple health-check acknowledgement."""
    return ok_response({"status": "healthy"}, 0)


def handle_slo_snapshot(_args: dict[str, Any]) -> ResponseDict:
    """Query SLO dashboard and return a snapshot payload."""
    try:
        from agent_sre.slo.dashboard import SLODashboard  # noqa: F811
    except ImportError:
        return error_response("agent-sre package not installed")

    dashboard = SLODashboard()
    snapshots = dashboard.take_snapshot()
    summary = dashboard.health_summary()
    slo_data = _build_slo_payload(snapshots, summary)
    trust_data = _fetch_trust_scores()
    if trust_data is not None:
        slo_data["trust_scores"] = trust_data
    return ok_response(slo_data, 0)


def _build_slo_payload(
    snapshots: list[Any], summary: dict[str, Any]
) -> dict[str, Any]:
    """Transform SLO snapshots into the VS Code payload shape."""
    indicator_map: dict[str, float | None] = {}
    for snap in snapshots:
        for name, value in snap.indicator_values.items():
            indicator_map[name] = value

    return {
        "task_success_rate": {
            "value": indicator_map.get("task_success_rate", 0.0) or 0.0,
            "target": 0.95,
            "compliance": summary.get("healthy", 0) / max(summary.get("total_slos", 1), 1),
            "window": "7d",
        },
        "response_latency": {
            "value": indicator_map.get("response_latency", 0.0) or 0.0,
            "target": 2.0,
            "p50": indicator_map.get("latency_p50", 0.0) or 0.0,
            "p95": indicator_map.get("latency_p95", 0.0) or 0.0,
            "p99": indicator_map.get("latency_p99", 0.0) or 0.0,
        },
        "policy_compliance": {
            "value": indicator_map.get("policy_compliance", 0.0) or 0.0,
            "target": 1.0,
            "compliance": indicator_map.get("policy_compliance", 0.0) or 0.0,
        },
    }


def _fetch_trust_scores() -> dict[str, Any] | None:
    """Try to load trust score data from agentmesh. Returns None on failure."""
    try:
        from agentmesh.identity.agent_id import IdentityRegistry  # noqa: F811
    except ImportError:
        return None

    registry = IdentityRegistry()
    agents = registry.list_active()
    if not agents:
        return {"mean": 0.0, "min": 0, "below_threshold": 0, "distribution": [0, 0, 0, 0]}

    scores = [getattr(a, "trust_score", 500) for a in agents]
    return _compute_trust_distribution(scores)


def _compute_trust_distribution(scores: list[int]) -> dict[str, Any]:
    """Bucket trust scores into quartile distribution."""
    buckets = [0, 0, 0, 0]  # [0-250, 251-500, 501-750, 751-1000]
    for s in scores:
        idx = min(s // 251, 3)
        buckets[idx] += 1
    return {
        "mean": round(sum(scores) / len(scores), 1),
        "min": min(scores),
        "below_threshold": sum(1 for s in scores if s < 300),
        "distribution": buckets,
    }


def handle_topology_snapshot(_args: dict[str, Any]) -> ResponseDict:
    """Query the agent mesh for topology data."""
    try:
        from agentmesh.identity.agent_id import IdentityRegistry  # noqa: F811
        from agentmesh.trust.bridge import TrustBridge  # noqa: F811
    except ImportError:
        return error_response("agentmesh package not installed")

    registry = IdentityRegistry()
    agents = [_agent_to_dict(a) for a in registry.list_active()]
    bridge = TrustBridge(name="vscode-bridge", protocol="local")
    peers = bridge.get_trusted_peers()
    bridges = [{"protocol": bridge.protocol, "connected": True, "peer_count": len(peers)}]
    return ok_response({"agents": agents, "bridges": bridges, "delegations": []}, 0)


def _agent_to_dict(agent: Any) -> dict[str, Any]:
    """Serialize an AgentIdentity to the VS Code topology shape."""
    return {
        "did": str(getattr(agent, "did", "")),
        "trust_score": getattr(agent, "trust_score", 500),
        "status": "active" if agent.is_active() else "inactive",
        "created_at": str(getattr(agent, "created_at", "")),
        "last_activity": str(getattr(agent, "last_activity", "")),
        "capabilities": list(getattr(agent, "capabilities", [])),
    }


def handle_policy_snapshot(_args: dict[str, Any]) -> ResponseDict:
    """Query the policy engine for current rules and violations."""
    try:
        from agent_os.policies.evaluator import PolicyEvaluator  # noqa: F811
    except ImportError:
        return error_response("agent-os-kernel package not installed")

    evaluator = PolicyEvaluator()
    rules = [_policy_to_dict(p) for p in evaluator.policies]
    return ok_response({"rules": rules, "violations": [], "total_policies": len(rules)}, 0)


def _policy_to_dict(policy: Any) -> dict[str, Any]:
    """Serialize a PolicyDocument to a summary dict."""
    return {
        "name": getattr(policy, "name", "unknown"),
        "version": getattr(policy, "version", "0.0.0"),
        "rules_count": len(getattr(policy, "rules", [])),
    }


# ---------------------------------------------------------------------------
# Dispatch
# ---------------------------------------------------------------------------

HANDLERS: dict[str, Any] = {
    "health.ping": handle_health_ping,
    "agent_sre.slo.snapshot": handle_slo_snapshot,
    "agentmesh.topology.snapshot": handle_topology_snapshot,
    "agent_os.policies.snapshot": handle_policy_snapshot,
}


def dispatch(request: dict[str, Any]) -> ResponseDict:
    """Route a parsed request to the appropriate handler.

    Args:
        request: Dict with ``module``, ``command``, and ``args`` keys.

    Returns:
        A JSON-serializable response envelope.
    """
    module = request.get("module", "")
    command = request.get("command", "")
    key = f"{module}.{command}"
    handler = HANDLERS.get(key)
    if handler is None:
        return error_response(f"Unknown command: {key}")

    start = time.monotonic()
    try:
        result = handler(request.get("args", {}))
        elapsed = int((time.monotonic() - start) * 1000)
        if result.get("durationMs", 0) == 0:
            result["durationMs"] = elapsed
        return result
    except Exception as exc:
        elapsed = int((time.monotonic() - start) * 1000)
        _log_error(exc)
        return error_response("Internal handler error", elapsed)


def _log_error(exc: BaseException) -> None:
    """Write exception details to stderr (never stdout)."""
    print(f"[vscode_bridge] {type(exc).__name__}: {exc}", file=sys.stderr)


# ---------------------------------------------------------------------------
# Main entry point
# ---------------------------------------------------------------------------

def main() -> None:
    """Read one JSON request from stdin, dispatch, write response to stdout."""
    raw = sys.stdin.readline()
    if not raw.strip():
        _write_response(error_response("Empty input"))
        return

    try:
        request = json.loads(raw)
    except json.JSONDecodeError:
        _write_response(error_response("Malformed JSON input"))
        return

    if not isinstance(request, dict):
        _write_response(error_response("Request must be a JSON object"))
        return

    _write_response(dispatch(request))


def _write_response(response: ResponseDict) -> None:
    """Write a single JSON line to stdout and flush."""
    sys.stdout.write(json.dumps(response) + "\n")
    sys.stdout.flush()


if __name__ == "__main__":
    main()
