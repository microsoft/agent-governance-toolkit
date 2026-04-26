# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""Tests for Agent-SRE REST API."""

from __future__ import annotations

import json
import threading
import time
import urllib.request
from typing import Any

import pytest

from agent_sre.api import AgentSREServer, APIState, CostSnapshot
from agent_sre.slo.indicators import TaskSuccessRate
from agent_sre.slo.objectives import SLO, ErrorBudget

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_slo(name: str, target: float = 0.95) -> SLO:
    """Create a simple SLO for testing."""
    sli = TaskSuccessRate(target=target, window="1h")
    sli.record_task(True)  # One good event so it's not UNKNOWN
    return SLO(name=name, indicators=[sli])


def _get(url: str) -> tuple[int, Any]:
    """Make a GET request and return (status_code, json_body)."""
    try:
        req = urllib.request.Request(url)
        with urllib.request.urlopen(req, timeout=5) as resp:
            body = json.loads(resp.read().decode())
            return resp.status, body
    except urllib.error.HTTPError as e:
        body = json.loads(e.read().decode())
        return e.code, body


@pytest.fixture()
def api_server():
    """Start a test API server on a random port."""
    state = APIState()
    server = AgentSREServer(state, host="127.0.0.1", port=0)  # port=0 picks random
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    time.sleep(0.1)  # Let server start
    yield state, server
    server.shutdown()


def _url(server: AgentSREServer, path: str) -> str:
    return f"http://127.0.0.1:{server.port}{path}"


# ---------------------------------------------------------------------------
# CostSnapshot unit tests
# ---------------------------------------------------------------------------

class TestCostSnapshot:
    def test_defaults(self):
        snap = CostSnapshot()
        assert snap.total_usd == 0.0
        assert snap.per_agent == {}
        assert snap.budget_utilization is None

    def test_budget_utilization(self):
        snap = CostSnapshot(total_usd=5.0, budget_usd=10.0)
        assert snap.budget_utilization == 0.5

    def test_to_dict_no_budget(self):
        snap = CostSnapshot(total_usd=1.0, per_agent={"a": 0.5, "b": 0.5})
        d = snap.to_dict()
        assert d["total_usd"] == 1.0
        assert "budget_usd" not in d

    def test_to_dict_with_budget(self):
        snap = CostSnapshot(total_usd=3.0, budget_usd=10.0)
        d = snap.to_dict()
        assert d["budget_usd"] == 10.0
        assert d["budget_utilization"] == 0.3


# ---------------------------------------------------------------------------
# APIState unit tests
# ---------------------------------------------------------------------------

class TestAPIState:
    def test_add_and_get_slo(self):
        state = APIState()
        slo = _make_slo("test-slo")
        state.add_slo(slo)
        assert state.get_slo("test-slo") is slo
        assert "test-slo" in state.all_slos()

    def test_remove_slo(self):
        state = APIState()
        slo = _make_slo("test-slo")
        state.add_slo(slo)
        assert state.remove_slo("test-slo") is True
        assert state.get_slo("test-slo") is None
        assert state.remove_slo("nonexistent") is False

    def test_incidents_no_detector(self):
        state = APIState()
        assert state.open_incidents == []
        assert state.all_incidents == []

    def test_incidents_with_detector(self):
        state = APIState()

        class FakeDetector:
            open_incidents = [{"id": 1}]
            all_incidents = [{"id": 1}, {"id": 2}]

        state.set_incident_detector(FakeDetector())
        assert len(state.open_incidents) == 1
        assert len(state.all_incidents) == 2

    def test_cost_default(self):
        state = APIState()
        assert state.cost.total_usd == 0.0

    def test_update_cost(self):
        state = APIState()
        state.update_cost(CostSnapshot(total_usd=42.0))
        assert state.cost.total_usd == 42.0

    def test_trace_reports(self):
        state = APIState()
        assert state.trace_reports == []
        state.add_trace_report({"trace_id": "t1"})
        assert len(state.trace_reports) == 1

    def test_trace_report_cap(self):
        state = APIState()
        for i in range(110):
            state.add_trace_report({"i": i})
        assert len(state.trace_reports) == 100

    def test_metadata(self):
        state = APIState()
        state.set_metadata("version", "1.0")
        status = state.system_status()
        assert status["metadata"]["version"] == "1.0"

    def test_uptime(self):
        state = APIState()
        time.sleep(0.05)
        assert state.uptime_seconds > 0

    def test_system_status_no_slos(self):
        state = APIState()
        status = state.system_status()
        assert status["status"] == "unknown"
        assert status["slo_count"] == 0

    def test_system_status_healthy(self):
        state = APIState()
        state.add_slo(_make_slo("healthy-slo"))
        status = state.system_status()
        assert status["status"] == "healthy"

    def test_system_status_worst_wins(self):
        state = APIState()
        healthy = _make_slo("healthy")
        state.add_slo(healthy)
        # Create exhausted SLO
        exhausted = _make_slo("exhausted")
        exhausted.error_budget = ErrorBudget(total=0.01, consumed=1.0)
        state.add_slo(exhausted)
        status = state.system_status()
        assert status["status"] == "exhausted"


# ---------------------------------------------------------------------------
# HTTP endpoint tests
# ---------------------------------------------------------------------------

class TestHealthEndpoint:
    def test_health(self, api_server):
        state, server = api_server
        status, body = _get(_url(server, "/health"))
        assert status == 200
        assert body["status"] == "ok"
        assert "uptime_seconds" in body


class TestStatusEndpoint:
    def test_status_empty(self, api_server):
        state, server = api_server
        status, body = _get(_url(server, "/api/status"))
        assert status == 200
        assert body["status"] == "unknown"
        assert body["slo_count"] == 0

    def test_status_with_slo(self, api_server):
        state, server = api_server
        state.add_slo(_make_slo("my-slo"))
        status, body = _get(_url(server, "/api/status"))
        assert status == 200
        assert body["status"] == "healthy"
        assert body["slo_count"] == 1


class TestSLOEndpoints:
    def test_list_slos_empty(self, api_server):
        state, server = api_server
        status, body = _get(_url(server, "/api/slos"))
        assert status == 200
        assert body["count"] == 0

    def test_list_slos(self, api_server):
        state, server = api_server
        state.add_slo(_make_slo("slo-a"))
        state.add_slo(_make_slo("slo-b"))
        status, body = _get(_url(server, "/api/slos"))
        assert status == 200
        assert body["count"] == 2
        assert "slo-a" in body["slos"]
        assert "slo-b" in body["slos"]

    def test_slo_detail(self, api_server):
        state, server = api_server
        state.add_slo(_make_slo("detail-slo"))
        status, body = _get(_url(server, "/api/slos/detail-slo"))
        assert status == 200
        assert body["name"] == "detail-slo"
        assert "status" in body
        assert "error_budget" in body

    def test_slo_detail_not_found(self, api_server):
        state, server = api_server
        status, body = _get(_url(server, "/api/slos/nonexistent"))
        assert status == 404
        assert "not found" in body["error"].lower()


class TestIncidentEndpoints:
    def test_incidents_empty(self, api_server):
        state, server = api_server
        status, body = _get(_url(server, "/api/incidents"))
        assert status == 200
        assert body["count"] == 0

    def test_incidents_with_data(self, api_server):
        state, server = api_server

        class FakeIncident:
            def to_dict(self):
                return {"id": "inc-1", "title": "High latency"}

        class FakeDetector:
            open_incidents = [FakeIncident()]
            all_incidents = [FakeIncident()]

        state.set_incident_detector(FakeDetector())
        status, body = _get(_url(server, "/api/incidents"))
        assert status == 200
        assert body["count"] == 1
        assert body["incidents"][0]["title"] == "High latency"


class TestCostEndpoint:
    def test_cost_default(self, api_server):
        state, server = api_server
        status, body = _get(_url(server, "/api/cost"))
        assert status == 200
        assert body["total_usd"] == 0.0

    def test_cost_with_data(self, api_server):
        state, server = api_server
        state.update_cost(CostSnapshot(
            total_usd=15.5,
            per_agent={"agent-a": 10.0, "agent-b": 5.5},
            budget_usd=50.0,
        ))
        status, body = _get(_url(server, "/api/cost"))
        assert status == 200
        assert body["total_usd"] == 15.5
        assert body["per_agent"]["agent-a"] == 10.0
        assert body["budget_utilization"] == 0.31


class TestTracesEndpoint:
    def test_traces_empty(self, api_server):
        state, server = api_server
        status, body = _get(_url(server, "/api/traces"))
        assert status == 200
        assert body["count"] == 0

    def test_traces_with_data(self, api_server):
        state, server = api_server
        state.add_trace_report({"trace_id": "t1", "a2a_calls": 2})
        status, body = _get(_url(server, "/api/traces"))
        assert status == 200
        assert body["count"] == 1
        assert body["traces"][0]["trace_id"] == "t1"


class TestNotFound:
    def test_unknown_path(self, api_server):
        state, server = api_server
        status, body = _get(_url(server, "/api/unknown"))
        assert status == 404
        assert "Not found" in body["error"]
