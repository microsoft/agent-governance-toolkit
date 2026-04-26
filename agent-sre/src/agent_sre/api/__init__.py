# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""
REST API for Agent-SRE.

Two server implementations:

1. **Minimal (zero-dependency)** — ``AgentSREServer`` / ``APIState``
   Uses Python's built-in ``http.server``.  Suitable for embedding in
   any agent process with no extra packages.

2. **FastAPI (full-featured)** — ``create_app``
   Requires the ``api`` extra (``pip install agent-sre[api]``).
   Provides versioned REST endpoints for SLOs, cost, chaos, incidents,
   and progressive delivery.  Run with::

       uvicorn agent_sre.api.server:app

Minimal server endpoints:
    GET  /health           — Service health check
    GET  /api/slos         — All SLOs with status and error budgets
    GET  /api/slos/{name}  — Single SLO details
    GET  /api/incidents    — Open incidents
    GET  /api/incidents/all — All incidents (including resolved)
    GET  /api/cost         — Cost summary
    GET  /api/traces       — Recent protocol traces
    GET  /api/status       — Aggregate system status

Usage (minimal):
    from agent_sre.api import AgentSREServer, APIState

    state = APIState()
    state.add_slo(my_slo)
    state.set_incident_detector(detector)

    server = AgentSREServer(state, port=8080)
    server.serve_forever()

Usage (FastAPI):
    from agent_sre.api import create_app

    app = create_app()
"""

from __future__ import annotations

import json
import time
from dataclasses import dataclass, field
from http.server import BaseHTTPRequestHandler, HTTPServer
from typing import TYPE_CHECKING, Any
from urllib.parse import urlparse

from agent_sre.slo.objectives import SLO, SLOStatus

if TYPE_CHECKING:
    from collections.abc import Callable


def create_app() -> Any:
    """Create the FastAPI application (requires ``agent-sre[api]`` extra)."""
    from agent_sre.api.server import create_app as _factory

    return _factory()


# ---------------------------------------------------------------------------
# API state — shared data container
# ---------------------------------------------------------------------------

@dataclass
class CostSnapshot:
    """Point-in-time cost summary."""

    total_usd: float = 0.0
    per_agent: dict[str, float] = field(default_factory=dict)
    budget_usd: float | None = None
    timestamp: float = field(default_factory=time.time)

    @property
    def budget_utilization(self) -> float | None:
        if self.budget_usd and self.budget_usd > 0:
            return self.total_usd / self.budget_usd
        return None

    def to_dict(self) -> dict[str, Any]:
        d: dict[str, Any] = {
            "total_usd": self.total_usd,
            "per_agent": self.per_agent,
            "timestamp": self.timestamp,
        }
        if self.budget_usd is not None:
            d["budget_usd"] = self.budget_usd
            d["budget_utilization"] = self.budget_utilization
        return d


class APIState:
    """Shared state container for the API server.

    Register SLOs, incident detectors, cost data, and trace reports
    here. The HTTP handler reads from this state.
    """

    def __init__(self) -> None:
        self._slos: dict[str, SLO] = {}
        self._incident_detector: Any = None
        self._cost: CostSnapshot = CostSnapshot()
        self._trace_reports: list[dict[str, Any]] = []
        self._metadata: dict[str, str] = {}
        self._start_time: float = time.time()

    # -- SLOs --

    def add_slo(self, slo: SLO) -> None:
        """Register an SLO."""
        self._slos[slo.name] = slo

    def remove_slo(self, name: str) -> bool:
        """Remove an SLO by name."""
        return self._slos.pop(name, None) is not None

    def get_slo(self, name: str) -> SLO | None:
        return self._slos.get(name)

    def all_slos(self) -> dict[str, SLO]:
        return dict(self._slos)

    # -- Incidents --

    def set_incident_detector(self, detector: Any) -> None:
        """Register the incident detector (any object with open_incidents/all_incidents)."""
        self._incident_detector = detector

    @property
    def open_incidents(self) -> list[Any]:
        if self._incident_detector and hasattr(self._incident_detector, "open_incidents"):
            return list(self._incident_detector.open_incidents)
        return []

    @property
    def all_incidents(self) -> list[Any]:
        if self._incident_detector and hasattr(self._incident_detector, "all_incidents"):
            return list(self._incident_detector.all_incidents)
        return []

    # -- Cost --

    def update_cost(self, snapshot: CostSnapshot) -> None:
        self._cost = snapshot

    @property
    def cost(self) -> CostSnapshot:
        return self._cost

    # -- Traces --

    def add_trace_report(self, report: dict[str, Any]) -> None:
        """Add a trace report dict (from TracingReport.to_dict())."""
        self._trace_reports.append(report)
        # Keep last 100
        if len(self._trace_reports) > 100:
            self._trace_reports = self._trace_reports[-100:]

    @property
    def trace_reports(self) -> list[dict[str, Any]]:
        return list(self._trace_reports)

    # -- Metadata --

    def set_metadata(self, key: str, value: str) -> None:
        self._metadata[key] = value

    @property
    def uptime_seconds(self) -> float:
        return time.time() - self._start_time

    # -- Aggregate status --

    def system_status(self) -> dict[str, Any]:
        """Aggregate system health summary."""
        slo_statuses = {name: slo.evaluate().value for name, slo in self._slos.items()}

        worst = SLOStatus.HEALTHY
        for slo in self._slos.values():
            status = slo.evaluate()
            if status == SLOStatus.EXHAUSTED:
                worst = SLOStatus.EXHAUSTED
                break
            elif status == SLOStatus.CRITICAL and worst != SLOStatus.EXHAUSTED:
                worst = SLOStatus.CRITICAL
            elif status == SLOStatus.WARNING and worst not in (
                SLOStatus.CRITICAL,
                SLOStatus.EXHAUSTED,
            ):
                worst = SLOStatus.WARNING

        if not self._slos:
            worst = SLOStatus.UNKNOWN

        return {
            "status": worst.value,
            "slo_count": len(self._slos),
            "slo_statuses": slo_statuses,
            "open_incidents": len(self.open_incidents),
            "total_cost_usd": self._cost.total_usd,
            "uptime_seconds": round(self.uptime_seconds, 1),
            "metadata": self._metadata,
        }


# ---------------------------------------------------------------------------
# HTTP request handler
# ---------------------------------------------------------------------------

def _json_response(handler: _APIHandler, status: int, data: Any) -> None:
    """Send a JSON response."""
    body = json.dumps(data, indent=2, default=str).encode("utf-8")
    handler.send_response(status)
    handler.send_header("Content-Type", "application/json")
    handler.send_header("Content-Length", str(len(body)))
    handler.send_header("Access-Control-Allow-Origin", "http://localhost:8501")  # restrict to dashboard
    handler.end_headers()
    handler.wfile.write(body)


class _APIHandler(BaseHTTPRequestHandler):
    """HTTP request handler for Agent-SRE API."""

    state: APIState  # Set via class attribute by server

    def log_message(self, format: str, *args: Any) -> None:
        """Suppress default access logging."""
        pass

    def do_GET(self) -> None:
        parsed = urlparse(self.path)
        path = parsed.path.rstrip("/")

        routes: dict[str, Callable[[], None]] = {
            "/health": self._handle_health,
            "/api/status": self._handle_status,
            "/api/slos": self._handle_slos,
            "/api/incidents": self._handle_incidents,
            "/api/incidents/all": self._handle_all_incidents,
            "/api/cost": self._handle_cost,
            "/api/traces": self._handle_traces,
        }

        # Check for SLO detail route: /api/slos/{name}
        if path.startswith("/api/slos/") and path.count("/") == 3:
            slo_name = path.split("/")[3]
            self._handle_slo_detail(slo_name)
            return

        handler = routes.get(path)
        if handler:
            handler()
        else:
            _json_response(self, 404, {"error": "Not found", "path": self.path})

    def do_OPTIONS(self) -> None:
        """Handle CORS preflight."""
        self.send_response(204)
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Methods", "GET, OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "Content-Type")
        self.end_headers()

    # -- Route handlers --

    def _handle_health(self) -> None:
        _json_response(self, 200, {
            "status": "ok",
            "uptime_seconds": round(self.state.uptime_seconds, 1),
        })

    def _handle_status(self) -> None:
        _json_response(self, 200, self.state.system_status())

    def _handle_slos(self) -> None:
        slos = {name: slo.to_dict() for name, slo in self.state.all_slos().items()}
        _json_response(self, 200, {"slos": slos, "count": len(slos)})

    def _handle_slo_detail(self, name: str) -> None:
        slo = self.state.get_slo(name)
        if slo is None:
            _json_response(self, 404, {"error": f"SLO '{name}' not found"})
            return
        _json_response(self, 200, slo.to_dict())

    def _handle_incidents(self) -> None:
        incidents = self.state.open_incidents
        data = [inc.to_dict() if hasattr(inc, "to_dict") else str(inc) for inc in incidents]
        _json_response(self, 200, {"incidents": data, "count": len(data)})

    def _handle_all_incidents(self) -> None:
        incidents = self.state.all_incidents
        data = [inc.to_dict() if hasattr(inc, "to_dict") else str(inc) for inc in incidents]
        _json_response(self, 200, {"incidents": data, "count": len(data)})

    def _handle_cost(self) -> None:
        _json_response(self, 200, self.state.cost.to_dict())

    def _handle_traces(self) -> None:
        _json_response(self, 200, {
            "traces": self.state.trace_reports,
            "count": len(self.state.trace_reports),
        })


# ---------------------------------------------------------------------------
# Server
# ---------------------------------------------------------------------------

class AgentSREServer:
    """Minimal HTTP server exposing Agent-SRE data as a REST API.

    Usage:
        state = APIState()
        state.add_slo(my_slo)

        server = AgentSREServer(state, port=8080)
        server.serve_forever()  # blocking
    """

    def __init__(
        self,
        state: APIState,
        host: str = "127.0.0.1",
        port: int = 8080,
    ) -> None:
        self._state = state
        self._host = host
        self._port = port

        # Create handler class with state bound
        handler_class = type(
            "BoundAPIHandler",
            (_APIHandler,),
            {"state": state},
        )
        self._server = HTTPServer((host, port), handler_class)

    @property
    def port(self) -> int:
        return self._server.server_address[1]

    def serve_forever(self) -> None:
        """Start serving (blocks)."""
        self._server.serve_forever()

    def shutdown(self) -> None:
        """Stop the server."""
        self._server.shutdown()

    def handle_request(self) -> None:
        """Handle a single request (for testing)."""
        self._server.handle_request()
