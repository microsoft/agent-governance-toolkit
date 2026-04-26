# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""FastAPI REST API server for Agent-SRE.

Provides comprehensive endpoints for SLO management, cost tracking,
chaos engineering, incident response, and progressive delivery.

Run with::

    uvicorn agent_sre.api.server:app
"""

from __future__ import annotations

import os
import time
from contextlib import asynccontextmanager
from typing import TYPE_CHECKING, Any

from fastapi import FastAPI, HTTPException, Query
from fastapi.middleware.cors import CORSMiddleware

from agent_sre.chaos.engine import (
    AbortCondition,
    ChaosExperiment,
    ExperimentState,
    Fault,
    FaultType,
)
from agent_sre.cost.guard import CostGuard
from agent_sre.delivery.rollout import (
    CanaryRollout,
    RollbackCondition,
    RolloutState,
    RolloutStep,
)
from agent_sre.incidents.detector import (
    Incident,
    IncidentDetector,
    IncidentState,
    Signal,
    SignalType,
)
from agent_sre.slo.dashboard import SLODashboard
from agent_sre.slo.indicators import SLI, SLIValue
from agent_sre.slo.objectives import SLO, ErrorBudget

if TYPE_CHECKING:
    from collections.abc import AsyncGenerator

    from agent_sre.api.models import (
        ChaosCreateRequest,
        CostRecordRequest,
        FaultInjectRequest,
        IncidentResolveRequest,
        RolloutCreateRequest,
        SignalIngestRequest,
        SLOCreateRequest,
        SLOEventRequest,
    )

# ---------------------------------------------------------------------------
# In-memory stores (reset on restart)
# ---------------------------------------------------------------------------

_dashboard: SLODashboard | None = None
_cost_guard: CostGuard | None = None
_incident_detector: IncidentDetector | None = None
_experiments: dict[str, ChaosExperiment] = {}
_rollouts: dict[str, CanaryRollout] = {}
_start_time: float = 0.0
_metrics_counters: dict[str, int] = {
    "requests_total": 0,
    "slo_events_total": 0,
    "cost_records_total": 0,
    "signals_ingested_total": 0,
    "faults_injected_total": 0,
}


# ---------------------------------------------------------------------------
# Lightweight SLI for API-registered SLOs
# ---------------------------------------------------------------------------


class _APISli(SLI):
    """Minimal SLI backed by manual event recording."""

    def __init__(self, name: str, target: float, window: str = "30d") -> None:
        super().__init__(name=name, target=target, window=window)

    def collect(self) -> SLIValue:
        val = self.current_value()
        return SLIValue(name=self.name, value=val if val is not None else 0.0)


# ---------------------------------------------------------------------------
# Lifespan
# ---------------------------------------------------------------------------


@asynccontextmanager
async def _lifespan(app: FastAPI) -> AsyncGenerator[None, None]:
    global _dashboard, _cost_guard, _incident_detector, _start_time
    _dashboard = SLODashboard()
    _cost_guard = CostGuard()
    _incident_detector = IncidentDetector()
    _start_time = time.time()
    yield
    # cleanup (nothing needed for in-memory stores)


# ---------------------------------------------------------------------------
# Application factory
# ---------------------------------------------------------------------------


def create_app() -> FastAPI:
    """Create and configure the FastAPI application."""
    application = FastAPI(
        title="Agent-SRE API",
        description="Reliability Engineering for AI Agent Systems",
        version="0.1.0",
        lifespan=_lifespan,
    )
    application.add_middleware(
        CORSMiddleware,
        allow_origins=os.environ.get("CORS_ALLOWED_ORIGINS", "http://localhost:3000,http://localhost:8080").split(","),
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )
    return application


app = create_app()


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _get_dashboard() -> SLODashboard:
    assert _dashboard is not None, "Dashboard not initialised"  # noqa: S101 — startup validation assertion
    return _dashboard


def _get_cost_guard() -> CostGuard:
    assert _cost_guard is not None, "CostGuard not initialised"  # noqa: S101 — startup validation assertion
    return _cost_guard


def _get_incident_detector() -> IncidentDetector:
    assert _incident_detector is not None, "IncidentDetector not initialised"  # noqa: S101 — startup validation assertion
    return _incident_detector


def _bump(counter: str) -> None:
    _metrics_counters["requests_total"] += 1
    _metrics_counters[counter] = _metrics_counters.get(counter, 0) + 1


# =========================================================================
# Health & stats
# =========================================================================


@app.get("/health", tags=["health"])
def health_check() -> dict[str, Any]:
    """Service health check."""
    return {
        "status": "ok",
        "uptime_seconds": round(time.time() - _start_time, 1),
    }


@app.get("/api/v1/stats", tags=["health"])
def sre_stats() -> dict[str, Any]:
    """Overall SRE statistics."""
    db = _get_dashboard()
    cg = _get_cost_guard()
    det = _get_incident_detector()
    return {
        "slos": db.health_summary(),
        "cost": cg.summary(),
        "incidents": det.summary(),
        "experiments": len(_experiments),
        "rollouts": len(_rollouts),
        "counters": dict(_metrics_counters),
        "uptime_seconds": round(time.time() - _start_time, 1),
    }


@app.get("/metrics", tags=["health"])
def prometheus_metrics() -> str:
    """Prometheus-compatible metrics endpoint."""
    db = _get_dashboard()
    cg = _get_cost_guard()
    det = _get_incident_detector()
    health = db.health_summary()
    lines: list[str] = [
        "# HELP agent_sre_up Whether the service is up.",
        "# TYPE agent_sre_up gauge",
        "agent_sre_up 1",
        "# HELP agent_sre_slos_total Total registered SLOs.",
        "# TYPE agent_sre_slos_total gauge",
        f"agent_sre_slos_total {health.get('total_slos', 0)}",
        "# HELP agent_sre_slos_healthy Healthy SLOs.",
        "# TYPE agent_sre_slos_healthy gauge",
        f"agent_sre_slos_healthy {health.get('healthy', 0)}",
        "# HELP agent_sre_incidents_open Open incidents.",
        "# TYPE agent_sre_incidents_open gauge",
        f"agent_sre_incidents_open {det.summary().get('open_incidents', 0)}",
        "# HELP agent_sre_cost_org_spent_month Org spend this month (USD).",
        "# TYPE agent_sre_cost_org_spent_month gauge",
        f"agent_sre_cost_org_spent_month {cg.org_spent_month}",
        "# HELP agent_sre_requests_total Total API requests.",
        "# TYPE agent_sre_requests_total counter",
        f"agent_sre_requests_total {_metrics_counters['requests_total']}",
    ]
    return "\n".join(lines) + "\n"


# =========================================================================
# SLO endpoints
# =========================================================================


@app.post("/api/v1/slos", tags=["slos"], status_code=201)
def register_slo(body: SLOCreateRequest) -> dict[str, Any]:
    """Register a new SLO."""
    db = _get_dashboard()
    if body.name in {s.name for s in db._slos.values()}:
        raise HTTPException(status_code=409, detail=f"SLO '{body.name}' already exists")

    indicators: list[SLI] = []
    for ind in body.indicators:
        indicators.append(_APISli(name=ind.name, target=ind.target, window=ind.window))

    budget = ErrorBudget(total=body.error_budget_total) if body.error_budget_total else None
    slo = SLO(
        name=body.name,
        description=body.description,
        indicators=indicators,
        error_budget=budget,
        labels=body.labels,
        agent_id=body.agent_id,
    )
    db.register_slo(slo)
    _bump("slo_events_total")
    return slo.to_dict()


@app.get("/api/v1/slos", tags=["slos"])
def list_slos() -> dict[str, Any]:
    """List all SLOs with current status."""
    db = _get_dashboard()
    _bump("requests_total")
    slos = db.current_status()
    return {"slos": slos, "count": len(slos)}


@app.get("/api/v1/slos/{slo_name}", tags=["slos"])
def get_slo(slo_name: str) -> dict[str, Any]:
    """Get SLO details including indicators, budget, and burn rate."""
    db = _get_dashboard()
    slo = db._slos.get(slo_name)
    if slo is None:
        raise HTTPException(status_code=404, detail=f"SLO '{slo_name}' not found")
    _bump("requests_total")
    return slo.to_dict()


@app.get("/api/v1/slos/{slo_name}/history", tags=["slos"])
def get_slo_history(
    slo_name: str,
    since: float | None = Query(None, description="Unix timestamp lower bound"),
    until: float | None = Query(None, description="Unix timestamp upper bound"),
) -> dict[str, Any]:
    """Get SLO snapshots over time."""
    db = _get_dashboard()
    if slo_name not in db._slos:
        raise HTTPException(status_code=404, detail=f"SLO '{slo_name}' not found")
    snapshots = db.snapshots_in_range(slo_name=slo_name, since=since, until=until)
    _bump("requests_total")
    return {"slo_name": slo_name, "snapshots": [s.to_dict() for s in snapshots]}


@app.post("/api/v1/slos/{slo_name}/events", tags=["slos"])
def record_slo_event(slo_name: str, body: SLOEventRequest) -> dict[str, Any]:
    """Record a good or bad event against an SLO."""
    db = _get_dashboard()
    slo = db._slos.get(slo_name)
    if slo is None:
        raise HTTPException(status_code=404, detail=f"SLO '{slo_name}' not found")
    slo.record_event(body.good)
    _bump("slo_events_total")
    return {"slo_name": slo_name, "good": body.good, "status": slo.evaluate().value}


# =========================================================================
# Cost endpoints
# =========================================================================


@app.get("/api/v1/cost/budgets", tags=["cost"])
def list_budgets() -> dict[str, Any]:
    """List all agent budgets."""
    cg = _get_cost_guard()
    _bump("requests_total")
    return {
        "budgets": {aid: b.to_dict() for aid, b in cg._budgets.items()},
        "count": len(cg._budgets),
    }


@app.get("/api/v1/cost/budgets/{agent_id}", tags=["cost"])
def get_budget(agent_id: str) -> dict[str, Any]:
    """Get budget details for a specific agent."""
    cg = _get_cost_guard()
    _bump("requests_total")
    budget = cg.get_budget(agent_id)
    return budget.to_dict()


@app.post("/api/v1/cost/record", tags=["cost"], status_code=201)
def record_cost(body: CostRecordRequest) -> dict[str, Any]:
    """Record a cost event."""
    cg = _get_cost_guard()
    alerts = cg.record_cost(
        agent_id=body.agent_id,
        task_id=body.task_id,
        cost_usd=body.cost_usd,
        breakdown=body.breakdown,
    )
    _bump("cost_records_total")
    return {
        "agent_id": body.agent_id,
        "cost_usd": body.cost_usd,
        "alerts": [a.to_dict() for a in alerts],
    }


@app.get("/api/v1/cost/alerts", tags=["cost"])
def get_cost_alerts() -> dict[str, Any]:
    """Get active cost alerts."""
    cg = _get_cost_guard()
    _bump("requests_total")
    return {"alerts": [a.to_dict() for a in cg.alerts], "count": len(cg.alerts)}


@app.get("/api/v1/cost/summary", tags=["cost"])
def cost_summary() -> dict[str, Any]:
    """Cost summary across all agents."""
    cg = _get_cost_guard()
    _bump("requests_total")
    return cg.summary()


# =========================================================================
# Chaos endpoints
# =========================================================================


@app.post("/api/v1/chaos/experiments", tags=["chaos"], status_code=201)
def create_experiment(body: ChaosCreateRequest) -> dict[str, Any]:
    """Create a chaos experiment."""
    faults = []
    for f in body.faults:
        try:
            ft = FaultType(f.fault_type)
        except ValueError as e:
            raise HTTPException(
                status_code=400,
                detail=f"Unknown fault type '{f.fault_type}'. "
                f"Valid: {[t.value for t in FaultType]}",
            ) from e
        faults.append(Fault(fault_type=ft, target=f.target, rate=f.rate, params=f.params))

    abort_conditions = [
        AbortCondition(metric=a.metric, threshold=a.threshold, comparator=a.comparator)
        for a in body.abort_conditions
    ]

    exp = ChaosExperiment(
        name=body.name,
        target_agent=body.target_agent,
        faults=faults,
        duration_seconds=body.duration_seconds,
        abort_conditions=abort_conditions,
        blast_radius=body.blast_radius,
        description=body.description,
    )
    _experiments[exp.experiment_id] = exp
    _bump("requests_total")
    return exp.to_dict()


@app.get("/api/v1/chaos/experiments", tags=["chaos"])
def list_experiments(
    state: str | None = Query(None, description="Filter by experiment state"),
) -> dict[str, Any]:
    """List chaos experiments."""
    _bump("requests_total")
    exps = list(_experiments.values())
    if state:
        exps = [e for e in exps if e.state.value == state]
    return {"experiments": [e.to_dict() for e in exps], "count": len(exps)}


@app.get("/api/v1/chaos/experiments/{experiment_id}", tags=["chaos"])
def get_experiment(experiment_id: str) -> dict[str, Any]:
    """Get experiment details including fault impact score."""
    exp = _experiments.get(experiment_id)
    if exp is None:
        raise HTTPException(status_code=404, detail=f"Experiment '{experiment_id}' not found")
    _bump("requests_total")
    return exp.to_dict()


@app.post("/api/v1/chaos/experiments/{experiment_id}/start", tags=["chaos"])
def start_experiment(experiment_id: str) -> dict[str, Any]:
    """Start a chaos experiment."""
    exp = _experiments.get(experiment_id)
    if exp is None:
        raise HTTPException(status_code=404, detail=f"Experiment '{experiment_id}' not found")
    if exp.state != ExperimentState.PENDING:
        raise HTTPException(status_code=409, detail=f"Experiment is '{exp.state.value}', not pending")
    exp.start()
    _bump("requests_total")
    return exp.to_dict()


@app.post("/api/v1/chaos/experiments/{experiment_id}/inject", tags=["chaos"])
def inject_fault(experiment_id: str, body: FaultInjectRequest) -> dict[str, Any]:
    """Inject a fault into a running experiment."""
    exp = _experiments.get(experiment_id)
    if exp is None:
        raise HTTPException(status_code=404, detail=f"Experiment '{experiment_id}' not found")
    if exp.state != ExperimentState.RUNNING:
        raise HTTPException(status_code=409, detail=f"Experiment is '{exp.state.value}', not running")
    try:
        ft = FaultType(body.fault_type)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=f"Unknown fault type '{body.fault_type}'") from e
    fault = Fault(fault_type=ft, target=body.target, rate=body.rate, params=body.params)
    exp.inject_fault(fault, applied=body.applied, details=body.details or None)
    _bump("faults_injected_total")
    return {"experiment_id": experiment_id, "injection_count": len(exp.injection_events)}


# =========================================================================
# Incident endpoints
# =========================================================================


@app.get("/api/v1/incidents", tags=["incidents"])
def list_incidents(
    severity: str | None = Query(None, description="Filter by severity (p1-p4)"),
    state: str | None = Query(None, description="Filter by state"),
) -> dict[str, Any]:
    """List incidents with optional severity/state filters."""
    det = _get_incident_detector()
    _bump("requests_total")
    incidents: list[Incident] = list(det.all_incidents)
    if severity:
        incidents = [i for i in incidents if i.severity.value == severity]
    if state:
        incidents = [i for i in incidents if i.state.value == state]
    return {"incidents": [i.to_dict() for i in incidents], "count": len(incidents)}


@app.get("/api/v1/incidents/{incident_id}", tags=["incidents"])
def get_incident(incident_id: str) -> dict[str, Any]:
    """Get incident details."""
    det = _get_incident_detector()
    _bump("requests_total")
    for inc in det.all_incidents:
        if inc.incident_id == incident_id:
            return inc.to_dict()
    raise HTTPException(status_code=404, detail=f"Incident '{incident_id}' not found")


@app.post("/api/v1/incidents/{incident_id}/acknowledge", tags=["incidents"])
def acknowledge_incident(incident_id: str) -> dict[str, Any]:
    """Acknowledge an incident."""
    det = _get_incident_detector()
    for inc in det.all_incidents:
        if inc.incident_id == incident_id:
            if inc.state == IncidentState.RESOLVED:
                raise HTTPException(status_code=409, detail="Incident already resolved")
            inc.acknowledge()
            _bump("requests_total")
            return inc.to_dict()
    raise HTTPException(status_code=404, detail=f"Incident '{incident_id}' not found")


@app.post("/api/v1/incidents/{incident_id}/resolve", tags=["incidents"])
def resolve_incident(incident_id: str, body: IncidentResolveRequest | None = None) -> dict[str, Any]:
    """Resolve an incident."""
    det = _get_incident_detector()
    note = body.note if body else ""
    for inc in det.all_incidents:
        if inc.incident_id == incident_id:
            if inc.state == IncidentState.RESOLVED:
                raise HTTPException(status_code=409, detail="Incident already resolved")
            inc.resolve(note=note)
            _bump("requests_total")
            return inc.to_dict()
    raise HTTPException(status_code=404, detail=f"Incident '{incident_id}' not found")


@app.post("/api/v1/signals", tags=["incidents"], status_code=201)
def ingest_signal(body: SignalIngestRequest) -> dict[str, Any]:
    """Ingest a reliability signal."""
    det = _get_incident_detector()
    try:
        signal_type = SignalType(body.signal_type)
    except ValueError as e:
        raise HTTPException(
            status_code=400,
            detail=f"Unknown signal type '{body.signal_type}'. "
            f"Valid: {[t.value for t in SignalType]}",
        ) from e
    signal = Signal(
        signal_type=signal_type,
        source=body.source,
        value=body.value,
        threshold=body.threshold,
        message=body.message,
        metadata=body.metadata,
    )
    incident = det.ingest_signal(signal)
    _bump("signals_ingested_total")
    return {
        "signal": signal.to_dict(),
        "incident_created": incident is not None,
        "incident": incident.to_dict() if incident else None,
    }


# =========================================================================
# Delivery endpoints
# =========================================================================


@app.post("/api/v1/rollouts", tags=["delivery"], status_code=201)
def create_rollout(body: RolloutCreateRequest) -> dict[str, Any]:
    """Create a staged rollout."""
    steps = [
        RolloutStep(name=s.name, weight=s.weight, duration_seconds=s.duration_seconds, manual_gate=s.manual_gate)
        for s in body.steps
    ] or None
    conditions = [
        RollbackCondition(metric=r.metric, threshold=r.threshold, comparator=r.comparator)
        for r in body.rollback_conditions
    ] or None
    rollout = CanaryRollout(name=body.name, steps=steps, rollback_conditions=conditions)
    rollout.start()
    _rollouts[rollout.rollout_id] = rollout
    _bump("requests_total")
    return rollout.to_dict()


@app.get("/api/v1/rollouts", tags=["delivery"])
def list_rollouts(
    state: str | None = Query(None, description="Filter by rollout state"),
) -> dict[str, Any]:
    """List rollouts."""
    _bump("requests_total")
    rollouts = list(_rollouts.values())
    if state:
        rollouts = [r for r in rollouts if r.state.value == state]
    return {"rollouts": [r.to_dict() for r in rollouts], "count": len(rollouts)}


@app.get("/api/v1/rollouts/{rollout_id}", tags=["delivery"])
def get_rollout(rollout_id: str) -> dict[str, Any]:
    """Get rollout details and progress."""
    rollout = _rollouts.get(rollout_id)
    if rollout is None:
        raise HTTPException(status_code=404, detail=f"Rollout '{rollout_id}' not found")
    _bump("requests_total")
    return rollout.to_dict()


@app.post("/api/v1/rollouts/{rollout_id}/advance", tags=["delivery"])
def advance_rollout(rollout_id: str) -> dict[str, Any]:
    """Advance rollout to the next step."""
    rollout = _rollouts.get(rollout_id)
    if rollout is None:
        raise HTTPException(status_code=404, detail=f"Rollout '{rollout_id}' not found")
    if rollout.state not in (RolloutState.CANARY, RolloutState.SHADOW):
        raise HTTPException(status_code=409, detail=f"Rollout is '{rollout.state.value}', cannot advance")
    advanced = rollout.advance()
    _bump("requests_total")
    return {"advanced": advanced, **rollout.to_dict()}
