# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""
Governance Sidecar — unified FastAPI application.

Composes the policy server, trust engine, and metrics into a single
application for sidecar deployment alongside agent containers.

Environment variables:
    AGT_POLICY_DIR: Path to policy YAML files (default: /etc/agt/policies)
    AGT_LOG_LEVEL: Logging level (default: info)
    AGT_PORT: Server port (default: 8081)
    AGT_HOST: Server bind address (default: 0.0.0.0)
    AGT_SERVICE_NAME: OTEL service name (default: agt-sidecar)
"""

from __future__ import annotations

import hashlib
import json
import logging
import os
import time
from pathlib import Path
from typing import Any, Literal

from fastapi import FastAPI
from fastapi.responses import JSONResponse, PlainTextResponse
from pydantic import BaseModel, ConfigDict, Field

from agentmesh.governance.policy import PolicyEngine as _PolicyEngine

logger = logging.getLogger(__name__)

VERSION = "0.3.0"
_start_time: float = 0.0


def create_sidecar_app() -> FastAPI:
    """Create the governance sidecar FastAPI application."""
    global _start_time
    _start_time = time.monotonic()

    app = FastAPI(
        title="AGT Governance Sidecar",
        description=(
            "Policy enforcement, trust verification, and observability sidecar "
            "for AI agent containers."
        ),
        version=VERSION,
        docs_url="/docs",
        redoc_url=None,
    )

    # ── Health probes ────────────────────────────────────────────────

    @app.get("/health", tags=["health"])
    async def health() -> dict[str, str]:
        """Liveness probe."""
        return {"status": "ok", "component": "governance-sidecar"}

    def _readiness_response() -> JSONResponse:
        generation = _policy_state[1]
        payload: dict[str, Any] = {
            "status": "ready" if generation.effective_rules > 0 else "not-ready",
            "component": "governance-sidecar",
            **generation.model_dump(exclude={"files"}),
        }
        status_code = 200 if generation.effective_rules > 0 else 503
        return JSONResponse(status_code=status_code, content=payload)

    @app.get("/ready", tags=["health"], response_model=None)
    async def ready() -> JSONResponse:
        """Readiness probe. Reports loaded policy count."""
        return _readiness_response()

    @app.get("/healthz", tags=["health"])
    async def healthz() -> dict[str, str]:
        """Kubernetes-style liveness probe."""
        return {"status": "ok", "component": "governance-sidecar"}

    @app.get("/readyz", tags=["health"], response_model=None)
    async def readyz() -> JSONResponse:
        """Kubernetes-style readiness probe."""
        return _readiness_response()

    # ── Metrics endpoint ─────────────────────────────────────────────

    @app.get("/metrics", tags=["observability"])
    async def metrics_endpoint() -> PlainTextResponse:
        """Prometheus exposition format metrics."""
        try:
            from prometheus_client import REGISTRY, generate_latest

            output = generate_latest(REGISTRY).decode("utf-8")
            uptime = time.monotonic() - _start_time
            output += (
                f"# HELP agt_sidecar_uptime_seconds Sidecar uptime in seconds\n"
                f"# TYPE agt_sidecar_uptime_seconds gauge\n"
                f"agt_sidecar_uptime_seconds {uptime:.2f}\n"
            )
            return PlainTextResponse(
                content=output,
                media_type="text/plain; version=0.0.4; charset=utf-8",
            )
        except ImportError:
            uptime = time.monotonic() - _start_time
            return PlainTextResponse(
                content=(
                    f"# HELP agt_sidecar_uptime_seconds Sidecar uptime\n"
                    f"# TYPE agt_sidecar_uptime_seconds gauge\n"
                    f"agt_sidecar_uptime_seconds {uptime:.2f}\n"
                ),
                media_type="text/plain; version=0.0.4; charset=utf-8",
            )

    # ── Policy evaluation ────────────────────────────────────────────

    @app.on_event("startup")
    async def startup() -> None:
        _load_policies()
        _bootstrap_telemetry()

    @app.post("/api/v1/policy/evaluate", tags=["policy"])
    async def evaluate_policy(req: EvaluateRequest) -> EvaluateResponse:
        """Evaluate governance policies against an agent action."""
        from agentmesh.governance.policy import PolicyDecision

        ctx = {
            "action": req.action,
            "resource": req.resource,
            **req.context,
        }
        engine, generation = _policy_state

        # Fail-closed (#3536): if any policy file failed to load, or the policy
        # directory is unavailable, deny all actions so a broken deny policy is
        # not silently bypassed by an empty or partial policy set.
        if generation.policies_failed > 0 or generation.directory_status != "available":
            reason = (
                f"Policy set degraded: {generation.policies_failed} file(s) failed to load"
                if generation.policies_failed > 0
                else "Policy set degraded: policy directory is unavailable"
            )
            return EvaluateResponse(
                decision="deny",
                matched_rule=None,
                reason=reason,
                policy_name=None,
                policy_set_id=generation.policy_set_id,
                policy_set_status=generation.policy_set_status,
            )

        result: PolicyDecision = engine.evaluate(agent_did=req.agent_did, context=ctx)
        return EvaluateResponse(
            decision=result.action,
            matched_rule=result.matched_rule,
            reason=result.reason,
            policy_name=result.policy_name,
            policy_set_id=generation.policy_set_id,
            policy_set_status=generation.policy_set_status,
        )

    @app.get("/api/v1/policies", tags=["policy"])
    async def list_policies() -> dict[str, Any]:
        """List loaded policies."""
        generation = _policy_state[1]
        return {
            "total_loaded": generation.policies_loaded,
            "policy_dir": _policy_dir,
            "version": VERSION,
            **generation.model_dump(),
        }

    @app.post("/api/v1/policy/reload", tags=["policy"])
    async def reload_policies() -> dict[str, Any]:
        """Hot-reload policies from disk."""
        generation = _load_policies()
        return {
            "status": "reloaded",
            "total_loaded": generation.policies_loaded,
            **generation.model_dump(exclude={"files"}),
        }

    return app


# ── Request / Response models ────────────────────────────────────────


class EvaluateRequest(BaseModel):
    agent_did: str = Field(..., description="DID of the acting agent")
    action: str = Field(..., description="Action being performed")
    resource: str | None = Field(None, description="Target resource")
    context: dict[str, Any] = Field(default_factory=dict, description="Additional context")


class EvaluateResponse(BaseModel):
    decision: str = Field(..., description="allow, deny, warn, or require_approval")
    matched_rule: str | None = None
    reason: str = ""
    policy_name: str | None = None
    policy_set_id: str
    policy_set_status: Literal["complete", "degraded", "rejected", "not_loaded"]


class PolicyFileLoad(BaseModel):
    """One discovered file, without raw policy content or exception messages."""

    model_config = ConfigDict(frozen=True)
    name: str
    content_sha256: str | None
    status: Literal["loaded", "failed"]
    error_type: str | None = None


class PolicyLoadGeneration(BaseModel):
    """Immutable manifest of a completed load."""

    model_config = ConfigDict(frozen=True)
    policy_set_id: str
    policy_set_status: Literal["complete", "degraded", "rejected", "not_loaded"]
    policies_discovered: int
    policies_loaded: int
    effective_rules: int = 0
    policies_failed: int
    directory_status: Literal["available", "unavailable", "not_loaded"]
    files: tuple[PolicyFileLoad, ...]
    load_warnings: tuple[str, ...] = ()


# ── Internal state ───────────────────────────────────────────────────

_policy_dir = os.getenv("AGT_POLICY_DIR", "/etc/agt/policies")
_policy_state = (
    _PolicyEngine(),
    PolicyLoadGeneration(
        policy_set_id="sha256:" + hashlib.sha256(b"not_loaded").hexdigest(),
        policy_set_status="not_loaded",
        policies_discovered=0,
        policies_loaded=0,
        effective_rules=0,
        policies_failed=0,
        directory_status="not_loaded",
        files=(),
    ),
)


def _load_policies() -> PolicyLoadGeneration:
    """Build then publish an engine and its content-addressed load manifest together."""
    global _policy_state, _policy_dir

    from agentmesh.governance.policy import PolicyEngine

    _policy_dir = os.getenv("AGT_POLICY_DIR", "/etc/agt/policies")
    engine = PolicyEngine()
    loaded_policies: dict[str, Any] = {}

    policy_path = Path(_policy_dir)
    files = []
    directory_status: Literal["available", "unavailable"] = "available"
    try:
        # iterdir surfaces discovery errors instead of silently claiming an empty load.
        discovered = list(policy_path.iterdir())
    except OSError:
        discovered = []
        directory_status = "unavailable"
        logger.warning("Policy directory is unavailable")

    # Preserve YAML-before-JSON precedence for duplicate policy names.
    for suffix, loader in ((".yaml", engine.load_yaml), (".json", engine.load_json)):
        for f in sorted(p for p in discovered if p.suffix == suffix):
            digest = None
            error_type = None
            try:
                content = f.read_bytes()
                digest = hashlib.sha256(content).hexdigest()
                policy = loader(content.decode("utf-8"))
                loaded_policies[policy.name] = policy
            except Exception as exc:
                error_type = type(exc).__name__
                logger.warning("Skipped policy %r: %s", f.name, error_type)
            files.append(
                PolicyFileLoad(
                    name=f.name.encode("unicode_escape").decode("ascii"),
                    content_sha256=digest,
                    status="failed" if error_type else "loaded",
                    error_type=error_type,
                )
            )

    manifest = {
        "directory_status": directory_status,
        "files": [entry.model_dump() for entry in files],
    }
    canonical = json.dumps(manifest, sort_keys=True, separators=(",", ":"))
    failed = sum(entry.status == "failed" for entry in files)
    effective_rules = sum(
        sum(rule.enabled for rule in policy.rules)
        for policy in loaded_policies.values()
    )

    # Fail-closed (#3536 review): when files fail, publish the generation
    # as 'degraded' so evaluate_policy can deny based on policies_failed.
    # Do NOT raise or use 'rejected' -- #3909's generation model and its
    # existing tests expect 'degraded' for file-level parse failures.
    if failed:
        failed_names = [e.name for e in files if e.status == "failed"]
        logger.error(
            "Policy load generation degraded: %d file(s) failed: %s",
            failed,
            ", ".join(failed_names),
        )

    policy_set_status = "complete"
    if failed or directory_status == "unavailable":
        policy_set_status = "degraded"

    load_warnings: tuple[str, ...] = ()
    if effective_rules == 0:
        warning = (
            f"Policy load validation: no effective rules loaded from {_policy_dir}; "
            "readiness remains blocked until an enabled policy rule is loaded."
        )
        logger.warning(warning)
        load_warnings = (warning,)

    generation = PolicyLoadGeneration(
        policy_set_id="sha256:" + hashlib.sha256(canonical.encode("utf-8")).hexdigest(),
        policy_set_status=policy_set_status,
        policies_discovered=len(files),
        policies_loaded=len(files) - failed,
        effective_rules=effective_rules,
        policies_failed=failed,
        directory_status=directory_status,
        files=tuple(files),
        load_warnings=load_warnings,
    )
    serialized = generation.model_dump_json()
    _policy_state = (engine, generation)
    # ponytail: retain historical manifests through deployment logs, not an unbounded cache.
    logger.info("Policy load generation: %s", serialized)
    return generation


def _bootstrap_telemetry() -> None:
    """Bootstrap OTEL if configured."""
    try:
        from agentmesh.telemetry import bootstrap_otel

        service_name = os.getenv("AGT_SERVICE_NAME", "agt-sidecar")
        bootstrap_otel(service_name=service_name)
    except ImportError:
        pass


# ── Application instance ─────────────────────────────────────────────

app = create_sidecar_app()


def main() -> None:
    """Run the governance sidecar server."""
    import uvicorn

    host = os.getenv("AGT_HOST", "0.0.0.0")  # noqa: S104 — intentional bind-all for container
    port = int(os.getenv("AGT_PORT", "8081"))
    log_level = os.getenv("AGT_LOG_LEVEL", "info").lower()

    logging.basicConfig(level=getattr(logging, log_level.upper(), logging.INFO))
    logger.info("Starting AGT Governance Sidecar on %s:%d", host, port)

    uvicorn.run(app, host=host, port=port, log_level=log_level)


if __name__ == "__main__":
    main()
