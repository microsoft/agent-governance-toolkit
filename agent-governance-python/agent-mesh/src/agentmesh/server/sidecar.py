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

import logging
import os
import time
from pathlib import Path
from typing import Any

from agentmesh.governance.policy import PolicyEngine as _PolicyEngine
from fastapi import FastAPI, HTTPException
from fastapi.responses import PlainTextResponse
from pydantic import BaseModel, Field

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

    @app.get("/ready", tags=["health"])
    async def ready() -> dict[str, Any]:
        """Readiness probe. Reports loaded policy count."""
        return {
            "status": "ready",
            "component": "governance-sidecar",
            "policies_loaded": _loaded_count,
        }

    @app.get("/healthz", tags=["health"])
    async def healthz() -> dict[str, str]:
        """Kubernetes-style liveness probe."""
        return {"status": "ok", "component": "governance-sidecar"}

    @app.get("/readyz", tags=["health"])
    async def readyz() -> dict[str, str]:
        """Kubernetes-style readiness probe."""
        return {"status": "ready", "component": "governance-sidecar"}

    # ── Metrics endpoint ─────────────────────────────────────────────

    @app.get("/metrics", tags=["observability"])
    async def metrics_endpoint() -> PlainTextResponse:
        """Prometheus exposition format metrics."""
        try:
            from prometheus_client import generate_latest, REGISTRY

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
        result: PolicyDecision = _engine.evaluate(agent_did=req.agent_did, context=ctx)
        return EvaluateResponse(
            decision=result.action,
            matched_rule=result.matched_rule,
            reason=result.reason,
            policy_name=result.policy_name,
        )

    @app.get("/api/v1/policies", tags=["policy"])
    async def list_policies() -> dict[str, Any]:
        """List loaded policies."""
        return {
            "total_loaded": _loaded_count,
            "skipped": _skipped_count,
            "policy_dir": _policy_dir,
            "version": VERSION,
        }

    @app.post("/api/v1/policy/reload", tags=["policy"])
    async def reload_policies() -> dict[str, Any]:
        """Hot-reload policies from disk.

        A strict-mode load failure keeps the previously loaded policy set (see
        ``_load_policies``); this returns 409 rather than a bare 500 so the
        caller can tell the reload was rejected and the prior policies serve.
        """
        try:
            _load_policies()
        except RuntimeError as exc:
            logger.error("Policy reload rejected, keeping previous set: %s", exc)
            raise HTTPException(
                status_code=409,
                detail=f"Policy reload rejected; previous policy set retained. {exc}",
            ) from exc
        return {"status": "reloaded", "total_loaded": _loaded_count}

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


# ── Internal state ───────────────────────────────────────────────────

_policy_dir = os.getenv("AGT_POLICY_DIR", "/etc/agt/policies")
_loaded_count = 0
_skipped_count = 0

# Initialize engine eagerly so tests work without startup event
_engine = _PolicyEngine()


def _policy_strict() -> bool:
    """Whether the directory loader fails closed on an unloadable policy file.

    Defaults to on (issue #3538): a policy file that fails to load must not be
    silently dropped, or a deny policy could vanish while a broader allow keeps
    serving. Set ``AGT_POLICY_STRICT`` to ``0``/``false``/``no``/``off`` for
    best-effort loading instead. Any other value, including blank or
    unrecognised, stays strict so a misconfigured toggle fails closed.
    """
    return os.getenv("AGT_POLICY_STRICT", "1").strip().lower() not in {
        "0",
        "false",
        "no",
        "off",
    }


def _on_load_failure(name: str, exc: Exception, strict: bool) -> None:
    """Fail closed (raise) or, in non-strict mode, log at error level."""
    if strict:
        raise RuntimeError(
            f"Policy file {name!r} failed to load: {exc}. Refusing to start with a "
            f"policy silently dropped; set AGT_POLICY_STRICT=0 for best-effort "
            f"loading (issue #3538)."
        ) from exc
    logger.error("Skipped %s: %s", name, exc)


def _load_policies() -> None:
    """Load policies from AGT_POLICY_DIR.

    Fails closed by default: if any policy file present in the directory cannot
    be loaded, the loader raises rather than silently dropping it (issue #3538),
    so the server never serves decisions with a deny policy quietly missing. Set
    ``AGT_POLICY_STRICT=0`` for best-effort loading, which logs each unloadable
    file at error level and records a skipped count exposed via
    ``/api/v1/policies``.
    """
    global _engine, _loaded_count, _skipped_count, _policy_dir

    from agentmesh.governance.policy import PolicyEngine

    _policy_dir = os.getenv("AGT_POLICY_DIR", "/etc/agt/policies")
    strict = _policy_strict()

    policy_path = Path(_policy_dir)
    if not policy_path.exists():
        logger.warning("Policy directory %s does not exist", _policy_dir)
        _engine = PolicyEngine()
        _loaded_count = 0
        _skipped_count = 0
        return

    # Build into a local engine and commit only once every file has loaded, so a
    # strict-mode failure leaves the previously loaded policy set intact instead
    # of swapping in a partially loaded (weaker) one on reload (issue #3538).
    engine = PolicyEngine()
    count = 0
    skipped = 0
    for f in sorted(policy_path.glob("*.yaml")):
        try:
            engine.load_yaml(f.read_text())
            count += 1
            logger.info("Loaded policy: %s", f.name)
        except Exception as exc:
            skipped += 1
            _on_load_failure(f.name, exc, strict)

    for f in sorted(policy_path.glob("*.json")):
        try:
            engine.load_json(f.read_text())
            count += 1
        except Exception as exc:
            skipped += 1
            _on_load_failure(f.name, exc, strict)

    _engine = engine
    _loaded_count = count
    _skipped_count = skipped
    logger.info("Loaded %d policies from %s", count, _policy_dir)


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
