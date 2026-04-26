# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""FastAPI application for Agent OS governance API."""

from __future__ import annotations

import logging
import os
import time
from datetime import datetime, timezone
from typing import Any

from fastapi import FastAPI, HTTPException, Query, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

from agent_os.server.models import (
    DetectBatchRequest,
    DetectInjectionRequest,
    DetectionBatchResponse,
    DetectionResponse,
    ErrorResponse,
    ExecuteRequest,
    ExecuteResponse,
    HealthResponse,
    MetricsResponse,
)

logger = logging.getLogger(__name__)


def _detection_result_to_response(result: Any) -> DetectionResponse:
    """Convert a ``DetectionResult`` dataclass to a Pydantic response."""
    return DetectionResponse(
        is_injection=result.is_injection,
        threat_level=result.threat_level.value,
        injection_type=result.injection_type.value if result.injection_type else None,
        confidence=result.confidence,
        matched_patterns=list(result.matched_patterns),
        explanation=result.explanation,
    )


class GovServer:
    """High-level wrapper that owns the FastAPI app and its dependencies."""

    def __init__(
        self,
        *,
        title: str = "Agent OS Governance API",
        version: str | None = None,
    ) -> None:
        from agent_os import __version__
        from agent_os.health import HealthChecker
        from agent_os.metrics import GovernanceMetrics
        from agent_os.prompt_injection import DetectionConfig, PromptInjectionDetector

        self._version = version or __version__
        self._detector = PromptInjectionDetector(DetectionConfig(sensitivity="balanced"))
        self._metrics = GovernanceMetrics()
        self._health_checker = HealthChecker(version=self._version)
        self._app = create_app(self, title=title)

    @property
    def app(self) -> FastAPI:
        return self._app

    @property
    def detector(self) -> Any:
        return self._detector

    @property
    def metrics(self) -> Any:
        return self._metrics

    @property
    def health_checker(self) -> Any:
        return self._health_checker


def create_app(
    server: GovServer | None = None,
    *,
    title: str = "Agent OS Governance API",
) -> FastAPI:
    """Build and return the FastAPI application with all routes."""
    from agent_os import __version__

    version = server._version if server else __version__

    app = FastAPI(
        title=title,
        version=version,
        description="REST API for Agent OS governance operations.",
    )

    # -- CORS middleware ----------------------------------------------------
    app.add_middleware(
        CORSMiddleware,
        allow_origins=os.environ.get("CORS_ALLOWED_ORIGINS", "http://localhost:3000,http://localhost:8080").split(","),
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )

    # -- request timing middleware -----------------------------------------
    @app.middleware("http")
    async def _timing_middleware(request: Request, call_next: Any) -> Any:
        start = time.perf_counter()
        response = await call_next(request)
        elapsed_ms = (time.perf_counter() - start) * 1000.0
        response.headers["X-Response-Time"] = f"{elapsed_ms:.2f}ms"
        return response

    # -- exception handler -------------------------------------------------
    @app.exception_handler(Exception)
    async def _global_exception_handler(request: Request, exc: Exception) -> JSONResponse:
        logger.exception("Unhandled exception: %s", exc)
        return JSONResponse(
            status_code=500,
            content=ErrorResponse(
                detail=str(exc),
                error_code="INTERNAL_ERROR",
            ).model_dump(),
        )

    # ======================================================================
    # Routes
    # ======================================================================

    @app.get("/")
    async def root() -> dict:
        """Root info endpoint."""
        return {
            "name": "Agent OS Governance API",
            "version": version,
            "docs": "/docs",
        }

    # -- health / readiness ------------------------------------------------

    @app.get("/health", response_model=HealthResponse)
    async def health() -> HealthResponse:
        """Health check endpoint."""
        if server:
            report = server.health_checker.check_health()
            return HealthResponse(
                status=report.status.value,
                components={
                    name: {
                        "status": comp.status.value,
                        "message": comp.message,
                    }
                    for name, comp in report.components.items()
                },
                timestamp=report.timestamp,
            )
        return HealthResponse(
            status="healthy",
            components={},
            timestamp=datetime.now(timezone.utc).isoformat() + "Z",
        )

    @app.get("/ready")
    async def ready() -> dict:
        """Readiness probe."""
        if server:
            report = server.health_checker.check_ready()
            if not report.is_ready():
                raise HTTPException(status_code=503, detail="Not ready")
        return {"ready": True}

    # -- metrics -----------------------------------------------------------

    @app.get("/api/v1/metrics", response_model=MetricsResponse)
    async def get_metrics() -> MetricsResponse:
        """Return governance metrics snapshot."""
        if server:
            snap = server.metrics.snapshot()
            return MetricsResponse(
                total_checks=snap["total_checks"],
                violations=snap["violations"],
                approvals=snap["approvals"],
                blocked=snap["blocked"],
                avg_latency_ms=snap["avg_latency_ms"],
            )
        return MetricsResponse()

    # -- prompt injection detection ----------------------------------------

    @app.post("/api/v1/detect/injection", response_model=DetectionResponse)
    async def detect_injection(req: DetectInjectionRequest) -> DetectionResponse:
        """Scan a single text for prompt injection."""
        from agent_os.prompt_injection import DetectionConfig, PromptInjectionDetector

        if server and req.sensitivity == server.detector._config.sensitivity:
            detector = server.detector
        else:
            detector = PromptInjectionDetector(
                DetectionConfig(sensitivity=req.sensitivity)
            )

        result = detector.detect(req.text, req.source, req.canary_tokens)
        return _detection_result_to_response(result)

    @app.post("/api/v1/detect/injection/batch", response_model=DetectionBatchResponse)
    async def detect_injection_batch(req: DetectBatchRequest) -> DetectionBatchResponse:
        """Scan multiple texts for prompt injection."""
        from agent_os.prompt_injection import DetectionConfig, PromptInjectionDetector

        if server and req.sensitivity == server.detector._config.sensitivity:
            detector = server.detector
        else:
            detector = PromptInjectionDetector(
                DetectionConfig(sensitivity=req.sensitivity)
            )

        inputs = [(item.get("text", ""), item.get("source", "api")) for item in req.inputs]
        results = detector.detect_batch(inputs, req.canary_tokens)
        responses = [_detection_result_to_response(r) for r in results]
        injections = sum(1 for r in responses if r.is_injection)

        return DetectionBatchResponse(
            results=responses,
            total=len(responses),
            injections_found=injections,
        )

    # -- execute -----------------------------------------------------------

    @app.post("/api/v1/execute", response_model=ExecuteResponse)
    async def execute(req: ExecuteRequest) -> ExecuteResponse:
        """Execute an action through the stateless kernel."""
        from agent_os.stateless import ExecutionContext, StatelessKernel

        kernel = StatelessKernel()
        ctx = ExecutionContext(
            agent_id=req.agent_id,
            policies=req.policies,
        )
        try:
            result = await kernel.execute(req.action, req.params, ctx)
            return ExecuteResponse(
                success=result.success,
                data=result.data,
                error=result.error,
                signal=result.signal,
            )
        except Exception as exc:
            return ExecuteResponse(
                success=False,
                error=str(exc),
                signal="SIGTERM",
            )

    # -- audit -------------------------------------------------------------

    @app.get("/api/v1/audit/injections")
    async def audit_injections(limit: int = Query(default=50, ge=1, le=1000)) -> dict:
        """Return recent injection audit log entries."""
        records: list[dict] = []
        if server:
            for rec in server.detector.audit_log[-limit:]:
                records.append({
                    "timestamp": rec.timestamp.isoformat(),
                    "input_hash": rec.input_hash,
                    "source": rec.source,
                    "is_injection": rec.result.is_injection,
                    "threat_level": rec.result.threat_level.value,
                    "injection_type": (
                        rec.result.injection_type.value if rec.result.injection_type else None
                    ),
                    "explanation": rec.result.explanation,
                })
        return {"records": records, "total": len(records)}

    return app
