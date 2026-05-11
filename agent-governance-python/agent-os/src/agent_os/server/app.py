# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""FastAPI application for Agent OS governance API."""

from __future__ import annotations

import logging
import os
import re
import time
from datetime import datetime, timedelta, timezone
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


def _parse_cors_origins(raw: str) -> list[str]:
    """Parse, validate, and return CORS origins.

    Rejects ``*`` when credentials are enabled, and validates that each
    origin has a scheme and a non-empty hostname.
    """
    origins: list[str] = []
    for origin in raw.split(","):
        origin = origin.strip()
        if not origin:
            continue
        if origin == "*":
            logger.warning(
                "CORS origin '*' is not allowed with allow_credentials=True — skipping"
            )
            continue
        from urllib.parse import urlparse
        parsed = urlparse(origin)
        if not parsed.scheme or not parsed.hostname:
            logger.warning("Invalid CORS origin (missing scheme or host): %s — skipping", origin)
            continue
        origins.append(origin)
    if not origins:
        logger.warning("No valid CORS origins configured — falling back to localhost defaults")
        origins = ["http://localhost:3000", "http://localhost:8080"]
    return origins

_EXECUTE_TOKENS_ENV = "AGENT_OS_EXECUTION_TOKENS"
_EXECUTE_TOKENS_TTL_ENV = "AGENT_OS_EXECUTION_TOKEN_TTL_HOURS"
_DEFAULT_EXECUTE_TOKEN_TTL_HOURS = 24
_ALLOW_UNAUTHENTICATED_EXECUTE_ENV = "AGENT_OS_ALLOW_UNAUTHENTICATED_EXECUTE"


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
        execute_authenticator: Any | None = None,
        allow_unauthenticated_execute: bool | None = None,
    ) -> None:
        from agent_os import __version__
        from agent_os.health import HealthChecker
        from agent_os.mcp_session_auth import MCPSessionAuthenticator
        from agent_os.metrics import GovernanceMetrics
        from agent_os.prompt_injection import DetectionConfig, PromptInjectionDetector

        self._version = version or __version__
        self._detector = PromptInjectionDetector(DetectionConfig(sensitivity="balanced"))
        self._metrics = GovernanceMetrics()
        self._health_checker = HealthChecker(version=self._version)
        self._execute_authenticator: MCPSessionAuthenticator | None = (
            execute_authenticator or _build_execute_authenticator_from_env()
        )
        self._allow_unauthenticated_execute = (
            _read_bool_env(_ALLOW_UNAUTHENTICATED_EXECUTE_ENV, default=False)
            if allow_unauthenticated_execute is None
            else allow_unauthenticated_execute
        )
        if not self._allow_unauthenticated_execute and self._execute_authenticator is None:
            logger.warning(
                "Execute authentication is enabled but no bearer tokens are configured. "
                "/api/v1/execute will return 503 until %s or execute_authenticator is set.",
                _EXECUTE_TOKENS_ENV,
            )
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

    @property
    def execute_authenticator(self) -> Any:
        return self._execute_authenticator

    @property
    def allow_unauthenticated_execute(self) -> bool:
        return self._allow_unauthenticated_execute


def _read_bool_env(name: str, *, default: bool) -> bool:
    raw_value = os.environ.get(name)
    if raw_value is None:
        return default
    return raw_value.strip().lower() in {"1", "true", "yes", "on"}


def _parse_execute_tokens(raw_tokens: str) -> dict[str, str]:
    tokens: dict[str, str] = {}
    seen_tokens: set[str] = set()
    for item in re.split(r"[,\n;]+", raw_tokens):
        entry = item.strip()
        if not entry:
            continue
        agent_id, separator, token = entry.partition("=")
        if separator == "" or not agent_id.strip() or not token.strip():
            raise ValueError(
                f"Invalid {_EXECUTE_TOKENS_ENV} entry '{entry}'. Use 'agent-id=token'."
            )
        normalized_agent_id = agent_id.strip()
        normalized_token = token.strip()
        if normalized_agent_id in tokens:
            raise ValueError(f"Duplicate execute token mapping for agent '{normalized_agent_id}'.")
        if normalized_token in seen_tokens:
            raise ValueError("Execute bearer tokens must be unique per agent.")
        tokens[normalized_agent_id] = normalized_token
        seen_tokens.add(normalized_token)
    return tokens


def _read_bootstrap_ttl_from_env() -> timedelta:
    raw = os.environ.get(_EXECUTE_TOKENS_TTL_ENV, "").strip()
    if not raw:
        return timedelta(hours=_DEFAULT_EXECUTE_TOKEN_TTL_HOURS)
    try:
        hours = float(raw)
    except ValueError as exc:
        raise ValueError(
            f"Invalid {_EXECUTE_TOKENS_TTL_ENV}={raw!r}: must be a positive number of hours."
        ) from exc
    if hours <= 0:
        raise ValueError(
            f"Invalid {_EXECUTE_TOKENS_TTL_ENV}={raw!r}: must be strictly positive."
        )
    return timedelta(hours=hours)


def _build_execute_authenticator_from_env() -> Any | None:
    from agent_os.mcp_session_auth import MCPSessionAuthenticator

    raw_tokens = os.environ.get(_EXECUTE_TOKENS_ENV, "").strip()
    if not raw_tokens:
        return None

    ttl = _read_bootstrap_ttl_from_env()
    authenticator = MCPSessionAuthenticator()
    for agent_id, token in _parse_execute_tokens(raw_tokens).items():
        authenticator.bootstrap_session(agent_id, token, ttl=ttl)
    return authenticator


def _extract_bearer_token(request: Request) -> str:
    authorization = request.headers.get("Authorization", "")
    scheme, _, token = authorization.partition(" ")
    if scheme.lower() != "bearer" or not token.strip():
        raise HTTPException(
            status_code=401,
            detail="Missing or invalid Authorization header. Use 'Bearer <session-token>'.",
        )
    return token.strip()


def _authenticate_execute_request(
    request: Request,
    *,
    execute_authenticator: Any | None,
    allow_unauthenticated_execute: bool,
) -> Any | None:
    if allow_unauthenticated_execute:
        return None
    if execute_authenticator is None:
        raise HTTPException(
            status_code=503,
            detail=(
                "Execute authentication is not configured. Set AGENT_OS_EXECUTION_TOKENS or "
                "provide GovServer(execute_authenticator=...)."
            ),
        )

    session = execute_authenticator.validate_token(_extract_bearer_token(request))
    if session is None:
        raise HTTPException(status_code=401, detail="Invalid or expired execute bearer token.")
    return session


def create_app(
    server: GovServer | None = None,
    *,
    title: str = "Agent OS Governance API",
) -> FastAPI:
    """Build and return the FastAPI application with all routes."""
    from agent_os import __version__

    version = server._version if server else __version__
    execute_authenticator = server.execute_authenticator if server else _build_execute_authenticator_from_env()
    allow_unauthenticated_execute = (
        server.allow_unauthenticated_execute
        if server
        else _read_bool_env(_ALLOW_UNAUTHENTICATED_EXECUTE_ENV, default=False)
    )

    app = FastAPI(
        title=title,
        version=version,
        description="REST API for Agent OS governance operations.",
    )

    # -- CORS middleware ----------------------------------------------------
    app.add_middleware(
        CORSMiddleware,
        allow_origins=_parse_cors_origins(os.environ.get("CORS_ALLOWED_ORIGINS", "http://localhost:3000,http://localhost:8080")),
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
                detail="An internal error occurred",
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
    async def execute(req: ExecuteRequest, request: Request) -> ExecuteResponse:
        """Execute an action through the stateless kernel."""
        from agent_os.stateless import ExecutionContext, StatelessKernel

        authenticated_session = _authenticate_execute_request(
            request,
            execute_authenticator=execute_authenticator,
            allow_unauthenticated_execute=allow_unauthenticated_execute,
        )
        if authenticated_session is not None:
            if req.agent_id and req.agent_id != authenticated_session.agent_id:
                raise HTTPException(
                    status_code=403,
                    detail=(
                        "Request agent_id does not match the identity bound to the "
                        "execute bearer token."
                    ),
                )
            effective_agent_id = authenticated_session.agent_id
        else:
            if not req.agent_id:
                raise HTTPException(
                    status_code=422,
                    detail="agent_id is required when unauthenticated execute mode is enabled.",
                )
            effective_agent_id = req.agent_id

        kernel = StatelessKernel()
        ctx = ExecutionContext(
            agent_id=effective_agent_id,
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
