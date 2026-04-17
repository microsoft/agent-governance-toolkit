# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""
AgentMesh Component Servers

FastAPI-based HTTP servers for the four AgentMesh components:
- trust-engine: Agent identity verification and trust token issuance
- policy-server: Governance policy evaluation
- audit-collector: Append-only audit log with Merkle integrity
- api-gateway: Reverse proxy with rate limiting
"""

from __future__ import annotations

import os
import time
from typing import Any

from fastapi import FastAPI
from fastapi.responses import JSONResponse

COMPONENT = os.getenv("AGENTMESH_COMPONENT", "unknown")
VERSION = "0.3.0"
_start_time: float = 0.0


def create_base_app(component: str, description: str) -> FastAPI:
    """Create a FastAPI app with standard health/metrics endpoints."""
    global _start_time
    _start_time = time.monotonic()

    app = FastAPI(
        title=f"AgentMesh {component}",
        description=description,
        version=VERSION,
        docs_url="/docs",
        redoc_url=None,
    )

    @app.get("/healthz", tags=["health"])
    async def healthz() -> dict[str, str]:
        return {"status": "ok", "component": component}

    @app.get("/readyz", tags=["health"])
    async def readyz() -> dict[str, str]:
        return {"status": "ready", "component": component}

    @app.get("/metrics", tags=["observability"])
    async def metrics() -> dict[str, Any]:
        uptime = time.monotonic() - _start_time
        return {
            "component": component,
            "version": VERSION,
            "uptime_seconds": round(uptime, 2),
        }

    return app


def run_server(app: FastAPI, default_port: int) -> None:
    """Run uvicorn with env-configurable host/port."""
    import uvicorn

    host = os.getenv("HOST", "0.0.0.0")
    port = int(os.getenv("PORT", str(default_port)))
    log_level = os.getenv("LOG_LEVEL", "info").lower()
    uvicorn.run(app, host=host, port=port, log_level=log_level)
