# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""
API Gateway Server

External entry point for agent traffic. Routes requests to trust-engine,
policy-server, and audit-collector with rate limiting and DID extraction.
"""

from __future__ import annotations

import logging
import os
from typing import Any

import httpx
from fastapi import HTTPException, Request, Response
from pydantic import BaseModel, Field

from agentmesh.services.rate_limiter import RateLimiter
from agentmesh.server import create_base_app, run_server

logger = logging.getLogger(__name__)

app = create_base_app(
    "api-gateway",
    "External entry point for agent traffic with rate limiting.",
)

# Upstream URLs — set via environment or Helm chart
TRUST_ENGINE_URL = os.getenv("AGENTMESH_TRUST_ENGINE_URL", "http://localhost:8443")
POLICY_SERVER_URL = os.getenv("AGENTMESH_POLICY_SERVER_URL", "http://localhost:8444")
AUDIT_COLLECTOR_URL = os.getenv("AGENTMESH_AUDIT_COLLECTOR_URL", "http://localhost:8445")
RATE_LIMIT_PER_MIN = int(os.getenv("AGENTMESH_RATE_LIMIT_PER_MIN", "1000"))

# Rate limiter (per agent DID)
_rate_limiter = RateLimiter(
    global_rate=RATE_LIMIT_PER_MIN / 60.0,
    global_capacity=RATE_LIMIT_PER_MIN,
)

# Shared HTTP client
_client: httpx.AsyncClient | None = None

# Route mapping: path prefix → upstream base URL
_ROUTE_MAP = {
    "/api/v1/handshake": TRUST_ENGINE_URL,
    "/api/v1/agents": TRUST_ENGINE_URL,
    "/api/v1/capabilities": TRUST_ENGINE_URL,
    "/api/v1/policy": POLICY_SERVER_URL,
    "/api/v1/policies": POLICY_SERVER_URL,
    "/api/v1/audit": AUDIT_COLLECTOR_URL,
}


@app.on_event("startup")
async def startup() -> None:
    global _client
    _client = httpx.AsyncClient(timeout=30.0, follow_redirects=True)
    logger.info(
        "API Gateway started — trust=%s policy=%s audit=%s rateLimit=%d/min",
        TRUST_ENGINE_URL,
        POLICY_SERVER_URL,
        AUDIT_COLLECTOR_URL,
        RATE_LIMIT_PER_MIN,
    )


@app.on_event("shutdown")
async def shutdown() -> None:
    if _client:
        await _client.aclose()


def _resolve_upstream(path: str) -> str | None:
    """Find the upstream URL for a given request path."""
    for prefix, url in _ROUTE_MAP.items():
        if path.startswith(prefix):
            return url
    return None


def _extract_agent_did(request: Request) -> str:
    """Extract agent DID from the X-Agent-DID header."""
    return request.headers.get("X-Agent-DID", "anonymous")


# ── Direct status endpoints (registered before proxy catch-all) ──────


class GatewayStatus(BaseModel):
    upstreams: dict[str, str] = Field(default_factory=dict)
    rate_limit_per_min: int = 0


@app.get("/api/v1/gateway/status", tags=["gateway"])
async def gateway_status() -> GatewayStatus:
    """Report gateway configuration and upstream URLs."""
    return GatewayStatus(
        upstreams={
            "trust-engine": TRUST_ENGINE_URL,
            "policy-server": POLICY_SERVER_URL,
            "audit-collector": AUDIT_COLLECTOR_URL,
        },
        rate_limit_per_min=RATE_LIMIT_PER_MIN,
    )


# ── Proxy endpoint ───────────────────────────────────────────────────


@app.api_route(
    "/api/v1/{path:path}",
    methods=["GET", "POST", "PUT", "DELETE", "PATCH"],
    tags=["proxy"],
)
async def proxy(request: Request, path: str) -> Response:
    """Forward requests to the appropriate upstream component."""
    full_path = f"/api/v1/{path}"
    upstream_base = _resolve_upstream(full_path)

    if upstream_base is None:
        raise HTTPException(404, f"No upstream for path: {full_path}")

    agent_did = _extract_agent_did(request)

    # Rate limiting
    if not _rate_limiter.allow(agent_did):
        raise HTTPException(
            429,
            detail="Rate limit exceeded",
            headers={"Retry-After": "60"},
        )

    # Forward the request
    assert _client is not None
    upstream_url = f"{upstream_base}{full_path}"

    try:
        body = await request.body()
        headers = {
            k: v
            for k, v in request.headers.items()
            if k.lower() not in ("host", "content-length", "transfer-encoding")
        }

        resp = await _client.request(
            method=request.method,
            url=upstream_url,
            content=body,
            headers=headers,
        )

        return Response(
            content=resp.content,
            status_code=resp.status_code,
            headers=dict(resp.headers),
            media_type=resp.headers.get("content-type"),
        )
    except httpx.ConnectError:
        raise HTTPException(502, f"Upstream {upstream_base} unreachable")
    except httpx.TimeoutException:
        raise HTTPException(504, f"Upstream {upstream_base} timed out")


def main() -> None:
    run_server(app, default_port=8446)


if __name__ == "__main__":
    main()
