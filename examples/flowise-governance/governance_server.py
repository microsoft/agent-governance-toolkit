# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""FastAPI sidecar that exposes AGT governance nodes to Flowise over HTTP.

Flowise is a Node.js application; governance logic lives in Python.
This server bridges the two: Flowise sends a JSON payload to /govern,
and this server runs the policy check, rate limit, and audit log before
returning an allow/block decision.

Usage:
    pip install flowise-agentmesh fastapi uvicorn
    uvicorn governance_server:app --port 8000

    # Or with auto-reload during development:
    uvicorn governance_server:app --port 8000 --reload
"""

from __future__ import annotations

import logging
import os
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Any

from fastapi import FastAPI
from fastapi.responses import JSONResponse
from pydantic import BaseModel

from flowise_agentmesh import AuditNode, GovernanceNode, RateLimiterNode

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("flowise_governance")

POLICY_PATH = os.environ.get(
    "AGT_POLICY_PATH",
    str(Path(__file__).parent / "policy.yaml"),
)
AUDIT_PATH = os.environ.get("AGT_AUDIT_PATH", "audit.jsonl")
MAX_REQUESTS = int(os.environ.get("AGT_MAX_REQUESTS", "100"))
WINDOW_SECONDS = float(os.environ.get("AGT_WINDOW_SECONDS", "60"))


gov: GovernanceNode
audit: AuditNode
limiter: RateLimiterNode


@asynccontextmanager
async def lifespan(application: FastAPI):
    global gov, audit, limiter
    gov = GovernanceNode(policy_path=POLICY_PATH, strict_mode=False)
    audit = AuditNode(storage="file", file_path=AUDIT_PATH, export_format="jsonl")
    limiter = RateLimiterNode(max_requests=MAX_REQUESTS, window_seconds=WINDOW_SECONDS)
    logger.info("Governance sidecar ready. Policy: %s", POLICY_PATH)
    yield


app = FastAPI(
    title="AGT Governance Sidecar",
    description="Flowise HTTP governance bridge for Agent Governance Toolkit",
    version="1.0.0",
    lifespan=lifespan,
)


class GovernRequest(BaseModel):
    tool: str
    content: str | None = None
    agent_id: str = "flowise-agent"
    arguments: dict[str, Any] | None = None


class GovernResponse(BaseModel):
    allowed: bool
    reason: str | None = None
    tool: str
    agent_id: str


@app.get("/health")
def health() -> dict[str, str]:
    """Liveness probe. Returns 200 when the sidecar is ready."""
    return {"status": "ok"}


@app.post("/govern", response_model=GovernResponse)
def govern(req: GovernRequest) -> GovernResponse:
    """Evaluate a tool call against governance policy.

    Returns {"allowed": true} to proceed, or {"allowed": false, "reason": "..."}
    to block. Always fails closed on unexpected errors.
    """
    try:
        # 1. Rate limit
        rate = limiter.run({"agent_id": req.agent_id, "action": req.tool})
        if not rate["allowed"]:
            retry = rate.get("retry_after")
            reason = (
                f"Rate limit exceeded. Retry after {retry:.1f}s."
                if retry
                else "Rate limit exceeded."
            )
            audit.run(
                {
                    "agent_id": req.agent_id,
                    "tool": req.tool,
                    "decision": "blocked",
                    "reason": reason,
                }
            )
            return GovernResponse(
                allowed=False, reason=reason, tool=req.tool, agent_id=req.agent_id
            )

        # 2. Policy check
        gov_result = gov.run(
            {
                "tool": req.tool,
                "content": req.content,
                "arguments": req.arguments,
            }
        )

        decision = "allowed" if gov_result["allowed"] else "blocked"
        audit.run(
            {
                "agent_id": req.agent_id,
                "tool": req.tool,
                "content": req.content,
                "decision": decision,
                "reason": gov_result.get("reason"),
            }
        )

        return GovernResponse(
            allowed=gov_result["allowed"],
            reason=gov_result.get("reason"),
            tool=req.tool,
            agent_id=req.agent_id,
        )

    except Exception:
        logger.exception("Governance check failed; failing closed")
        audit.run(
            {
                "agent_id": req.agent_id,
                "tool": req.tool,
                "decision": "blocked",
                "reason": "internal error",
            }
        )
        return JSONResponse(  # type: ignore[return-value]
            status_code=500,
            content={
                "allowed": False,
                "reason": "Internal governance error; request blocked for safety.",
                "tool": req.tool,
                "agent_id": req.agent_id,
            },
        )
