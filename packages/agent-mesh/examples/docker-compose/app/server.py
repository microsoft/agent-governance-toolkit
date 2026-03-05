# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""
AgentMesh Example Server

A self-contained FastAPI application that demonstrates the mesh server,
trust registry, identity service, and agent sidecar proxy — all in one
image controlled by environment variables.

When MESH_MODE is unset or "server", it runs the mesh control plane.
When MESH_MODE is "agent", it runs an agent sidecar that registers with
the mesh server and exposes a local health/task API.
"""

import asyncio
import os
import time
import logging
import json
import uuid
from contextlib import asynccontextmanager
from datetime import datetime, timezone

import httpx
import redis.asyncio as aioredis
import yaml
import uvicorn
from fastapi import FastAPI, HTTPException, Request
from prometheus_client import (
    Counter,
    Gauge,
    Histogram,
    generate_latest,
    CONTENT_TYPE_LATEST,
)
from fastapi.responses import Response

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

MODE = os.getenv("MESH_MODE", "server")  # "server" or "agent"
HOST = os.getenv("MESH_HOST", "0.0.0.0")
PORT = int(os.getenv("MESH_PORT", os.getenv("MESH_SIDECAR_PORT", "8080")))
METRICS_PORT = int(os.getenv("MESH_METRICS_PORT", "9090"))
REDIS_URL = os.getenv("MESH_REDIS_URL", "redis://localhost:6379/0")
LOG_LEVEL = os.getenv("MESH_LOG_LEVEL", "INFO").upper()

# Agent-specific
AGENT_ID = os.getenv("MESH_AGENT_ID", f"agent-{uuid.uuid4().hex[:8]}")
AGENT_NAME = os.getenv("MESH_AGENT_NAME", "unnamed")
AGENT_CAPS = [c.strip() for c in os.getenv("MESH_AGENT_CAPABILITIES", "").split(",") if c.strip()]
SERVER_URL = os.getenv("MESH_SERVER_URL", "http://localhost:8080")

# Trust
TRUST_THRESHOLD = float(os.getenv("MESH_TRUST_THRESHOLD", "0.6"))
CONFIG_PATH = os.getenv("MESH_CONFIG_PATH", "")

logging.basicConfig(level=LOG_LEVEL, format="%(asctime)s %(levelname)s %(name)s — %(message)s")
logger = logging.getLogger("agentmesh")

# ---------------------------------------------------------------------------
# Prometheus metrics
# ---------------------------------------------------------------------------

REGISTERED_AGENTS = Gauge("agentmesh_registered_agents", "Number of registered agents")
TRUST_SCORE = Gauge("agentmesh_trust_score", "Current trust score", ["agent_id"])
TASKS_TOTAL = Counter("agentmesh_tasks_total", "Tasks processed", ["agent_id", "status"])
HANDSHAKE_DURATION = Histogram(
    "agentmesh_handshake_duration_seconds",
    "Handshake latency",
    buckets=[0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0],
)
POLICY_VIOLATIONS = Counter("agentmesh_policy_violations_total", "Policy violations", ["agent_id", "violation_type"])
REDIS_OPS = Counter("agentmesh_redis_operations_total", "Redis operations", ["operation"])
HEARTBEAT_TS = Gauge("agentmesh_agent_last_heartbeat", "Last heartbeat unix ts", ["agent_id"])

# ---------------------------------------------------------------------------
# Shared state (in-process for this example)
# ---------------------------------------------------------------------------

agents: dict[str, dict] = {}
redis_client: aioredis.Redis | None = None
mesh_config: dict = {}

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


async def _connect_redis():
    global redis_client
    try:
        redis_client = aioredis.from_url(REDIS_URL, decode_responses=True)
        await redis_client.ping()
        logger.info("Connected to Redis at %s", REDIS_URL)
    except Exception as exc:
        logger.warning("Redis unavailable (%s); running without persistence", exc)
        redis_client = None


async def _load_config():
    global mesh_config
    if CONFIG_PATH and os.path.isfile(CONFIG_PATH):
        with open(CONFIG_PATH) as f:
            mesh_config = yaml.safe_load(f) or {}
        logger.info("Loaded mesh config from %s", CONFIG_PATH)


async def _persist_agent(agent_id: str, data: dict):
    if redis_client:
        await redis_client.hset(f"agentmesh:agent:{agent_id}", mapping={k: json.dumps(v) if isinstance(v, (dict, list)) else str(v) for k, v in data.items()})
        REDIS_OPS.labels(operation="hset").inc()


async def _publish(channel: str, message: dict):
    if redis_client:
        await redis_client.publish(channel, json.dumps(message))
        REDIS_OPS.labels(operation="publish").inc()


# ---------------------------------------------------------------------------
# Lifespan
# ---------------------------------------------------------------------------


@asynccontextmanager
async def lifespan(app: FastAPI):
    await _connect_redis()
    await _load_config()

    if MODE == "agent":
        asyncio.create_task(_agent_registration_loop())

    yield  # app runs here

    if redis_client:
        await redis_client.aclose()


# ---------------------------------------------------------------------------
# Agent registration loop (agent mode only)
# ---------------------------------------------------------------------------


async def _agent_registration_loop():
    """Periodically register / heartbeat with the mesh server."""
    await asyncio.sleep(2)  # wait for server to be ready
    async with httpx.AsyncClient(timeout=10) as client:
        while True:
            try:
                payload = {
                    "agent_id": AGENT_ID,
                    "name": AGENT_NAME,
                    "capabilities": AGENT_CAPS,
                    "endpoint": f"http://{AGENT_ID}:{PORT}",
                }
                resp = await client.post(f"{SERVER_URL}/agents/register", json=payload)
                if resp.status_code in (200, 201):
                    logger.info("Registered/heartbeat with mesh server (%s)", AGENT_ID)
                else:
                    logger.warning("Registration returned %s: %s", resp.status_code, resp.text)
            except Exception as exc:
                logger.warning("Cannot reach mesh server: %s", exc)
            await asyncio.sleep(25)  # heartbeat interval


# ---------------------------------------------------------------------------
# FastAPI app
# ---------------------------------------------------------------------------

app = FastAPI(title="AgentMesh Example", lifespan=lifespan)

# ---- shared endpoints (both modes) ----


@app.get("/health")
async def health():
    return {"status": "healthy", "mode": MODE, "timestamp": _now_iso()}


@app.get("/metrics")
async def metrics():
    return Response(content=generate_latest(), media_type=CONTENT_TYPE_LATEST)


# ---- server-mode endpoints ----

if MODE == "server":

    @app.post("/agents/register", status_code=201)
    async def register_agent(request: Request):
        body = await request.json()
        agent_id = body.get("agent_id")
        if not agent_id:
            raise HTTPException(status_code=400, detail="agent_id is required")

        start = time.monotonic()
        now = _now_iso()
        is_new = agent_id not in agents

        trust_initial = mesh_config.get("trust", {}).get("initial_score", 0.5)
        existing_score = agents.get(agent_id, {}).get("trust_score", trust_initial)

        agents[agent_id] = {
            "agent_id": agent_id,
            "name": body.get("name", ""),
            "capabilities": body.get("capabilities", []),
            "endpoint": body.get("endpoint", ""),
            "trust_score": existing_score if not is_new else trust_initial,
            "registered_at": agents.get(agent_id, {}).get("registered_at", now),
            "last_heartbeat": now,
            "status": "active",
        }

        REGISTERED_AGENTS.set(len(agents))
        TRUST_SCORE.labels(agent_id=agent_id).set(agents[agent_id]["trust_score"])
        HEARTBEAT_TS.labels(agent_id=agent_id).set(time.time())
        HANDSHAKE_DURATION.observe(time.monotonic() - start)

        await _persist_agent(agent_id, agents[agent_id])
        await _publish("agentmesh:events", {"type": "register" if is_new else "heartbeat", "agent_id": agent_id})

        logger.info("Agent %s %s (trust=%.2f)", agent_id, "registered" if is_new else "heartbeat", agents[agent_id]["trust_score"])
        return {"agent_id": agent_id, "trust_score": agents[agent_id]["trust_score"]}

    @app.get("/agents")
    async def list_agents():
        return {"agents": list(agents.values()), "count": len(agents)}

    @app.get("/agents/{agent_id}")
    async def get_agent(agent_id: str):
        if agent_id not in agents:
            raise HTTPException(status_code=404, detail="Agent not found")
        return agents[agent_id]

    @app.get("/agents/{agent_id}/trust")
    async def get_trust(agent_id: str):
        if agent_id not in agents:
            raise HTTPException(status_code=404, detail="Agent not found")
        a = agents[agent_id]
        return {
            "agent_id": agent_id,
            "trust_score": a["trust_score"],
            "threshold": TRUST_THRESHOLD,
            "trusted": a["trust_score"] >= TRUST_THRESHOLD,
        }

    @app.post("/agents/{agent_id}/task")
    async def submit_task(agent_id: str, request: Request):
        if agent_id not in agents:
            raise HTTPException(status_code=404, detail="Agent not found")

        body = await request.json()
        a = agents[agent_id]

        if a["trust_score"] < TRUST_THRESHOLD:
            POLICY_VIOLATIONS.labels(agent_id=agent_id, violation_type="low_trust").inc()
            raise HTTPException(status_code=403, detail="Trust score below threshold")

        task_id = f"task-{uuid.uuid4().hex[:12]}"
        scoring = mesh_config.get("trust", {}).get("scoring", {})
        delta = scoring.get("successful_task", 0.05)
        a["trust_score"] = min(1.0, a["trust_score"] + delta)

        TRUST_SCORE.labels(agent_id=agent_id).set(a["trust_score"])
        TASKS_TOTAL.labels(agent_id=agent_id, status="success").inc()

        await _publish("agentmesh:events", {"type": "task_complete", "agent_id": agent_id, "task_id": task_id})
        logger.info("Task %s completed for %s (trust now %.2f)", task_id, agent_id, a["trust_score"])
        return {"task_id": task_id, "status": "completed", "trust_score": a["trust_score"]}

    @app.get("/trust/scores")
    async def trust_scores():
        return {
            "scores": {aid: a["trust_score"] for aid, a in agents.items()},
            "threshold": TRUST_THRESHOLD,
        }

    @app.get("/config")
    async def get_config():
        return mesh_config

# ---- agent-mode endpoints ----

if MODE == "agent":

    @app.post("/task")
    async def agent_task(request: Request):
        body = await request.json()
        task_id = f"local-{uuid.uuid4().hex[:8]}"
        logger.info("[%s] Received task: %s", AGENT_NAME, body.get("description", "no description"))
        TASKS_TOTAL.labels(agent_id=AGENT_ID, status="success").inc()
        return {"task_id": task_id, "agent": AGENT_NAME, "status": "completed"}

    @app.get("/info")
    async def agent_info():
        return {"agent_id": AGENT_ID, "name": AGENT_NAME, "capabilities": AGENT_CAPS}


# ---------------------------------------------------------------------------
# Entrypoint
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    logger.info("Starting AgentMesh in %s mode on %s:%d", MODE, HOST, PORT)
    uvicorn.run("server:app", host=HOST, port=PORT, log_level=LOG_LEVEL.lower())
