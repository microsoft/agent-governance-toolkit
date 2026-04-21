# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""AgentMesh Registry — FastAPI application.

Spec: docs/specs/AGENTMESH-WIRE-1.0.md Section 11
Independent design: implements against wire spec only.
"""

from __future__ import annotations

import base64
import logging
from datetime import datetime, timedelta, timezone
from typing import Any

from fastapi import FastAPI, HTTPException, Query
from pydantic import BaseModel, Field

from agentmesh.registry.store import AgentRecord, InMemoryRegistryStore, RegistryStore

logger = logging.getLogger(__name__)

REPLAY_WINDOW = timedelta(minutes=5)


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


# ── Request/Response Models ──────────────────────────────────────────


class RegisterAgentRequest(BaseModel):
    did: str
    public_key: str  # base64url
    capabilities: list[str] = Field(default_factory=list)
    metadata: dict[str, str] = Field(default_factory=dict)


class PreKeyBundleRequest(BaseModel):
    identity_key: str  # base64url
    signed_pre_key: dict[str, Any]
    one_time_pre_keys: list[dict[str, Any]] = Field(default_factory=list)


class ReputationRequest(BaseModel):
    score: float = Field(ge=0.0, le=1.0)
    reason: str = ""


# ── Auth ─────────────────────────────────────────────────────────────


def verify_ed25519_timestamp_auth(
    authorization: str | None,
    store: RegistryStore,
) -> str:
    """Verify Ed25519-Timestamp auth header. Returns the agent DID.

    Format: Ed25519-Timestamp <did> <iso8601> <base64url(signature)>

    Spec: docs/specs/AGENTMESH-WIRE-1.0.md Section 13.1
    """
    if not authorization or not authorization.startswith("Ed25519-Timestamp "):
        raise HTTPException(status_code=401, detail="Missing or invalid Authorization header")

    parts = authorization.split(" ", 3)
    if len(parts) != 4:
        raise HTTPException(status_code=401, detail="Malformed Ed25519-Timestamp header")

    _, did, timestamp_str, sig_b64 = parts

    # Check timestamp within replay window
    try:
        ts = datetime.fromisoformat(timestamp_str.replace("Z", "+00:00"))
    except ValueError:
        raise HTTPException(status_code=401, detail="Invalid timestamp format")

    now = _utcnow()
    if abs((now - ts).total_seconds()) > REPLAY_WINDOW.total_seconds():
        raise HTTPException(status_code=401, detail="Timestamp outside replay window")

    # Look up agent
    agent = store.get_agent(did)
    if not agent:
        raise HTTPException(status_code=401, detail="Agent not registered")

    # Verify Ed25519 signature over timestamp
    try:
        from nacl.signing import VerifyKey

        sig = base64.urlsafe_b64decode(sig_b64 + "==")
        vk = VerifyKey(agent.public_key)
        vk.verify(timestamp_str.encode("utf-8"), sig)
    except Exception:
        raise HTTPException(status_code=401, detail="Invalid signature")

    return did


# ── Application ──────────────────────────────────────────────────────


class RegistryServer:
    """AgentMesh Registry — FastAPI application."""

    def __init__(self, store: RegistryStore | None = None) -> None:
        self._store = store or InMemoryRegistryStore()
        self._app = self._create_app()

    @property
    def app(self) -> FastAPI:
        return self._app

    @property
    def store(self) -> RegistryStore:
        return self._store

    def _create_app(self) -> FastAPI:
        app = FastAPI(
            title="AgentMesh Registry",
            version="1.0.0",
            description="Agent registration, pre-key distribution, and discovery.",
        )

        store = self._store

        # ── Registration ─────────────────────────────────────────

        @app.post("/v1/agents", status_code=201)
        async def register_agent(req: RegisterAgentRequest) -> dict:
            """Register a new agent."""
            if store.get_agent(req.did):
                raise HTTPException(status_code=409, detail="Agent already registered")

            try:
                public_key = base64.urlsafe_b64decode(req.public_key + "==")
            except Exception:
                raise HTTPException(status_code=400, detail="Invalid public_key encoding")

            if len(public_key) != 32:
                raise HTTPException(status_code=400, detail="public_key must be 32 bytes")

            record = AgentRecord(
                did=req.did,
                public_key=public_key,
                capabilities=req.capabilities,
                metadata=req.metadata,
            )
            store.put_agent(record)
            logger.info("Registered agent %s", req.did)
            return {"did": req.did, "status": "registered"}

        @app.get("/v1/agents/{did}")
        async def get_agent(did: str) -> dict:
            """Get agent metadata."""
            agent = store.get_agent(did)
            if not agent:
                raise HTTPException(status_code=404, detail="Agent not found")
            return {
                "did": agent.did,
                "capabilities": agent.capabilities,
                "metadata": agent.metadata,
                "registered_at": agent.registered_at.isoformat(),
                "last_seen": agent.last_seen.isoformat(),
                "reputation_score": agent.reputation_score,
            }

        @app.delete("/v1/agents/{did}", status_code=204)
        async def deregister_agent(did: str) -> None:
            """Deregister an agent."""
            if not store.delete_agent(did):
                raise HTTPException(status_code=404, detail="Agent not found")
            logger.info("Deregistered agent %s", did)

        # ── Pre-Keys ─────────────────────────────────────────────

        @app.put("/v1/agents/{did}/prekeys")
        async def upload_prekeys(did: str, req: PreKeyBundleRequest) -> dict:
            """Upload a pre-key bundle."""
            agent = store.get_agent(did)
            if not agent:
                raise HTTPException(status_code=404, detail="Agent not found")

            try:
                agent.identity_key = base64.urlsafe_b64decode(req.identity_key + "==")
                spk = req.signed_pre_key
                agent.signed_pre_key = base64.urlsafe_b64decode(spk["public_key"] + "==")
                agent.signed_pre_key_signature = base64.urlsafe_b64decode(spk["signature"] + "==")
                agent.signed_pre_key_id = spk["key_id"]
                agent.one_time_pre_keys = list(req.one_time_pre_keys)
            except Exception as e:
                raise HTTPException(status_code=400, detail=f"Invalid pre-key bundle: {e}")

            store.put_agent(agent)
            return {"did": did, "otk_count": len(agent.one_time_pre_keys)}

        @app.get("/v1/agents/{did}/prekeys")
        async def fetch_prekeys(did: str) -> dict:
            """Fetch a pre-key bundle. Atomically consumes one OPK."""
            agent = store.get_agent(did)
            if not agent or not agent.signed_pre_key:
                raise HTTPException(status_code=404, detail="Pre-key bundle not found")

            otk = store.consume_one_time_key(did)

            result: dict[str, Any] = {
                "identity_key": base64.urlsafe_b64encode(agent.identity_key or b"").decode().rstrip("="),
                "signed_pre_key": {
                    "key_id": agent.signed_pre_key_id,
                    "public_key": base64.urlsafe_b64encode(agent.signed_pre_key).decode().rstrip("="),
                    "signature": base64.urlsafe_b64encode(
                        agent.signed_pre_key_signature or b""
                    ).decode().rstrip("="),
                },
            }

            if otk:
                result["one_time_pre_key"] = otk
            else:
                result["one_time_pre_key"] = None

            return result

        # ── Presence ─────────────────────────────────────────────

        @app.get("/v1/agents/{did}/presence")
        async def get_presence(did: str) -> dict:
            """Get agent presence / last-seen."""
            agent = store.get_agent(did)
            if not agent:
                raise HTTPException(status_code=404, detail="Agent not found")
            return {
                "did": agent.did,
                "last_seen": agent.last_seen.isoformat(),
                "online": (_utcnow() - agent.last_seen).total_seconds() < 90,
            }

        # ── Reputation ───────────────────────────────────────────

        @app.post("/v1/agents/{did}/reputation")
        async def submit_reputation(did: str, req: ReputationRequest) -> dict:
            """Submit reputation feedback for an agent."""
            agent = store.get_agent(did)
            if not agent:
                raise HTTPException(status_code=404, detail="Agent not found")

            # Simple exponential moving average
            alpha = 0.3
            agent.reputation_score = alpha * req.score + (1 - alpha) * agent.reputation_score
            store.put_agent(agent)
            return {"did": did, "reputation_score": round(agent.reputation_score, 4)}

        # ── Discovery ────────────────────────────────────────────

        @app.get("/v1/discover")
        async def discover(
            capability: str = Query(..., description="Capability to search for"),
            limit: int = Query(default=50, ge=1, le=200),
        ) -> dict:
            """Search agents by capability."""
            results = store.search_by_capability(capability, limit)
            return {
                "results": [
                    {
                        "did": a.did,
                        "capabilities": a.capabilities,
                        "reputation_score": a.reputation_score,
                        "last_seen": a.last_seen.isoformat(),
                    }
                    for a in results
                ],
                "total": len(results),
            }

        # ── Health ───────────────────────────────────────────────

        @app.get("/health")
        async def health() -> dict:
            return {"status": "healthy", "service": "agentmesh-registry"}

        return app
