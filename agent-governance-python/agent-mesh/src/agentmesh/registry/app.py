# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""AgentMesh Registry — FastAPI application.

Spec: docs/specs/AGENTMESH-WIRE-1.0.md Section 11
Independent design: implements against wire spec only.
"""

from __future__ import annotations

import base64
import os
import logging
from datetime import datetime, timedelta, timezone
from typing import Any

from fastapi import FastAPI, Header, HTTPException, Query
from pydantic import BaseModel, Field

from agentmesh.registry.store import AgentRecord, InMemoryRegistryStore, RegistryStore

logger = logging.getLogger(__name__)

REPLAY_WINDOW = timedelta(minutes=5)


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


# ── Request/Response Models ──────────────────────────────────────────


class RegisterAgentRequest(BaseModel):
    public_key: str  # base64url, Ed25519 (32 bytes)
    proof: str  # base64url Ed25519 signature over (public_key || proof_timestamp)
    proof_timestamp: str  # ISO 8601 UTC timestamp signed in the proof
    capabilities: list[str] = Field(default_factory=list)
    metadata: dict[str, str] = Field(default_factory=dict)


class PreKeyBundleRequest(BaseModel):
    identity_key: str  # base64url, X25519 (32 bytes)
    # Ed25519 signing key (32 bytes, base64url). Required to verify the
    # signed_pre_key signature on the receiver side. Optional for
    # back-compat with older clients that conflated the two keys.
    identity_key_ed: str | None = None
    signed_pre_key: dict[str, Any]
    one_time_pre_keys: list[dict[str, Any]] = Field(default_factory=list)


class ReputationRequest(BaseModel):
    score: float = Field(ge=0.0, le=1.0)
    reason: str = ""


class SessionReputationRequest(BaseModel):
    """Best-effort end-of-session telemetry from initiator/receiver.

    The router-side `/agt/registry/registry/reputation/session` path lands
    here (router strips `/agt/registry/` then prepends `/v1/`). Used by
    AzureClaw to score session outcomes after `mesh_send` round-trips.
    """

    session_id: str
    initiator_amid: str
    receiver_amid: str
    intent: str = ""
    outcome: str  # "success" | "failed" | "timeout"
    started_at: str = ""
    reporter_amid: str
    timestamp: str = ""
    signature: str = ""


class IdentityVerifyRequest(BaseModel):
    """Body for POST /v1/registry/verify (Phase 6.c).

    Used by the kars mesh plugin (and any future AGT-SDK client) to
    upgrade a registered agent from anonymous-tier to verified-tier
    by presenting an Entra-signed JWT. The verifier validates the
    token against the tenant's JWKS, then stamps the verified appId
    + tenantId + timestamp + tier onto the agent record.

    Fail-closed: invalid/expired/wrong-aud/wrong-tid tokens return
    401 and leave the agent's existing tier unchanged (so a failed
    re-verify can't accidentally downgrade a previously-verified peer).
    """

    amid: str
    verification_token: str = Field(..., max_length=8192)


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
    # Reject TZ-naive timestamps explicitly to avoid a 500 from the
    # ``now - ts`` subtraction below.
    if ts.tzinfo is None:
        raise HTTPException(status_code=401, detail="Timestamp must include timezone offset")

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
            """Register a new agent with proof-of-possession."""
            import hashlib

            from nacl.exceptions import BadSignatureError
            from nacl.signing import VerifyKey

            # Decode and validate public key
            try:
                public_key = base64.urlsafe_b64decode(req.public_key + "==")
            except Exception:
                raise HTTPException(status_code=400, detail="Invalid public_key encoding")
            if len(public_key) != 32:
                raise HTTPException(status_code=400, detail="public_key must be 32 bytes")

            # Verify proof timestamp is within replay window
            try:
                ts = datetime.fromisoformat(req.proof_timestamp)
            except (ValueError, TypeError):
                raise HTTPException(status_code=400, detail="Invalid proof_timestamp")
            if abs((_utcnow() - ts).total_seconds()) > REPLAY_WINDOW.total_seconds():
                raise HTTPException(status_code=401, detail="Proof timestamp outside replay window")

            # Verify proof-of-possession: signature over (public_key || proof_timestamp)
            try:
                proof_bytes = base64.urlsafe_b64decode(req.proof + "==")
                message = req.public_key.encode() + req.proof_timestamp.encode()
                VerifyKey(public_key).verify(message, proof_bytes)
            except BadSignatureError:
                raise HTTPException(status_code=401, detail="Invalid proof-of-possession")
            except Exception:
                raise HTTPException(status_code=400, detail="Malformed proof")

            # Derive DID deterministically from public key hash
            key_hash = hashlib.sha256(public_key).hexdigest()[:32]
            did = f"did:mesh:{key_hash}"

            if store.get_agent(did):
                raise HTTPException(status_code=409, detail="Agent already registered")

            record = AgentRecord(
                did=did,
                public_key=public_key,
                capabilities=req.capabilities,
                metadata=req.metadata,
            )
            store.put_agent(record)
            logger.info("Registered agent %s", did)
            return {"did": did, "status": "registered"}

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
                # Phase 6.c follow-up — session counters. Old clients
                # that don't know about these keys ignore them; new
                # clients (kars router → operator CLI) surface them as
                # total_sessions / successful / failed / timeout in
                # the AGT detail overlay's Reputation block.
                "total_sessions": agent.total_sessions,
                "successful_sessions": agent.successful_sessions,
                "failed_sessions": agent.failed_sessions,
                "timeout_sessions": agent.timeout_sessions,
                "last_session_at": (
                    agent.last_session_at.isoformat()
                    if agent.last_session_at is not None
                    else None
                ),
                # Derived field: success / total. -1.0 sentinel means
                # "no sessions yet" so consumers can distinguish from
                # "0 of N succeeded". Computing it server-side keeps
                # clients honest (no risk of a stale client computing
                # 0.0 because it doesn't know about the new fields).
                "completion_rate": (
                    agent.successful_sessions / agent.total_sessions
                    if agent.total_sessions > 0 else -1.0
                ),
                # Phase 6.c identity verification — populated when the
                # agent has POSTed a valid Entra-signed JWT to
                # /v1/registry/verify. All three are None for anonymous
                # tier and for clusters that have not opted in to
                # verification. `tier` is the human-readable label
                # operators see in the AGT overlay.
                "tier": agent.tier,
                "verified_app_id": agent.verified_app_id,
                "verified_tenant_id": agent.verified_tenant_id,
                "verified_at": (
                    agent.verified_at.isoformat()
                    if agent.verified_at is not None
                    else None
                ),
            }

        @app.delete("/v1/agents/{did}", status_code=204)
        async def deregister_agent(
            did: str,
            authorization: str = Header(..., alias="Authorization"),
        ) -> None:
            """Deregister an agent.

            Requires Ed25519-Timestamp auth and the caller's DID must
            match the DID being deregistered — only the holder of the
            corresponding private key can remove a registration.
            """
            authed_did = verify_ed25519_timestamp_auth(authorization, store)
            if authed_did != did:
                raise HTTPException(status_code=403, detail="DID mismatch")
            if not store.delete_agent(did):
                raise HTTPException(status_code=404, detail="Agent not found")
            logger.info("Deregistered agent %s", did)

        # ── Pre-Keys ─────────────────────────────────────────────

        @app.put("/v1/agents/{did}/prekeys")
        async def upload_prekeys(
            did: str,
            req: PreKeyBundleRequest,
            authorization: str = Header(..., alias="Authorization"),
        ) -> dict:
            """Upload a pre-key bundle. Requires Ed25519-Timestamp auth."""
            agent = store.get_agent(did)
            if not agent:
                raise HTTPException(status_code=404, detail="Agent not found")

            # Verify the caller owns this DID via Ed25519-Timestamp auth
            authed_did = verify_ed25519_timestamp_auth(authorization, store)
            if authed_did != did:
                raise HTTPException(status_code=403, detail="DID mismatch")

            try:
                agent.identity_key = base64.urlsafe_b64decode(req.identity_key + "==")
                if req.identity_key_ed:
                    agent.identity_key_ed = base64.urlsafe_b64decode(req.identity_key_ed + "==")
                    if len(agent.identity_key_ed) != 32:
                        raise HTTPException(
                            status_code=400,
                            detail="identity_key_ed must be exactly 32 bytes (Ed25519 public key)",
                        )
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
                "identity_key_ed": (
                    base64.urlsafe_b64encode(agent.identity_key_ed).decode().rstrip("=")
                    if agent.identity_key_ed
                    else None
                ),
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

        @app.post("/v1/agents/{did}/heartbeat")
        async def heartbeat(
            did: str,
            authorization: str | None = Header(None, alias="Authorization"),
        ) -> dict:
            """Bump an agent's `last_seen` to keep it visible in presence
            checks. Rate-limited to at most once per 10 seconds per agent
            to prevent abuse (attacker keeping stale agents permanently
            online). Returns 429 when throttled without updating last_seen.

            Authentication: required. The caller must present an
            ``Ed25519-Timestamp`` header signed by ``did``. Without this,
            any unauthenticated party could keep an offline agent's
            presence record live (impersonation / DoS-mask).
            """
            authed_did = verify_ed25519_timestamp_auth(authorization, store)
            if authed_did != did:
                raise HTTPException(
                    status_code=403,
                    detail="Authenticated DID does not match heartbeat target",
                )
            if not store.get_agent(did):
                raise HTTPException(status_code=404, detail="Agent not found")
            if not store.try_update_last_seen(did, min_interval_seconds=10.0):
                raise HTTPException(
                    status_code=429,
                    detail="Heartbeat throttled; retry after 10s",
                )
            agent = store.get_agent(did)
            return {
                "did": did,
                "last_seen": agent.last_seen.isoformat() if agent else None,
            }

        # ── Reputation ───────────────────────────────────────────

        @app.post("/v1/agents/{did}/reputation")
        async def submit_reputation(
            did: str,
            req: ReputationRequest,
            authorization: str | None = Header(None, alias="Authorization"),
        ) -> dict:
            """Submit reputation feedback for an agent.

            Authentication: required. The caller must present an
            ``Ed25519-Timestamp`` header so the reporter is bound to an
            authenticated identity. Self-reporting is rejected — agents
            cannot inflate their own reputation.

            Phase 6.c follow-up: ALSO bumps the per-agent session
            counters. This endpoint is the only path AGT mesh peers
            currently take to record session feedback
            (POST /v1/registry/reputation/session is reserved for
            initiator/receiver pairs with explicit outcome buckets and
            is not what the mesh SDK calls today). Without this bump,
            `total_sessions` would stay at 0 even as `reputation_score`
            drifts from the default 0.5 over hundreds of session
            replies, leaving operators unable to gauge sample size.

            Score → bucket mapping uses the same thresholds as the
            session endpoint's outcome semantics for consistency with
            the existing 5-band tier ladder:
              score >= 0.7 → successful (peer responded well)
              score <  0.3 → failed     (peer responded badly)
              else         → timeout    (partial / ambiguous)
            """
            authed_did = verify_ed25519_timestamp_auth(authorization, store)
            if authed_did == did:
                raise HTTPException(
                    status_code=403,
                    detail="Agents may not submit reputation about themselves",
                )
            agent = store.get_agent(did)
            if not agent:
                raise HTTPException(status_code=404, detail="Agent not found")

            # Simple exponential moving average
            alpha = 0.3
            agent.reputation_score = alpha * req.score + (1 - alpha) * agent.reputation_score
            # Bump counters in lockstep with the EMA so total_sessions
            # always reflects the number of EMA updates and consumers
            # can compute a confidence interval.
            agent.total_sessions += 1
            if req.score >= 0.7:
                agent.successful_sessions += 1
            elif req.score < 0.3:
                agent.failed_sessions += 1
            else:
                agent.timeout_sessions += 1
            agent.last_session_at = _utcnow()
            store.put_agent(agent)
            return {"did": did, "reputation_score": round(agent.reputation_score, 4)}

        @app.post("/v1/registry/reputation/session")
        async def submit_session_reputation(
            req: SessionReputationRequest,
            authorization: str | None = Header(None, alias="Authorization"),
        ) -> dict:
            """Record a session outcome and update both endpoints' reputation.

            Outcome mapping (EMA, alpha=0.2):
              - success → score 1.0 toward both endpoints
              - failed  → score 0.0 toward the receiver (initiator unchanged)
              - timeout → score 0.2 toward the receiver (initiator unchanged)

            Missing agents are silently skipped (best-effort telemetry).

            Authentication: required. The caller must present an
            ``Ed25519-Timestamp`` header and the authenticated DID MUST
            equal ``reporter_amid``. Additionally, the reporter must be
            a session participant (initiator or receiver). Together this
            stops any party — authenticated or not — from forging session
            telemetry as another agent.

            Phase 6.c follow-up: in addition to bumping the EMA, this
            handler also increments per-outcome session counters on the
            same agent records. Operators querying `GET /v1/agents/{did}`
            can then distinguish "0.7 from 2 sessions" (noisy) from
            "0.7 from 200 sessions" (confident). Counters and EMA are
            updated together inside `_apply` so they stay coherent —
            you can't get one without the other.
            """
            authed_did = verify_ed25519_timestamp_auth(authorization, store)
            if authed_did != req.reporter_amid:
                raise HTTPException(
                    status_code=403,
                    detail="reporter_amid does not match authenticated DID",
                )
            # Validate reporter is a session participant
            if req.reporter_amid not in (req.initiator_amid, req.receiver_amid):
                raise HTTPException(
                    status_code=403,
                    detail="reporter_amid must be a session participant",
                )
            reporter = store.get_agent(req.reporter_amid)
            if not reporter:
                raise HTTPException(
                    status_code=403,
                    detail="reporter_amid is not a registered agent",
                )
            outcome = (req.outcome or "").lower()
            alpha = 0.2
            updated: dict[str, float] = {}
            now = _utcnow()

            def _apply(did: str, target_score: float) -> None:
                agent = store.get_agent(did)
                if not agent:
                    return
                agent.reputation_score = alpha * target_score + (1 - alpha) * agent.reputation_score
                # Always bump the totals — every reputation update is a
                # session, regardless of which side initiated. Per-outcome
                # buckets are stored only for the SAME outcome the EMA
                # was nudged with, so success/fail/timeout sum to total.
                agent.total_sessions += 1
                if outcome == "success":
                    agent.successful_sessions += 1
                elif outcome == "failed":
                    agent.failed_sessions += 1
                elif outcome == "timeout":
                    agent.timeout_sessions += 1
                agent.last_session_at = now
                store.put_agent(agent)
                updated[did] = round(agent.reputation_score, 4)

            if outcome == "success":
                _apply(req.receiver_amid, 1.0)
                _apply(req.initiator_amid, 1.0)
            elif outcome == "failed":
                _apply(req.receiver_amid, 0.0)
            elif outcome == "timeout":
                _apply(req.receiver_amid, 0.2)
            else:
                raise HTTPException(
                    status_code=400,
                    detail=f"Invalid outcome '{req.outcome}' (expected success|failed|timeout)",
                )

            return {
                "session_id": req.session_id,
                "outcome": outcome,
                "reputation": updated,
            }

        # ── Identity Verification (Phase 6.c) ────────────────────

        @app.post("/v1/registry/verify")
        async def verify_identity(req: IdentityVerifyRequest) -> dict:
            """Upgrade a registered agent from anonymous → verified tier
            by validating an Entra-signed JWT against tenant JWKS.

            Opt-in: when AGENTMESH_ENTRA_AUDIENCE + AGENTMESH_ENTRA_TENANT_ID
            are unset on the registry deployment, this endpoint returns
            503 (verification disabled). Clusters that haven't opted in
            keep all agents at anonymous tier — preserving full backward
            compat with v3.7.0.

            On success: stamps verified_app_id (Entra `appid` claim),
            verified_tenant_id (`tid`), verified_at (server time), and
            tier='verified' onto the agent record. Subsequent
            GET /v1/agents/{did} reflects the new tier.

            Fail-closed: invalid/expired/wrong-aud/wrong-tid tokens
            return 401 and leave the agent's existing tier unchanged.
            A previously-verified peer keeps its tier on re-verify
            failure (defense against transient JWKS-fetch flakes that
            could otherwise demote a legitimate peer mid-session).
            """
            from agentmesh.identity.entra_verifier import (
                EntraTokenError,
                get_verifier,
            )

            # Phase 6.c — the openclaw plugin's `agtIdentity.amid` is
            # the bare base64-encoded public-key blob, NOT the
            # DID-prefixed form the registry stores under. We accept
            # both shapes via a two-step lookup: literal-amid first,
            # then linear scan keyed by the agent's identity_key
            # (X25519 32-byte public key) when the literal lookup
            # misses. Linear scan is O(n) but the registry is in-
            # memory and rarely holds >100 agents in practice — well
            # below any threshold where this would matter.
            agent = store.get_agent(req.amid)
            if not agent and not req.amid.startswith("did:"):
                # Look up by raw public-key bytes
                import base64
                try:
                    pub = base64.urlsafe_b64decode(req.amid + "==")
                except Exception:
                    pub = None
                if pub is not None and hasattr(store, "_agents"):
                    for stored in store._agents.values():
                        if (
                            stored.identity_key == pub
                            or stored.identity_key_ed == pub
                        ):
                            agent = stored
                            req = req.model_copy(update={"amid": stored.did})
                            break
            if not agent:
                logger.warning(
                    "verify_identity got 404 for amid=%r (request body amid). "
                    "Known agent count=%d. This usually means the plugin sent "
                    "a different amid from the one it registered with — check "
                    "agtIdentity.amid vs RegistryClient.register payload.",
                    req.amid,
                    len(store._agents) if hasattr(store, "_agents") else -1,
                )
                raise HTTPException(status_code=404, detail="Agent not registered")

            verifier = await get_verifier()
            if verifier is None:
                # Opt-out path: registry deployed without env vars →
                # verification disabled cluster-wide. Distinct from
                # "token rejected" so clients can log/skip cleanly.
                raise HTTPException(
                    status_code=503,
                    detail="Entra verification not configured on this registry",
                )

            try:
                claims = await verifier.verify(req.verification_token)
            except EntraTokenError as exc:
                logger.warning(
                    "verify_identity rejected token for %s: %s",
                    req.amid, exc,
                )
                raise HTTPException(status_code=401, detail="Token verification failed")

            app_id = str(claims.get("appid") or claims.get("azp") or "").strip()
            tenant_id = str(claims.get("tid", "")).strip()
            if not app_id:
                raise HTTPException(
                    status_code=401,
                    detail="Verified token missing appid/azp claim",
                )

            agent.verified_app_id = app_id
            agent.verified_tenant_id = tenant_id
            agent.verified_at = _utcnow()
            agent.tier = "verified"
            store.put_agent(agent)
            logger.info(
                "verify_identity: %s upgraded to verified tier (appid=%s tenant=%s)",
                req.amid, app_id, tenant_id,
            )
            return {
                "did": req.amid,
                "tier": agent.tier,
                "verified_app_id": app_id,
                "verified_tenant_id": tenant_id,
                "verified_at": agent.verified_at.isoformat(),
            }

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
            # Phase 6.c — surface the verification toggle so the kars
            # operator CLI can tell whether the cluster has opted in
            # to verified-tier mesh peers. Same shape as relay /health.
            entra_enabled = bool(
                os.environ.get("AGENTMESH_ENTRA_AUDIENCE", "").strip()
                and os.environ.get("AGENTMESH_ENTRA_TENANT_ID", "").strip()
            )
            return {
                "status": "healthy",
                "service": "agentmesh-registry",
                "entra_verify_enabled": entra_enabled,
            }

        return app
