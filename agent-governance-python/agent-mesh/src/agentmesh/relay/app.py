# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""AgentMesh Relay — FastAPI + WebSocket application.

Spec: docs/specs/AGENTMESH-WIRE-1.0.md Section 12
Independent design: implements against wire spec only.
"""

from __future__ import annotations

import asyncio
import base64
import hashlib
import json
import logging
import os
import secrets
from datetime import datetime, timedelta, timezone

from fastapi import FastAPI, WebSocket, WebSocketDisconnect

from agentmesh.relay.store import InMemoryInboxStore, InboxStore, StoredMessage

logger = logging.getLogger(__name__)

# Shared-secret token for relay authentication (optional, backward-compatible).
_RELAY_TOKEN: str | None = os.environ.get("AGENTMESH_RELAY_TOKEN")
if not _RELAY_TOKEN:
    logger.warning(
        "AGENTMESH_RELAY_TOKEN is not set — the relay will accept "
        "unauthenticated connections.  Set this env var in production."
    )

# Phase 6.c — optional Entra-signed JWT verification for the connect
# frame's ``token`` field. Opt-in via AGENTMESH_ENTRA_AUDIENCE +
# AGENTMESH_ENTRA_TENANT_ID. When disabled the legacy shared-secret /
# open-connect behavior is preserved exactly.
_ENTRA_VERIFY_ENABLED = bool(
    os.environ.get("AGENTMESH_ENTRA_AUDIENCE", "").strip()
    and os.environ.get("AGENTMESH_ENTRA_TENANT_ID", "").strip()
)
if _ENTRA_VERIFY_ENABLED:
    logger.info(
        "Entra-signed JWT verification enabled (audience=%s tenant=%s) — "
        "shared-secret AGENTMESH_RELAY_TOKEN path is BYPASSED when an "
        "Entra token is supplied",
        os.environ.get("AGENTMESH_ENTRA_AUDIENCE"),
        os.environ.get("AGENTMESH_ENTRA_TENANT_ID"),
    )

# Proof-of-possession enforcement for connect frames. When True (default),
# every ``connect`` frame must include ``public_key``, ``timestamp``, and
# ``signature`` and the relay verifies that the supplied DID is derived
# from the public key and that the signature over the timestamp is valid.
# Setting ``AGENTMESH_RELAY_ALLOW_UNAUTHED_DID=1`` re-enables the legacy
# behavior for local/dev usage only — never in production.
_REQUIRE_DID_POP: bool = (
    os.environ.get("AGENTMESH_RELAY_ALLOW_UNAUTHED_DID", "").lower()
    not in ("1", "true", "yes")
)
if not _REQUIRE_DID_POP:
    logger.warning(
        "AGENTMESH_RELAY_ALLOW_UNAUTHED_DID is set — the relay will "
        "accept connect frames without DID proof-of-possession. "
        "Any client can impersonate any DID. Do not use in production."
    )

HEARTBEAT_INTERVAL = 30  # seconds
OFFLINE_THRESHOLD = 90  # seconds — 3 missed heartbeats
DID_POP_REPLAY_WINDOW = timedelta(minutes=5)


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


def _verify_connect_pop(frame: dict) -> tuple[bool, str]:
    """Verify proof-of-possession on a relay ``connect`` frame.

    Required fields when ``_REQUIRE_DID_POP`` is True:

    - ``from`` — the agent DID (``did:mesh:<32-hex>``)
    - ``public_key`` — base64 Ed25519 public key (32 bytes)
    - ``timestamp`` — ISO-8601 UTC timestamp (within 5-minute window)
    - ``signature`` — base64 Ed25519 signature over the timestamp

    The DID is checked against ``did:mesh:`` + ``sha256(public_key)[:32]``
    so the client cannot present someone else's DID with their own key.

    Returns ``(True, "")`` on success; ``(False, reason)`` on failure.
    """
    from nacl.exceptions import BadSignatureError
    from nacl.signing import VerifyKey

    did = frame.get("from")
    pub_b64 = frame.get("public_key")
    ts_str = frame.get("timestamp")
    sig_b64 = frame.get("signature")

    if not (isinstance(did, str) and isinstance(pub_b64, str)
            and isinstance(ts_str, str) and isinstance(sig_b64, str)):
        return False, "connect frame missing did/public_key/timestamp/signature"

    # Decode and length-check the public key.
    try:
        pub_bytes = base64.b64decode(pub_b64)
    except Exception:
        return False, "invalid public_key encoding"
    if len(pub_bytes) != 32:
        return False, "public_key must be 32 bytes"

    # DID must be derived from the public key (binds key to identity).
    expected_did = f"did:mesh:{hashlib.sha256(pub_bytes).hexdigest()[:32]}"
    if did != expected_did:
        return False, "DID does not match public_key (sha256 mismatch)"

    # Reject stale or future-dated proofs.
    try:
        ts = datetime.fromisoformat(ts_str.replace("Z", "+00:00"))
    except ValueError:
        return False, "invalid timestamp format"
    if ts.tzinfo is None:
        # Without tzinfo, the subtraction below raises TypeError. Treat
        # naive timestamps as an outright rejection — clients must send
        # explicit offsets per spec.
        return False, "timestamp must include timezone offset"
    if abs((_utcnow() - ts).total_seconds()) > DID_POP_REPLAY_WINDOW.total_seconds():
        return False, "timestamp outside replay window"

    # Verify Ed25519 signature over the timestamp.
    try:
        sig = base64.b64decode(sig_b64)
        VerifyKey(pub_bytes).verify(ts_str.encode("utf-8"), sig)
    except BadSignatureError:
        return False, "invalid signature"
    except Exception:
        return False, "signature verification failed"

    return True, ""


class ConnectedAgent:
    """Tracks a connected agent's WebSocket and heartbeat."""

    def __init__(
        self,
        did: str,
        ws: WebSocket,
        verified_app_id: str | None = None,
    ) -> None:
        self.did = did
        self.ws = ws
        self.connected_at = _utcnow()
        self.last_heartbeat = _utcnow()
        # Phase 6.c — populated when the connect frame's ``token`` was
        # an Entra-signed JWT and verification succeeded. Operators
        # can correlate did→appid via this field on /health.
        self.verified_app_id = verified_app_id

    @property
    def is_stale(self) -> bool:
        return (_utcnow() - self.last_heartbeat).total_seconds() > OFFLINE_THRESHOLD


class RelayServer:
    """AgentMesh Relay — store-and-forward WebSocket message relay.

    Routes messages between connected agents. Stores messages for
    offline agents in the inbox store (ciphertext-only — the relay
    cannot read message content).
    """

    def __init__(self, inbox: InboxStore | None = None) -> None:
        self._inbox = inbox or InMemoryInboxStore()
        self._connections: dict[str, ConnectedAgent] = {}
        self._app = self._create_app()
        self._stats = {"messages_routed": 0, "messages_stored": 0, "messages_delivered": 0}

    @property
    def app(self) -> FastAPI:
        return self._app

    @property
    def connections(self) -> dict[str, ConnectedAgent]:
        return dict(self._connections)

    @property
    def stats(self) -> dict[str, int]:
        return dict(self._stats)

    def _create_app(self) -> FastAPI:
        app = FastAPI(
            title="AgentMesh Relay",
            version="1.0.0",
            description="Store-and-forward WebSocket relay for agent messaging.",
        )

        @app.get("/health")
        async def health() -> dict:
            verified_count = sum(
                1 for c in self._connections.values() if c.verified_app_id
            )
            return {
                "status": "healthy",
                "service": "agentmesh-relay",
                "connected_agents": len(self._connections),
                "verified_agents": verified_count,
                "entra_verify_enabled": _ENTRA_VERIFY_ENABLED,
                "stats": self._stats,
            }

        @app.websocket("/ws")
        async def websocket_endpoint(ws: WebSocket) -> None:
            await ws.accept()
            agent_did: str | None = None

            try:
                # First frame must be connect
                raw = await asyncio.wait_for(ws.receive_text(), timeout=10.0)
                frame = json.loads(raw)

                if frame.get("type") != "connect":
                    await ws.send_json({"type": "error", "detail": "First frame must be 'connect'"})
                    await ws.close(code=4001)
                    return

                agent_did = frame.get("from")
                if not agent_did:
                    await ws.send_json({"type": "error", "detail": "Missing 'from' field"})
                    await ws.close(code=4002)
                    return

                # DID proof-of-possession check (upstream main). Binds the
                # WebSocket to the holder of the private key, preventing
                # any client from connecting as an arbitrary DID and
                # intercepting its mail. Applies in both Entra and
                # shared-secret auth modes — it's an independent layer
                # over identity, not over tokens.
                if _REQUIRE_DID_POP:
                    ok, reason = _verify_connect_pop(frame)
                    if not ok:
                        logger.warning(
                            "Rejecting connect frame for %s: %s", agent_did, reason
                        )
                        await ws.send_json(
                            {"type": "error", "detail": f"DID proof failed: {reason}"}
                        )
                        await ws.close(code=4005)
                        return

                # Authenticate. Three modes, in priority order:
                #
                # 1. Entra-signed JWT verification (Phase 6.c). When the
                #    operator has set both AGENTMESH_ENTRA_AUDIENCE and
                #    AGENTMESH_ENTRA_TENANT_ID, the connect frame MUST
                #    carry a valid Entra-issued JWT in ``token``. We
                #    extract ``appid`` and stamp it on the
                #    ConnectedAgent so /health and trust-scoring can
                #    correlate did→appid. There is NO fallback to the
                #    legacy shared-secret path when Entra is enabled —
                #    that would let an attacker bypass JWT verification
                #    by simply omitting the ``token`` field.
                # 2. Legacy shared-secret. When AGENTMESH_RELAY_TOKEN is
                #    set AND Entra verification is disabled, accept the
                #    shared secret. Preserves backward compat for
                #    clusters that haven't migrated to Entra.
                # 3. Open. When neither is configured, accept anything.
                #    The boot-time WARNING tells the operator about it.
                verified_app_id: str | None = None
                client_token = frame.get("token")
                if _ENTRA_VERIFY_ENABLED:
                    # Lazy import keeps PyJWT off the cold path when
                    # verification is disabled. Verifier lives under
                    # `agentmesh.identity` so the registry (which also
                    # validates inbound Entra tokens via /v1/registry/verify)
                    # can reuse it without a cross-module dependency.
                    from agentmesh.identity.entra_verifier import (
                        EntraTokenError,
                        get_verifier,
                    )

                    if not client_token or (
                        isinstance(client_token, str) and len(client_token) > 16384
                    ):
                        # Reject empty/missing/oversized tokens IMMEDIATELY when
                        # Entra is enabled. Falling through to the
                        # shared-secret branch (or open-acceptance)
                        # would let a peer skip the JWT presentation
                        # entirely — exactly the bypass we're meant
                        # to prevent.
                        logger.warning(
                            "Entra enabled but no token presented by %s",
                            agent_did,
                        )
                        await ws.send_json(
                            {
                                "type": "error",
                                "detail": "Authentication required (Entra)",
                            }
                        )
                        await ws.close(code=4003)
                        return

                    verifier = await get_verifier()
                    if verifier is None:
                        # Should not happen if _ENTRA_VERIFY_ENABLED — but
                        # if the verifier failed to initialize post-boot
                        # (e.g. JWKS reachability issue), fail closed
                        # rather than silently downgrading to shared-secret.
                        logger.error(
                            "Entra verification enabled but get_verifier() "
                            "returned None — refusing connect for %s",
                            agent_did,
                        )
                        await ws.send_json(
                            {
                                "type": "error",
                                "detail": "Authentication unavailable (Entra)",
                            }
                        )
                        await ws.close(code=4003)
                        return

                    try:
                        claims = await verifier.verify(client_token)
                        verified_app_id = str(
                            claims.get("appid") or claims.get("azp") or ""
                        ) or None
                        logger.info(
                            "Entra token verified for %s (appid=%s)",
                            agent_did,
                            verified_app_id,
                        )
                    except EntraTokenError as exc:
                        # Differentiated path: only the Entra branch
                        # was tried, so we MUST NOT fall back to the
                        # shared-secret compare — an attacker could
                        # otherwise present a malformed JWT to skip
                        # straight to the shared-secret check.
                        logger.warning(
                            "Entra token rejected for %s: %s",
                            agent_did,
                            exc,
                        )
                        await ws.send_json(
                            {
                                "type": "error",
                                "detail": "Authentication failed (Entra)",
                            }
                        )
                        await ws.close(code=4003)
                        return
                elif _RELAY_TOKEN is not None:
                    # Legacy shared-secret path. Reached only when Entra
                    # verification is disabled (operator hasn't opted in).
                    if not client_token or not secrets.compare_digest(
                        client_token, _RELAY_TOKEN
                    ):
                        await ws.send_json(
                            {"type": "error", "detail": "Authentication failed"}
                        )
                        await ws.close(code=4003)
                        return

                # Register connection.
                #
                # Gap G5 (vendored agentmesh-relay patch #2): if a stale
                # connection already exists for this DID, close it eagerly
                # before the dict overwrite. Without this, the old socket
                # lingers as a "ghost" until the 90s heartbeat-eviction
                # timer fires, during which time messages can be routed to
                # a dead connection. Code 1000 is used instead of a custom
                # 4xxx so the client treats this as a clean close and does
                # NOT trigger its auto-reconnect loop (which would just
                # race the new socket the same client just opened).
                existing = self._connections.get(agent_did)
                if existing is not None:
                    logger.info(
                        "Closing ghost connection for %s (session replaced)",
                        agent_did,
                    )
                    try:
                        await existing.ws.close(
                            code=1000, reason="session_replaced"
                        )
                    except Exception:  # noqa: BLE001 - best-effort cleanup
                        pass

                self._connections[agent_did] = ConnectedAgent(
                    agent_did, ws, verified_app_id=verified_app_id
                )
                if verified_app_id:
                    logger.info(
                        "Agent connected: %s (verified appid=%s)",
                        agent_did,
                        verified_app_id,
                    )
                else:
                    logger.info("Agent connected: %s", agent_did)

                # Deliver pending messages
                await self._deliver_pending(agent_did, ws)

                # Message loop. Each receive is bounded by an idle
                # timeout — without it, a connected agent that never
                # sends a frame can hold its slot in self._connections
                # indefinitely. 90s is generous for typical heartbeat
                # cadences (~30s) and lets a stalled peer be reaped.
                _IDLE_TIMEOUT = 90.0
                while True:
                    try:
                        raw = await asyncio.wait_for(
                            ws.receive_text(), timeout=_IDLE_TIMEOUT
                        )
                    except asyncio.TimeoutError:
                        logger.info(
                            "Idle timeout for %s after %ss; closing",
                            agent_did, _IDLE_TIMEOUT,
                        )
                        await ws.close(code=4004)
                        return
                    frame = json.loads(raw)
                    await self._handle_frame(agent_did, frame, ws)

            except WebSocketDisconnect:
                logger.info("Agent disconnected: %s", agent_did)
            except asyncio.TimeoutError:
                logger.warning("Connection timeout for %s", agent_did)
            except json.JSONDecodeError:
                logger.warning("Invalid JSON from %s", agent_did)
            except Exception as e:
                logger.error("Relay error for %s: %s", agent_did, e)
            finally:
                # Only remove if the current dict entry still references
                # OUR ws — protects against ghost-cleanup races where this
                # finally is for an old socket that was already replaced.
                if agent_did:
                    current = self._connections.get(agent_did)
                    if current is not None and current.ws is ws:
                        del self._connections[agent_did]

        return app

    async def _handle_frame(
        self, sender_did: str, frame: dict, ws: WebSocket
    ) -> None:
        """Handle an incoming WebSocket frame."""
        frame_type = frame.get("type")

        if frame_type == "message":
            await self._handle_message(sender_did, frame)

        elif frame_type == "ack":
            msg_id = frame.get("id")
            if msg_id:
                self._inbox.acknowledge(msg_id)

        elif frame_type == "heartbeat":
            conn = self._connections.get(sender_did)
            if conn:
                conn.last_heartbeat = _utcnow()

        elif frame_type == "disconnect":
            conn = self._connections.pop(sender_did, None)
            if conn:
                await conn.ws.close(code=1000)

        elif frame_type == "knock" or frame_type == "knock_accept" or frame_type == "knock_reject":
            # Route KNOCK frames like messages
            await self._handle_message(sender_did, frame)

        else:
            await ws.send_json({"type": "error", "detail": f"Unknown frame type: {frame_type}"})

    async def _handle_message(self, sender_did: str, frame: dict) -> None:
        """Route a message to recipient — deliver live or store offline."""
        recipient_did = frame.get("to")
        message_id = frame.get("id")

        if not recipient_did or not message_id:
            return

        recipient = self._connections.get(recipient_did)

        if recipient and not recipient.is_stale:
            # Deliver directly
            try:
                await recipient.ws.send_json(frame)
                self._stats["messages_routed"] += 1
                return
            except Exception:
                # Connection broken — fall through to store
                self._connections.pop(recipient_did, None)

        # Store for offline delivery
        stored = StoredMessage(
            message_id=message_id,
            sender_did=sender_did,
            recipient_did=recipient_did,
            payload=json.dumps(frame),
        )
        if self._inbox.store(stored):
            self._stats["messages_stored"] += 1
            logger.debug("Stored offline message %s for %s", message_id, recipient_did)

    async def _deliver_pending(self, agent_did: str, ws: WebSocket) -> None:
        """Push all pending messages to a newly connected agent.

        Messages stay in the inbox until the recipient explicitly sends
        an ``ack`` frame for them — see the ``ack`` branch in
        :meth:`_handle_frame`. Acknowledging on send (the previous
        behavior) silently dropped messages whenever the recipient
        disconnected after ``send_json`` returned but before the frame
        actually reached them.
        """
        pending = self._inbox.fetch_pending(agent_did)
        for msg in pending:
            try:
                frame = json.loads(msg.payload)
                await ws.send_json(frame)
                self._stats["messages_delivered"] += 1
            except Exception as e:
                logger.warning("Failed to deliver pending %s: %s", msg.message_id, e)
                break  # Stop on first failure — reconnect will retry
