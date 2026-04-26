# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""AgentMesh Relay — FastAPI + WebSocket application.

Spec: docs/specs/AGENTMESH-WIRE-1.0.md Section 12
Independent design: implements against wire spec only.
"""

from __future__ import annotations

import asyncio
import json
import logging
from datetime import datetime, timezone

from fastapi import FastAPI, WebSocket, WebSocketDisconnect

from agentmesh.relay.store import InMemoryInboxStore, InboxStore, StoredMessage

logger = logging.getLogger(__name__)

HEARTBEAT_INTERVAL = 30  # seconds
OFFLINE_THRESHOLD = 90  # seconds — 3 missed heartbeats


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


class ConnectedAgent:
    """Tracks a connected agent's WebSocket and heartbeat."""

    def __init__(self, did: str, ws: WebSocket) -> None:
        self.did = did
        self.ws = ws
        self.connected_at = _utcnow()
        self.last_heartbeat = _utcnow()

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
            return {
                "status": "healthy",
                "service": "agentmesh-relay",
                "connected_agents": len(self._connections),
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

                # Register connection
                self._connections[agent_did] = ConnectedAgent(agent_did, ws)
                logger.info("Agent connected: %s", agent_did)

                # Deliver pending messages
                await self._deliver_pending(agent_did, ws)

                # Message loop
                while True:
                    raw = await ws.receive_text()
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
                if agent_did and agent_did in self._connections:
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
        """Push all pending messages to a newly connected agent."""
        pending = self._inbox.fetch_pending(agent_did)
        for msg in pending:
            try:
                frame = json.loads(msg.payload)
                await ws.send_json(frame)
                self._inbox.acknowledge(msg.message_id)
                self._stats["messages_delivered"] += 1
            except Exception as e:
                logger.warning("Failed to deliver pending %s: %s", msg.message_id, e)
                break  # Stop on first failure — reconnect will retry
