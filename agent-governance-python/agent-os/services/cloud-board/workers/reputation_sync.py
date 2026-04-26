# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""
Reputation Sync Worker

Background worker that periodically syncs reputation scores
and broadcasts slash events to the network.
"""

import asyncio
import logging
from datetime import datetime, timedelta, timezone
from typing import Optional
import aiohttp

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


class ReputationSyncWorker:
    """
    Background worker for reputation synchronization.
    
    Responsibilities:
    - Periodic reputation score recalculation
    - Broadcast slash events to connected agents
    - Sync reputation data with peer Nexus nodes (for federation)
    - Cleanup expired reputation records
    """
    
    def __init__(
        self,
        sync_interval_seconds: int = 60,
        broadcast_batch_size: int = 100,
    ):
        self.sync_interval = sync_interval_seconds
        self.broadcast_batch_size = broadcast_batch_size
        self._running = False
        self._connected_agents: dict[str, str] = {}  # DID -> webhook URL
        self._pending_broadcasts: list[dict] = []
    
    async def start(self):
        """Start the worker."""
        self._running = True
        logger.info("Reputation sync worker started")
        
        await asyncio.gather(
            self._sync_loop(),
            self._broadcast_loop(),
        )
    
    async def stop(self):
        """Stop the worker."""
        self._running = False
        logger.info("Reputation sync worker stopped")
    
    async def _sync_loop(self):
        """Main sync loop."""
        while self._running:
            try:
                await self._sync_reputation_scores()
                await asyncio.sleep(self.sync_interval)
            except Exception as e:
                logger.error(f"Error in sync loop: {e}")
                await asyncio.sleep(5)
    
    async def _broadcast_loop(self):
        """Broadcast loop for slash events."""
        while self._running:
            try:
                if self._pending_broadcasts:
                    await self._process_broadcasts()
                await asyncio.sleep(1)
            except Exception as e:
                logger.error(f"Error in broadcast loop: {e}")
                await asyncio.sleep(5)
    
    async def _sync_reputation_scores(self):
        """Recalculate and sync reputation scores."""
        logger.debug("Syncing reputation scores...")
        
        # In production, would:
        # 1. Fetch all agents from database
        # 2. Recalculate scores based on recent activity
        # 3. Update database
        # 4. Notify connected agents of significant changes
        
        pass
    
    async def _process_broadcasts(self):
        """Process pending broadcast events."""
        batch = self._pending_broadcasts[:self.broadcast_batch_size]
        self._pending_broadcasts = self._pending_broadcasts[self.broadcast_batch_size:]
        
        for event in batch:
            await self._broadcast_event(event)
    
    async def _broadcast_event(self, event: dict):
        """Broadcast an event to all connected agents."""
        logger.info(f"Broadcasting event: {event.get('type')}")
        
        async with aiohttp.ClientSession() as session:
            for agent_did, webhook_url in self._connected_agents.items():
                try:
                    async with session.post(
                        webhook_url,
                        json=event,
                        timeout=aiohttp.ClientTimeout(total=5),
                    ) as resp:
                        if resp.status != 200:
                            logger.warning(
                                f"Failed to broadcast to {agent_did}: {resp.status}"
                            )
                except Exception as e:
                    logger.warning(f"Error broadcasting to {agent_did}: {e}")
    
    def register_agent(self, agent_did: str, webhook_url: str):
        """Register an agent for broadcasts."""
        self._connected_agents[agent_did] = webhook_url
        logger.info(f"Agent registered for broadcasts: {agent_did}")
    
    def unregister_agent(self, agent_did: str):
        """Unregister an agent from broadcasts."""
        if agent_did in self._connected_agents:
            del self._connected_agents[agent_did]
            logger.info(f"Agent unregistered: {agent_did}")
    
    def queue_broadcast(self, event: dict):
        """Queue an event for broadcast."""
        event["queued_at"] = datetime.now(timezone.utc).isoformat()
        self._pending_broadcasts.append(event)
    
    def queue_slash_event(
        self,
        agent_did: str,
        slash_id: str,
        reason: str,
        severity: str,
        score_after: int,
    ):
        """Queue a slash event for broadcast."""
        self.queue_broadcast({
            "type": "reputation_slash",
            "agent_did": agent_did,
            "slash_id": slash_id,
            "reason": reason,
            "severity": severity,
            "score_after": score_after,
            "action": "block_agent" if score_after < 300 else "warn",
        })


# Global worker instance
_worker: Optional[ReputationSyncWorker] = None


def get_worker() -> ReputationSyncWorker:
    """Get or create the worker instance."""
    global _worker
    if _worker is None:
        _worker = ReputationSyncWorker()
    return _worker


async def main():
    """Run the worker standalone."""
    worker = get_worker()
    await worker.start()


if __name__ == "__main__":
    asyncio.run(main())
