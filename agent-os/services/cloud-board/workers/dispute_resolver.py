# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""
Dispute Resolver Worker

Background worker that automatically processes and resolves disputes
by replaying flight recorder logs against the Control Plane.
"""

import asyncio
import logging
from datetime import datetime, timedelta, timezone
from typing import Optional, Literal
from dataclasses import dataclass

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


@dataclass
class PendingDispute:
    """A dispute waiting to be resolved."""
    dispute_id: str
    escrow_id: str
    requester_did: str
    provider_did: str
    requester_logs_hash: Optional[str]
    provider_logs_hash: Optional[str]
    created_at: datetime
    priority: int = 0


class DisputeResolverWorker:
    """
    Background worker for automated dispute resolution.
    
    Responsibilities:
    - Monitor for disputes ready for resolution
    - Replay flight recorder logs against Control Plane
    - Determine outcomes and apply penalties
    - Update escrows based on resolution
    """
    
    def __init__(
        self,
        check_interval_seconds: int = 30,
        max_concurrent_resolutions: int = 5,
        auto_resolve_timeout_hours: int = 24,
    ):
        self.check_interval = check_interval_seconds
        self.max_concurrent = max_concurrent_resolutions
        self.auto_resolve_timeout = timedelta(hours=auto_resolve_timeout_hours)
        
        self._running = False
        self._pending_disputes: list[PendingDispute] = []
        self._active_resolutions: set[str] = set()
    
    async def start(self):
        """Start the worker."""
        self._running = True
        logger.info("Dispute resolver worker started")
        
        await asyncio.gather(
            self._resolution_loop(),
            self._timeout_loop(),
        )
    
    async def stop(self):
        """Stop the worker."""
        self._running = False
        logger.info("Dispute resolver worker stopped")
    
    async def _resolution_loop(self):
        """Main resolution loop."""
        while self._running:
            try:
                # Check for disputes ready to resolve
                ready_disputes = [
                    d for d in self._pending_disputes
                    if d.requester_logs_hash and d.provider_logs_hash
                    and d.dispute_id not in self._active_resolutions
                ]
                
                # Process up to max_concurrent
                for dispute in ready_disputes[:self.max_concurrent]:
                    asyncio.create_task(self._resolve_dispute(dispute))
                
                await asyncio.sleep(self.check_interval)
            except Exception as e:
                logger.error(f"Error in resolution loop: {e}")
                await asyncio.sleep(5)
    
    async def _timeout_loop(self):
        """Check for timed-out disputes."""
        while self._running:
            try:
                now = datetime.now(timezone.utc)
                
                for dispute in self._pending_disputes:
                    age = now - dispute.created_at
                    if age > self.auto_resolve_timeout:
                        if dispute.dispute_id not in self._active_resolutions:
                            logger.warning(
                                f"Dispute {dispute.dispute_id} timed out, auto-resolving"
                            )
                            asyncio.create_task(
                                self._auto_resolve_timeout(dispute)
                            )
                
                await asyncio.sleep(60)  # Check every minute
            except Exception as e:
                logger.error(f"Error in timeout loop: {e}")
                await asyncio.sleep(5)
    
    async def _resolve_dispute(self, dispute: PendingDispute):
        """Resolve a dispute."""
        dispute_id = dispute.dispute_id
        self._active_resolutions.add(dispute_id)
        
        try:
            logger.info(f"Resolving dispute {dispute_id}")
            
            # Fetch and validate logs
            requester_valid = await self._validate_logs(dispute.requester_logs_hash)
            provider_valid = await self._validate_logs(dispute.provider_logs_hash)
            
            # Replay against Control Plane
            if requester_valid and provider_valid:
                outcome = await self._replay_and_compare(
                    dispute.requester_logs_hash,
                    dispute.provider_logs_hash,
                )
            elif requester_valid:
                outcome = "requester_wins"
            elif provider_valid:
                outcome = "provider_wins"
            else:
                outcome = "split"
            
            # Apply resolution
            await self._apply_resolution(dispute, outcome)
            
            # Remove from pending
            self._pending_disputes = [
                d for d in self._pending_disputes
                if d.dispute_id != dispute_id
            ]
            
            logger.info(f"Dispute {dispute_id} resolved: {outcome}")
            
        except Exception as e:
            logger.error(f"Error resolving dispute {dispute_id}: {e}")
        finally:
            self._active_resolutions.discard(dispute_id)
    
    async def _validate_logs(self, logs_hash: Optional[str]) -> bool:
        """Validate flight recorder logs."""
        if not logs_hash:
            return False
        
        # In production, would:
        # 1. Fetch logs from storage
        # 2. Verify hash integrity
        # 3. Validate log format
        # 4. Check signatures
        
        return True
    
    async def _replay_and_compare(
        self,
        requester_logs_hash: str,
        provider_logs_hash: str,
    ) -> Literal["requester_wins", "provider_wins", "split"]:
        """
        Replay logs against Control Plane and compare.
        
        This is the core Arbiter logic - deterministically determines
        which agent's claim is accurate.
        """
        # In production, would:
        # 1. Parse both logs
        # 2. Identify disputed operations
        # 3. Replay each operation against Control Plane
        # 4. Compare expected vs actual outcomes
        # 5. Determine which agent was truthful
        
        # Placeholder - would use actual replay logic
        return "split"
    
    async def _apply_resolution(
        self,
        dispute: PendingDispute,
        outcome: Literal["requester_wins", "provider_wins", "split"],
    ):
        """Apply the resolution to escrow and reputation."""
        # In production, would:
        # 1. Update escrow status
        # 2. Distribute credits
        # 3. Update reputation scores
        # 4. Record compliance event
        # 5. Notify parties
        
        logger.info(
            f"Applied resolution for {dispute.dispute_id}: "
            f"{outcome}, credits distributed"
        )
    
    async def _auto_resolve_timeout(self, dispute: PendingDispute):
        """Auto-resolve a timed-out dispute."""
        self._active_resolutions.add(dispute.dispute_id)
        
        try:
            # Penalize the party that didn't submit evidence
            if not dispute.requester_logs_hash and not dispute.provider_logs_hash:
                outcome = "split"  # Both failed to submit
            elif not dispute.requester_logs_hash:
                outcome = "provider_wins"
            else:
                outcome = "requester_wins"
            
            await self._apply_resolution(dispute, outcome)
            
            # Remove from pending
            self._pending_disputes = [
                d for d in self._pending_disputes
                if d.dispute_id != dispute.dispute_id
            ]
            
        finally:
            self._active_resolutions.discard(dispute.dispute_id)
    
    def add_dispute(
        self,
        dispute_id: str,
        escrow_id: str,
        requester_did: str,
        provider_did: str,
        priority: int = 0,
    ):
        """Add a dispute to the resolution queue."""
        dispute = PendingDispute(
            dispute_id=dispute_id,
            escrow_id=escrow_id,
            requester_did=requester_did,
            provider_did=provider_did,
            requester_logs_hash=None,
            provider_logs_hash=None,
            created_at=datetime.now(timezone.utc),
            priority=priority,
        )
        self._pending_disputes.append(dispute)
        # Sort by priority
        self._pending_disputes.sort(key=lambda d: d.priority, reverse=True)
        
        logger.info(f"Dispute {dispute_id} added to queue")
    
    def submit_evidence(
        self,
        dispute_id: str,
        party: Literal["requester", "provider"],
        logs_hash: str,
    ):
        """Submit evidence for a dispute."""
        for dispute in self._pending_disputes:
            if dispute.dispute_id == dispute_id:
                if party == "requester":
                    dispute.requester_logs_hash = logs_hash
                else:
                    dispute.provider_logs_hash = logs_hash
                
                logger.info(
                    f"Evidence submitted for {dispute_id} by {party}"
                )
                return
        
        logger.warning(f"Dispute {dispute_id} not found")
    
    def get_queue_status(self) -> dict:
        """Get current queue status."""
        return {
            "pending": len(self._pending_disputes),
            "active": len(self._active_resolutions),
            "ready_for_resolution": len([
                d for d in self._pending_disputes
                if d.requester_logs_hash and d.provider_logs_hash
            ]),
        }


# Global worker instance
_worker: Optional[DisputeResolverWorker] = None


def get_worker() -> DisputeResolverWorker:
    """Get or create the worker instance."""
    global _worker
    if _worker is None:
        _worker = DisputeResolverWorker()
    return _worker


async def main():
    """Run the worker standalone."""
    worker = get_worker()
    await worker.start()


if __name__ == "__main__":
    asyncio.run(main())
