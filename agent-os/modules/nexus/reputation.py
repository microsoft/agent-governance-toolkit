# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""
Reputation Engine

Calculates and manages trust scores for agents on the Nexus network.
Implements the viral trust mechanism that drives network adoption.
"""

from datetime import datetime, timedelta, timezone
from typing import Optional, Literal
from dataclasses import dataclass, field
from enum import Enum
import asyncio


class TrustTier(str, Enum):
    """Trust tier classification based on score."""
    VERIFIED_PARTNER = "verified_partner"  # 900-1000
    TRUSTED = "trusted"                     # 700-899
    STANDARD = "standard"                   # 500-699
    PROBATIONARY = "probationary"           # 300-499
    UNTRUSTED = "untrusted"                 # 0-299


@dataclass
class TrustScore:
    """Represents an agent's trust score with breakdown."""
    
    agent_did: str
    total_score: int
    tier: TrustTier
    
    # Score components
    base_score: int
    behavioral_modifier: int
    capability_modifier: int
    
    # History
    successful_tasks: int = 0
    failed_tasks: int = 0
    disputes_won: int = 0
    disputes_lost: int = 0
    uptime_days: int = 0
    
    # Timestamps
    calculated_at: datetime = field(default_factory=datetime.utcnow)
    last_activity: Optional[datetime] = None
    
    @classmethod
    def get_tier(cls, score: int) -> TrustTier:
        """Get tier from score."""
        if score >= 900:
            return TrustTier.VERIFIED_PARTNER
        elif score >= 700:
            return TrustTier.TRUSTED
        elif score >= 500:
            return TrustTier.STANDARD
        elif score >= 300:
            return TrustTier.PROBATIONARY
        else:
            return TrustTier.UNTRUSTED
    
    def meets_threshold(self, required_score: int) -> bool:
        """Check if score meets a required threshold."""
        return self.total_score >= required_score


@dataclass
class ReputationHistory:
    """Historical reputation data for an agent."""
    
    agent_did: str
    
    # Task history
    successful_tasks: int = 0
    failed_tasks: int = 0
    total_tasks: int = 0
    
    # Dispute history
    disputes_raised: int = 0
    disputes_won: int = 0
    disputes_lost: int = 0
    
    # Activity
    uptime_days: int = 0
    last_activity: Optional[datetime] = None
    registered_at: Optional[datetime] = None
    
    # Slashing history
    times_slashed: int = 0
    total_slash_amount: int = 0
    last_slashed: Optional[datetime] = None
    
    @property
    def success_rate(self) -> float:
        """Calculate task success rate."""
        if self.total_tasks == 0:
            return 0.0
        return self.successful_tasks / self.total_tasks
    
    @property
    def dispute_win_rate(self) -> float:
        """Calculate dispute win rate."""
        total_disputes = self.disputes_won + self.disputes_lost
        if total_disputes == 0:
            return 0.5  # Neutral
        return self.disputes_won / total_disputes


@dataclass
class SlashEvent:
    """Record of a reputation slash event."""
    
    agent_did: str
    slash_id: str
    
    reason: Literal["hallucination", "policy_violation", "mute_triggered", "dispute_lost", "timeout", "fraud"]
    severity: Literal["critical", "high", "medium", "low"]
    
    score_before: int
    score_reduction: int
    score_after: int
    
    # Evidence
    evidence_hash: Optional[str] = None
    trace_id: Optional[str] = None
    
    # Timestamps
    occurred_at: datetime = field(default_factory=datetime.utcnow)
    
    # Broadcasting
    broadcast_to_network: bool = True
    broadcast_at: Optional[datetime] = None


class ReputationEngine:
    """
    Calculates and manages trust scores for the Nexus network.
    
    The core engine that determines which agents can communicate
    and drives the viral adoption loop.
    """
    
    # Base scores by verification level
    BASE_SCORES = {
        "verified_partner": 800,
        "verified": 650,
        "registered": 400,
        "unknown": 100,
    }
    
    # Severity penalties for slashing
    SLASH_PENALTIES = {
        "critical": 200,
        "high": 100,
        "medium": 50,
        "low": 25,
    }
    
    # Default threshold for communication
    DEFAULT_TRUST_THRESHOLD = 700
    
    def __init__(self, trust_threshold: int = DEFAULT_TRUST_THRESHOLD):
        self.trust_threshold = trust_threshold
        self._score_cache: dict[str, TrustScore] = {}
        self._history_cache: dict[str, ReputationHistory] = {}
        self._slash_events: list[SlashEvent] = []
    
    def calculate_trust_score(
        self,
        verification_level: str,
        history: ReputationHistory,
        capabilities: Optional[dict] = None,
        privacy: Optional[dict] = None,
    ) -> TrustScore:
        """
        Calculate trust score from 0-1000.
        
        Base score from verification level + modifiers from behavior and capabilities.
        
        Args:
            verification_level: Agent's verification tier
            history: Agent's reputation history
            capabilities: Agent's capability manifest
            privacy: Agent's privacy settings
            
        Returns:
            TrustScore with full breakdown
        """
        # Base score from verification tier
        base_score = self.BASE_SCORES.get(verification_level, 100)
        
        # Behavioral modifiers
        behavioral_modifier = 0
        behavioral_modifier += history.successful_tasks * 2      # +2 per success
        behavioral_modifier -= history.failed_tasks * 10         # -10 per failure
        behavioral_modifier -= history.disputes_lost * 50        # -50 per lost dispute
        behavioral_modifier += history.disputes_won * 10         # +10 per won dispute
        behavioral_modifier += int(history.uptime_days * 0.5)    # +0.5 per day online
        behavioral_modifier -= history.times_slashed * 75        # -75 per slash
        
        # Cap behavioral modifier
        behavioral_modifier = max(-300, min(300, behavioral_modifier))
        
        # Capability modifiers
        capability_modifier = 0
        if capabilities:
            if capabilities.get("reversibility") == "full":
                capability_modifier += 50
            elif capabilities.get("reversibility") == "partial":
                capability_modifier += 25
            
            if capabilities.get("idempotency"):
                capability_modifier += 20
        
        if privacy:
            if privacy.get("retention_policy") == "ephemeral":
                capability_modifier += 30
            elif privacy.get("retention_policy") == "permanent":
                capability_modifier -= 20
            
            if privacy.get("training_consent"):
                capability_modifier -= 20
            
            if privacy.get("pii_handling") == "reject":
                capability_modifier += 20
        
        # Calculate total
        total_score = base_score + behavioral_modifier + capability_modifier
        total_score = max(0, min(1000, total_score))  # Clamp to 0-1000
        
        return TrustScore(
            agent_did=history.agent_did,
            total_score=total_score,
            tier=TrustScore.get_tier(total_score),
            base_score=base_score,
            behavioral_modifier=behavioral_modifier,
            capability_modifier=capability_modifier,
            successful_tasks=history.successful_tasks,
            failed_tasks=history.failed_tasks,
            disputes_won=history.disputes_won,
            disputes_lost=history.disputes_lost,
            uptime_days=history.uptime_days,
            last_activity=history.last_activity,
        )
    
    def record_task_outcome(
        self,
        agent_did: str,
        outcome: Literal["success", "failure", "partial"],
    ) -> ReputationHistory:
        """Record a task outcome and update history."""
        history = self._get_or_create_history(agent_did)
        
        history.total_tasks += 1
        history.last_activity = datetime.now(timezone.utc)
        
        if outcome == "success":
            history.successful_tasks += 1
        elif outcome == "failure":
            history.failed_tasks += 1
        else:  # partial
            history.successful_tasks += 0.5
            history.failed_tasks += 0.5
        
        return history
    
    def record_dispute_outcome(
        self,
        agent_did: str,
        outcome: Literal["won", "lost"],
    ) -> ReputationHistory:
        """Record a dispute outcome and update history."""
        history = self._get_or_create_history(agent_did)
        
        history.disputes_raised += 1
        history.last_activity = datetime.now(timezone.utc)
        
        if outcome == "won":
            history.disputes_won += 1
        else:
            history.disputes_lost += 1
        
        return history
    
    def slash_reputation(
        self,
        agent_did: str,
        reason: Literal["hallucination", "policy_violation", "mute_triggered", "dispute_lost", "timeout", "fraud"],
        severity: Literal["critical", "high", "medium", "low"],
        evidence_hash: Optional[str] = None,
        trace_id: Optional[str] = None,
        broadcast: bool = True,
    ) -> SlashEvent:
        """
        Slash an agent's reputation for misbehavior.
        
        When triggered, broadcasts to the network so all agents
        immediately block the offending agent.
        """
        history = self._get_or_create_history(agent_did)
        
        # Get current score
        current_score = self._score_cache.get(agent_did)
        score_before = current_score.total_score if current_score else 400
        
        # Calculate reduction
        score_reduction = self.SLASH_PENALTIES[severity]
        score_after = max(0, score_before - score_reduction)
        
        # Update history
        history.times_slashed += 1
        history.total_slash_amount += score_reduction
        history.last_slashed = datetime.now(timezone.utc)
        
        # Create slash event
        slash_event = SlashEvent(
            agent_did=agent_did,
            slash_id=f"slash_{agent_did}_{datetime.now(timezone.utc).timestamp()}",
            reason=reason,
            severity=severity,
            score_before=score_before,
            score_reduction=score_reduction,
            score_after=score_after,
            evidence_hash=evidence_hash,
            trace_id=trace_id,
            broadcast_to_network=broadcast,
            broadcast_at=datetime.now(timezone.utc) if broadcast else None,
        )
        
        self._slash_events.append(slash_event)
        
        # Invalidate score cache
        if agent_did in self._score_cache:
            del self._score_cache[agent_did]
        
        return slash_event
    
    def check_trust_threshold(
        self,
        agent_did: str,
        required_score: Optional[int] = None,
    ) -> tuple[bool, TrustScore]:
        """
        Check if an agent meets the trust threshold.
        
        Returns:
            Tuple of (meets_threshold, trust_score)
        """
        threshold = required_score or self.trust_threshold
        
        # Get or calculate score
        score = self._score_cache.get(agent_did)
        if not score:
            history = self._get_or_create_history(agent_did)
            score = self.calculate_trust_score("registered", history)
            self._score_cache[agent_did] = score
        
        return score.meets_threshold(threshold), score
    
    def get_network_reputation(
        self,
        agent_dids: Optional[list[str]] = None,
    ) -> dict[str, int]:
        """
        Get reputation scores for multiple agents.
        
        Used for syncing local known_peers cache.
        """
        if agent_dids is None:
            return {did: score.total_score for did, score in self._score_cache.items()}
        
        result = {}
        for did in agent_dids:
            if did in self._score_cache:
                result[did] = self._score_cache[did].total_score
            else:
                history = self._get_or_create_history(did)
                score = self.calculate_trust_score("registered", history)
                result[did] = score.total_score
        
        return result
    
    async def broadcast_slash_event(self, slash_event: SlashEvent) -> int:
        """
        Broadcast a slash event to all connected agents.
        
        Returns number of agents notified.
        """
        # In production, this would use pub/sub or webhooks
        # For now, just mark as broadcast
        slash_event.broadcast_at = datetime.now(timezone.utc)
        return len(self._score_cache)
    
    def _get_or_create_history(self, agent_did: str) -> ReputationHistory:
        """Get or create reputation history for an agent."""
        if agent_did not in self._history_cache:
            self._history_cache[agent_did] = ReputationHistory(
                agent_did=agent_did,
                registered_at=datetime.now(timezone.utc),
            )
        return self._history_cache[agent_did]
    
    def get_leaderboard(self, limit: int = 100) -> list[TrustScore]:
        """Get top agents by trust score."""
        scores = list(self._score_cache.values())
        scores.sort(key=lambda s: s.total_score, reverse=True)
        return scores[:limit]
    
    def get_slash_history(
        self,
        agent_did: Optional[str] = None,
        since: Optional[datetime] = None,
    ) -> list[SlashEvent]:
        """Get slash event history."""
        events = self._slash_events
        
        if agent_did:
            events = [e for e in events if e.agent_did == agent_did]
        
        if since:
            events = [e for e in events if e.occurred_at >= since]
        
        return events
