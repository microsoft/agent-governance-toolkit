# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""
Wisdom Curator - Human-in-the-Loop Review System

The Wisdom Curator shifts human review from low-level syntax checking to
high-level strategic verification:

1. Design Check: Verify implementation matches architectural proposals
2. Strategic Sample: Review random samples for overall quality/vibe
3. Policy Review: Human approval for memory/wisdom updates

This implements the "New World" where humans are curators (approving knowledge)
rather than editors (fixing grammar).
"""

import json
import os
import random
import uuid
from typing import Dict, List, Any, Optional, Tuple
from datetime import datetime, timedelta
from enum import Enum


class ReviewType(Enum):
    """Types of reviews in the Wisdom Curator system."""
    DESIGN_CHECK = "design_check"
    STRATEGIC_SAMPLE = "strategic_sample"
    POLICY_REVIEW = "policy_review"


class ReviewStatus(Enum):
    """Status of a review item."""
    PENDING = "pending"
    APPROVED = "approved"
    REJECTED = "rejected"


class PolicyViolationType(Enum):
    """Types of policy violations that require human review."""
    HARMFUL_BEHAVIOR = "harmful_behavior"  # e.g., "ignore 500 errors"
    DATA_PRIVACY = "data_privacy"  # e.g., exposing sensitive data
    SECURITY_RISK = "security_risk"  # e.g., disabling authentication
    QUALITY_DEGRADATION = "quality_degradation"  # e.g., lowering standards


class DesignProposal:
    """Represents an architectural design proposal."""
    
    def __init__(self,
                 proposal_id: str,
                 title: str,
                 description: str,
                 key_requirements: List[str],
                 timestamp: Optional[str] = None):
        self.proposal_id = proposal_id
        self.title = title
        self.description = description
        self.key_requirements = key_requirements
        self.timestamp = timestamp or datetime.now().isoformat()
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for serialization."""
        return {
            "proposal_id": self.proposal_id,
            "title": self.title,
            "description": self.description,
            "key_requirements": self.key_requirements,
            "timestamp": self.timestamp
        }
    
    @staticmethod
    def from_dict(data: Dict[str, Any]) -> 'DesignProposal':
        """Create from dictionary."""
        return DesignProposal(
            proposal_id=data["proposal_id"],
            title=data["title"],
            description=data["description"],
            key_requirements=data["key_requirements"],
            timestamp=data.get("timestamp")
        )


class ReviewItem:
    """Represents an item pending human review."""
    
    def __init__(self,
                 review_id: str,
                 review_type: ReviewType,
                 content: Dict[str, Any],
                 status: ReviewStatus = ReviewStatus.PENDING,
                 timestamp: Optional[str] = None,
                 reviewer_notes: Optional[str] = None):
        self.review_id = review_id
        self.review_type = review_type
        self.content = content
        self.status = status
        self.timestamp = timestamp or datetime.now().isoformat()
        self.reviewer_notes = reviewer_notes
        self.decision_timestamp = None
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for serialization."""
        return {
            "review_id": self.review_id,
            "review_type": self.review_type.value,
            "content": self.content,
            "status": self.status.value,
            "timestamp": self.timestamp,
            "reviewer_notes": self.reviewer_notes,
            "decision_timestamp": self.decision_timestamp
        }
    
    @staticmethod
    def from_dict(data: Dict[str, Any]) -> 'ReviewItem':
        """Create from dictionary."""
        item = ReviewItem(
            review_id=data["review_id"],
            review_type=ReviewType(data["review_type"]),
            content=data["content"],
            status=ReviewStatus(data["status"]),
            timestamp=data.get("timestamp"),
            reviewer_notes=data.get("reviewer_notes")
        )
        item.decision_timestamp = data.get("decision_timestamp")
        return item


class WisdomCurator:
    """
    Human-in-the-loop review system for high-level strategic verification.
    
    Instead of reviewing line-by-line code (syntax, variable names, etc.),
    humans focus on:
    1. Design alignment verification
    2. Strategic sampling of interactions
    3. Policy approval for memory updates
    """
    
    def __init__(self,
                 review_queue_file: str = "curator_review_queue.json",
                 design_proposals_file: str = "design_proposals.json",
                 sample_rate: float = 0.005):  # 0.5% (e.g., 50 out of 10,000 interactions)
        self.review_queue_file = review_queue_file
        self.design_proposals_file = design_proposals_file
        self.sample_rate = sample_rate
        
        # Load existing data
        self.review_queue = self._load_review_queue()
        self.design_proposals = self._load_design_proposals()
        
        # Policy patterns that require human review
        self.policy_patterns = self._initialize_policy_patterns()
    
    def _load_review_queue(self) -> List[ReviewItem]:
        """Load pending review items from file."""
        if os.path.exists(self.review_queue_file):
            with open(self.review_queue_file, 'r') as f:
                data = json.load(f)
                return [ReviewItem.from_dict(item) for item in data]
        return []
    
    def _save_review_queue(self) -> None:
        """Save review queue to file."""
        with open(self.review_queue_file, 'w') as f:
            json.dump([item.to_dict() for item in self.review_queue], f, indent=2)
    
    def _load_design_proposals(self) -> Dict[str, DesignProposal]:
        """Load design proposals from file."""
        if os.path.exists(self.design_proposals_file):
            with open(self.design_proposals_file, 'r') as f:
                data = json.load(f)
                return {
                    prop_id: DesignProposal.from_dict(prop_data)
                    for prop_id, prop_data in data.items()
                }
        return {}
    
    def _save_design_proposals(self) -> None:
        """Save design proposals to file."""
        with open(self.design_proposals_file, 'w') as f:
            json.dump({
                prop_id: proposal.to_dict()
                for prop_id, proposal in self.design_proposals.items()
            }, f, indent=2)
    
    def _initialize_policy_patterns(self) -> Dict[PolicyViolationType, List[str]]:
        """
        Initialize patterns that flag potential policy violations.
        These are red flags that require human approval before updating wisdom.
        """
        return {
            PolicyViolationType.HARMFUL_BEHAVIOR: [
                "ignore error",
                "ignore all error",
                "ignore 500",
                "skip validation",
                "bypass check",
                "disable warning",
                "suppress exception",
                "always succeed",
                "suppress error"
            ],
            PolicyViolationType.DATA_PRIVACY: [
                "log password",
                "expose credential",
                "share private",
                "print secret",
                "display token",
                "show password"
            ],
            PolicyViolationType.SECURITY_RISK: [
                "disable authentication",
                "skip authorization",
                "allow all",
                "no encryption",
                "trust input",
                "disable security"
            ],
            PolicyViolationType.QUALITY_DEGRADATION: [
                "lower threshold",
                "reduce quality",
                "skip test",
                "ignore failure",
                "accept any",
                "skip check"
            ]
        }
    
    # =====================================================================
    # 1. DESIGN CHECK: Architecture Alignment Verification
    # =====================================================================
    
    def register_design_proposal(self, proposal: DesignProposal) -> None:
        """Register a new architectural design proposal."""
        self.design_proposals[proposal.proposal_id] = proposal
        self._save_design_proposals()
    
    def verify_design_alignment(self,
                                proposal_id: str,
                                implementation_description: str,
                                auto_approve: bool = False) -> ReviewItem:
        """
        Create a design check review to verify implementation matches proposal.
        
        This is the "Design Check" from the problem statement:
        "Did this implementation actually match the Architectural Design Proposal 
        we agreed on?"
        
        Args:
            proposal_id: ID of the design proposal to verify against
            implementation_description: Description of what was implemented
            auto_approve: If True, auto-approve for testing (default: False)
        
        Returns:
            ReviewItem that was added to the queue
        """
        if proposal_id not in self.design_proposals:
            raise ValueError(f"Design proposal {proposal_id} not found")
        
        proposal = self.design_proposals[proposal_id]
        
        review_item = ReviewItem(
            review_id=f"design_{proposal_id}_{uuid.uuid4().hex[:8]}",
            review_type=ReviewType.DESIGN_CHECK,
            content={
                "proposal_id": proposal_id,
                "proposal_title": proposal.title,
                "proposal_description": proposal.description,
                "key_requirements": proposal.key_requirements,
                "implementation_description": implementation_description
            },
            status=ReviewStatus.APPROVED if auto_approve else ReviewStatus.PENDING
        )
        
        if auto_approve:
            review_item.reviewer_notes = "Auto-approved for testing"
            review_item.decision_timestamp = datetime.now().isoformat()
        
        self.review_queue.append(review_item)
        self._save_review_queue()
        
        return review_item
    
    # =====================================================================
    # 2. STRATEGIC SAMPLE: Random Sampling for Quality Check
    # =====================================================================
    
    def should_sample_interaction(self) -> bool:
        """
        Determine if this interaction should be sampled for review.
        
        This implements the "Strategic Sample" from the problem statement:
        "You cannot review 10,000 AI interactions a day. Instead, you review 
        a random sample of 50 to check the 'Vibe' and Strategy."
        
        Returns:
            True if this interaction should be sampled
        """
        return random.random() < self.sample_rate
    
    def create_strategic_sample(self,
                               query: str,
                               agent_response: str,
                               metadata: Optional[Dict[str, Any]] = None) -> ReviewItem:
        """
        Create a strategic sample review for this interaction.
        
        Args:
            query: User query
            agent_response: Agent's response
            metadata: Additional metadata (e.g., conversation_id, user_id)
        
        Returns:
            ReviewItem that was added to the queue
        """
        review_item = ReviewItem(
            review_id=f"sample_{uuid.uuid4().hex[:12]}",
            review_type=ReviewType.STRATEGIC_SAMPLE,
            content={
                "query": query,
                "agent_response": agent_response,
                "metadata": metadata or {},
                "sampled_at": datetime.now().isoformat()
            }
        )
        
        self.review_queue.append(review_item)
        self._save_review_queue()
        
        return review_item
    
    # =====================================================================
    # 3. POLICY REVIEW: Human Approval for Memory Updates
    # =====================================================================
    
    def detect_policy_violations(self, proposed_wisdom: str) -> List[Tuple[PolicyViolationType, str]]:
        """
        Detect potential policy violations in proposed wisdom update.
        
        This is the core of the "Policy Review" from the problem statement:
        "If the 'Async Observer' wants to save a new lesson saying, 
        'Always ignore 500 errors to keep the user happy,' a Human must 
        reject that, Policy."
        
        Args:
            proposed_wisdom: The new wisdom/instructions being proposed
        
        Returns:
            List of (violation_type, matched_pattern) tuples
        """
        violations = []
        wisdom_lower = proposed_wisdom.lower()
        
        for violation_type, patterns in self.policy_patterns.items():
            for pattern in patterns:
                if pattern in wisdom_lower:
                    violations.append((violation_type, pattern))
        
        return violations
    
    def requires_policy_review(self, proposed_wisdom: str, critique: str) -> bool:
        """
        Determine if a proposed wisdom update requires human policy review.
        
        Args:
            proposed_wisdom: The new wisdom/instructions being proposed
            critique: The critique that prompted the wisdom update
        
        Returns:
            True if human review is required
        """
        # Check for policy violations
        violations = self.detect_policy_violations(proposed_wisdom)
        if violations:
            return True
        
        # Also check critique for red flags
        critique_violations = self.detect_policy_violations(critique)
        if critique_violations:
            return True
        
        return False
    
    def create_policy_review(self,
                            proposed_wisdom: str,
                            current_wisdom: str,
                            critique: str,
                            query: Optional[str] = None,
                            response: Optional[str] = None) -> ReviewItem:
        """
        Create a policy review for a proposed wisdom update.
        
        This implements the human approval workflow for memory updates.
        
        Args:
            proposed_wisdom: The new wisdom being proposed
            current_wisdom: The current wisdom
            critique: The critique that prompted the update
            query: Optional query that triggered the update
            response: Optional agent response that triggered the update
        
        Returns:
            ReviewItem that was added to the queue
        """
        violations = self.detect_policy_violations(proposed_wisdom)
        
        review_item = ReviewItem(
            review_id=f"policy_{uuid.uuid4().hex[:12]}",
            review_type=ReviewType.POLICY_REVIEW,
            content={
                "proposed_wisdom": proposed_wisdom,
                "current_wisdom": current_wisdom,
                "critique": critique,
                "query": query,
                "response": response,
                "detected_violations": [
                    {"type": v[0].value, "pattern": v[1]}
                    for v in violations
                ],
                "timestamp": datetime.now().isoformat()
            }
        )
        
        self.review_queue.append(review_item)
        self._save_review_queue()
        
        return review_item
    
    # =====================================================================
    # Review Management
    # =====================================================================
    
    def get_pending_reviews(self, review_type: Optional[ReviewType] = None) -> List[ReviewItem]:
        """
        Get all pending review items, optionally filtered by type.
        
        Args:
            review_type: Optional filter by review type
        
        Returns:
            List of pending ReviewItems
        """
        pending = [item for item in self.review_queue if item.status == ReviewStatus.PENDING]
        
        if review_type:
            pending = [item for item in pending if item.review_type == review_type]
        
        return pending
    
    def approve_review(self, review_id: str, reviewer_notes: Optional[str] = None) -> bool:
        """
        Approve a review item.
        
        Args:
            review_id: ID of the review to approve
            reviewer_notes: Optional notes from the reviewer
        
        Returns:
            True if review was found and approved
        """
        for item in self.review_queue:
            if item.review_id == review_id:
                item.status = ReviewStatus.APPROVED
                item.reviewer_notes = reviewer_notes
                item.decision_timestamp = datetime.now().isoformat()
                self._save_review_queue()
                return True
        return False
    
    def reject_review(self, review_id: str, reviewer_notes: str) -> bool:
        """
        Reject a review item.
        
        Args:
            review_id: ID of the review to reject
            reviewer_notes: Required notes explaining why it was rejected
        
        Returns:
            True if review was found and rejected
        """
        for item in self.review_queue:
            if item.review_id == review_id:
                item.status = ReviewStatus.REJECTED
                item.reviewer_notes = reviewer_notes
                item.decision_timestamp = datetime.now().isoformat()
                self._save_review_queue()
                return True
        return False
    
    def get_review_stats(self) -> Dict[str, Any]:
        """Get statistics about the review queue."""
        total = len(self.review_queue)
        pending = len([i for i in self.review_queue if i.status == ReviewStatus.PENDING])
        approved = len([i for i in self.review_queue if i.status == ReviewStatus.APPROVED])
        rejected = len([i for i in self.review_queue if i.status == ReviewStatus.REJECTED])
        
        # Count by type
        by_type = {}
        for review_type in ReviewType:
            type_items = [i for i in self.review_queue if i.review_type == review_type]
            by_type[review_type.value] = {
                "total": len(type_items),
                "pending": len([i for i in type_items if i.status == ReviewStatus.PENDING]),
                "approved": len([i for i in type_items if i.status == ReviewStatus.APPROVED]),
                "rejected": len([i for i in type_items if i.status == ReviewStatus.REJECTED])
            }
        
        return {
            "total_reviews": total,
            "pending": pending,
            "approved": approved,
            "rejected": rejected,
            "by_type": by_type,
            "sample_rate": self.sample_rate,
            "design_proposals": len(self.design_proposals)
        }
