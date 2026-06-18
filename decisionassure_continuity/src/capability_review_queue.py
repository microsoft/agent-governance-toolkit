"""
Capability Review Queue – Manages the review of unknown capabilities and ontology evolution.
"""

import json
import os
from datetime import datetime
from typing import List, Dict, Any, Optional
from dataclasses import dataclass, asdict
from enum import Enum

class ReviewStatus(Enum):
    PENDING = "pending"
    APPROVED = "approved"
    REJECTED = "rejected"
    DEFERRED = "deferred"

@dataclass
class ReviewItem:
    capability_id: str
    capability_name: str
    required_actions: List[Dict[str, str]]
    first_seen: str
    status: ReviewStatus
    reviewer: Optional[str] = None
    reasoning: Optional[str] = None
    reviewed_at: Optional[str] = None
    evidence_hash: Optional[str] = None

@dataclass
class OntologyChange:
    version: int
    timestamp: str
    action: str  # "add", "update", "remove"
    capability_id: str
    capability_name: str
    required_actions: List[Dict[str, str]]
    reviewer: str
    reasoning: str
    previous_state: Optional[Dict[str, Any]] = None

class CapabilityReviewQueue:
    def __init__(self, data_dir: str = "data"):
        self.data_dir = data_dir
        os.makedirs(data_dir, exist_ok=True)
        self.review_file = os.path.join(data_dir, "review_queue.json")
        self.ledger_file = os.path.join(data_dir, "ontology_ledger.json")
        self._load_data()

    def _load_data(self):
        self.review_queue: List[ReviewItem] = []
        self.ledger: List[OntologyChange] = []
        self.current_version = 0

        if os.path.exists(self.review_file):
            with open(self.review_file, 'r') as f:
                data = json.load(f)
                self.review_queue = [ReviewItem(**item) for item in data]

        if os.path.exists(self.ledger_file):
            with open(self.ledger_file, 'r') as f:
                data = json.load(f)
                self.ledger = [OntologyChange(**item) for item in data]
                if self.ledger:
                    self.current_version = max(c.version for c in self.ledger)

    def _save_review_queue(self):
        with open(self.review_file, 'w') as f:
            json.dump([asdict(item) for item in self.review_queue], f, indent=2, default=str)

    def _save_ledger(self):
        with open(self.ledger_file, 'w') as f:
            json.dump([asdict(item) for item in self.ledger], f, indent=2, default=str)

    def add_for_review(self, capability_id: str, capability_name: str,
                       required_actions: List[Dict[str, str]],
                       evidence_hash: Optional[str] = None) -> ReviewItem:
        """Add an unknown capability to the review queue."""
        # Check if already pending
        existing = [r for r in self.review_queue if r.capability_id == capability_id and r.status == ReviewStatus.PENDING]
        if existing:
            return existing[0]

        item = ReviewItem(
            capability_id=capability_id,
            capability_name=capability_name,
            required_actions=required_actions,
            first_seen=datetime.now().isoformat(),
            status=ReviewStatus.PENDING,
            evidence_hash=evidence_hash
        )
        self.review_queue.append(item)
        self._save_review_queue()
        return item

    def approve_review(self, capability_id: str, reviewer: str,
                       reasoning: str, capability_name: str,
                       required_actions: List[Dict[str, str]]) -> bool:
        """Approve a review item and add it to the ontology."""
        for item in self.review_queue:
            if item.capability_id == capability_id and item.status == ReviewStatus.PENDING:
                item.status = ReviewStatus.APPROVED
                item.reviewer = reviewer
                item.reasoning = reasoning
                item.reviewed_at = datetime.now().isoformat()

                # Add to ontology ledger
                self.current_version += 1
                change = OntologyChange(
                    version=self.current_version,
                    timestamp=datetime.now().isoformat(),
                    action="add",
                    capability_id=capability_id,
                    capability_name=capability_name,
                    required_actions=required_actions,
                    reviewer=reviewer,
                    reasoning=reasoning,
                    previous_state=None
                )
                self.ledger.append(change)
                self._save_review_queue()
                self._save_ledger()

                # ===== NEW: Export evolved ontology and reload global ontology =====
                self.export_ontology("evolved_ontology.json")
                # Reload the global ontology so subsequent calls see it
                from src.capability_ontology import load_ontology_from_file
                # Since DEFAULT_ONTOLOGY is a module-level variable, we need to reload it
                # We'll use a simple approach: directly assign to the module
                import src.capability_ontology as cap_ontology
                cap_ontology.DEFAULT_ONTOLOGY = load_ontology_from_file("evolved_ontology.json")
                print(f"   🔄 Global ontology reloaded with new capability: {capability_name}")
                # ===== END NEW =====

                return True
        return False

    def reject_review(self, capability_id: str, reviewer: str,
                      reasoning: str) -> bool:
        """Reject a review item."""
        for item in self.review_queue:
            if item.capability_id == capability_id and item.status == ReviewStatus.PENDING:
                item.status = ReviewStatus.REJECTED
                item.reviewer = reviewer
                item.reasoning = reasoning
                item.reviewed_at = datetime.now().isoformat()
                self._save_review_queue()
                return True
        return False

    def get_pending_reviews(self) -> List[ReviewItem]:
        """Get all pending review items."""
        return [r for r in self.review_queue if r.status == ReviewStatus.PENDING]

    def get_approved_reviews(self) -> List[ReviewItem]:
        """Get all approved review items."""
        return [r for r in self.review_queue if r.status == ReviewStatus.APPROVED]

    def get_ledger_entries(self) -> List[OntologyChange]:
        """Get all ontology ledger entries."""
        return self.ledger

    def export_ontology(self, output_file: str = "evolved_ontology.json") -> None:
        """Export the evolved ontology from the ledger."""
        patterns = []
        for change in self.ledger:
            if change.action == "add":
                patterns.append({
                    "capability_id": change.capability_id,
                    "name": change.capability_name,
                    "description": f"Added via review by {change.reviewer}",
                    "severity": "critical",
                    "required_actions": [a["action"] for a in change.required_actions],
                    "min_agents": len(change.required_actions),
                    "max_agents": len(change.required_actions),
                    "version_added": change.version,
                    "timestamp": change.timestamp
                })
            elif change.action == "update":
                # For simplicity, we skip updates in this version
                pass
        with open(output_file, 'w') as f:
            json.dump({"patterns": patterns}, f, indent=2)
        print(f"✅ Evolved ontology exported to {output_file}")