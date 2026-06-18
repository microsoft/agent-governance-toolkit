"""
Capability Classifier – Maps discovered action patterns to known capability types.
"""

from typing import List, Dict, Any, Set, Optional
from src.models import AgentAction

# Knowledge base: mapping from action sets to capability types
CAPABILITY_KNOWLEDGE = {
    "credential_exfiltration": {
        "actions": {"read_database", "read_credentials", "export_data"},
        "name": "Credential Exfiltration",
        "severity": "critical",
        "description": "Agents collectively gather and export credentials"
    },
    "privilege_escalation": {
        "actions": {"grant_permission", "write_config", "delete_logs"},
        "name": "Privilege Escalation",
        "severity": "critical",
        "description": "Agents escalate privileges and cover tracks"
    },
    "data_manipulation": {
        "actions": {"read_database", "write_database", "delete_records"},
        "name": "Data Manipulation",
        "severity": "high",
        "description": "Agents read, modify, and delete data across sources"
    },
    "persistence": {
        "actions": {"write_config", "schedule_task", "modify_registry"},
        "name": "Persistence",
        "severity": "medium",
        "description": "Agents establish persistence mechanisms"
    },
    "data_exfiltration": {
        "actions": {"read_database", "read_files", "export_data", "upload_file"},
        "name": "Data Exfiltration",
        "severity": "high",
        "description": "Agents collectively exfiltrate data"
    }
}

class CapabilityClassifier:
    """
    Classifies action patterns into known capability types.
    Uses set similarity and threshold-based matching.
    """

    def __init__(self, knowledge: Dict[str, Any] = None, threshold: float = 0.6):
        self.knowledge = knowledge or CAPABILITY_KNOWLEDGE
        self.threshold = threshold

    def classify(self, actions: List[Dict[str, str]]) -> Dict[str, Any]:
        """
        Classify a set of required actions.
        Returns a dict with classification details.
        """
        action_set = set((a["agent"], a["action"]) for a in actions)
        action_types = {a["action"] for a in actions}

        best_match = None
        best_score = 0.0

        for cap_id, cap_def in self.knowledge.items():
            required = cap_def["actions"]
            # Compute Jaccard similarity between action types and required set
            intersection = action_types.intersection(required)
            union = action_types.union(required)
            score = len(intersection) / len(union) if union else 0.0

            # Also check if all required actions are present (higher score)
            if required.issubset(action_types):
                # Perfect match: all required actions present
                score = 1.0
            elif score >= self.threshold and score > best_score:
                best_match = cap_id
                best_score = score

        if best_match and best_score >= self.threshold:
            cap_def = self.knowledge[best_match]
            return {
                "classification": best_match,
                "name": cap_def["name"],
                "severity": cap_def["severity"],
                "description": cap_def["description"],
                "confidence": best_score,
                "matched_actions": list(intersection),
                "required_actions": list(required)
            }
        else:
            # Unknown capability: return the pattern as is
            return {
                "classification": "unknown",
                "name": "Unknown Capability",
                "severity": "unknown",
                "description": "No known classification matched",
                "confidence": 0.0,
                "matched_actions": [],
                "required_actions": [a["action"] for a in actions]
            }

    def classify_batch(self, patterns: List[List[Dict[str, str]]]) -> List[Dict[str, Any]]:
        """Classify multiple patterns."""
        return [self.classify(p) for p in patterns]