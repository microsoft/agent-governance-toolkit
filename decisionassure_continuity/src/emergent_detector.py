from typing import List, Dict, Any, Set
from collections import defaultdict
from src.models import (
    AgentAction, EmergentCapability, EmergentCapabilityResult,
    CapabilityContribution, CapabilityLineage
)
from src.capability_witness import CapabilityWitnessEngine  # NEW import

# Updated rules with contribution mapping
CAPABILITY_RULES = [
    {
        "capability_id": "credential_exfiltration",
        "name": "Credential Exfiltration",
        "description": "Agents collectively gather and export credentials",
        "severity": "critical",
        "required_actions": ["read_database", "read_credentials", "export_data"],
        "contribution_map": {
            "read_database": "discovery",
            "read_credentials": "aggregation",
            "export_data": "export"
        }
    },
    {
        "capability_id": "system_compromise",
        "name": "System Compromise",
        "description": "Agents collectively escalate privileges and modify system",
        "severity": "critical",
        "required_actions": ["grant_permission", "write_config", "delete_logs"],
        "contribution_map": {
            "grant_permission": "escalation",
            "write_config": "modification",
            "delete_logs": "destruction"
        }
    },
    {
        "capability_id": "data_manipulation",
        "name": "Coordinated Data Manipulation",
        "description": "Agents read, modify, and delete data across sources",
        "severity": "high",
        "required_actions": ["read_database", "write_database", "delete_records"],
        "contribution_map": {
            "read_database": "discovery",
            "write_database": "modification",
            "delete_records": "destruction"
        }
    }
]

class EmergentDetector:
    def __init__(self, rules: List[Dict[str, Any]] = None):
        self.rules = rules or CAPABILITY_RULES
        self.capabilities = [EmergentCapability(**r) for r in self.rules]
        self.contribution_maps = {r["capability_id"]: r.get("contribution_map", {}) for r in self.rules}
        self.witness_engine = CapabilityWitnessEngine()  # NEW: instantiate witness engine
    def discover_from_traces(self, traces: List[List[AgentAction]]) -> List[Dict[str, Any]]:
       """
       Discover emergent capabilities from a corpus of traces.
       This is the unsupervised capability discovery method.
       """
       from src.capability_discovery import CapabilityDiscovery
       discovery = CapabilityDiscovery(min_samples=3, eps=0.5)
       results = discovery.discover(traces)
       return results

    def detect(self, actions: List[AgentAction]) -> List[EmergentCapabilityResult]:
        results = []
        agent_actions: Dict[str, Set[str]] = defaultdict(set)
        action_objects: Dict[str, List[AgentAction]] = defaultdict(list)

        for act in actions:
            agent_actions[act.agent_id].add(act.action_type)
            action_objects[act.agent_id].append(act)

        for cap in self.capabilities:
            required = set(cap.required_actions)
            all_present = set().union(*agent_actions.values())
            if required.issubset(all_present):
                # Build contributions
                contributions = []
                for agent, acts in action_objects.items():
                    for act in acts:
                        if act.action_type in required:
                            contribution_type = self.contribution_maps.get(cap.capability_id, {}).get(act.action_type, "unknown")
                            contributions.append(CapabilityContribution(
                                agent=agent,
                                contribution_type=contribution_type,
                                action=act.action_type,
                                evidence={"tool": act.tool, "params": act.params}
                            ))

                # Create lineage
                lineage = CapabilityLineage(
                    capability_id=cap.capability_id,
                    capability_name=cap.name,
                    contributions=contributions
                )
                lineage.lineage_hash = lineage.compute_lineage_hash()

                # NEW: Generate a Capability Witness for this detection
                witness = self.witness_engine.generate_witness(actions)
                if witness:
                    lineage.witness = witness  # attach witness to lineage

                # Aggregate contributing agents
                contributing_agents = list(set(c.agent for c in contributions))
                involved_actions = [act for acts in action_objects.values() for act in acts if act.action_type in required]
                confidence = len(required.intersection(all_present)) / len(required)

                results.append(EmergentCapabilityResult(
                    capability_detected=True,
                    capability=cap,
                    contributing_agents=contributing_agents,
                    actions_involved=involved_actions,
                    confidence=confidence,
                    evidence={
                        "required": list(required),
                        "present": list(all_present),
                        "agent_contributions": {a: list(s) for a, s in agent_actions.items()}
                    },
                    lineage=lineage
                ))

        if not results:
            results.append(EmergentCapabilityResult(
                capability_detected=False,
                capability=None,
                contributing_agents=[],
                actions_involved=[],
                confidence=0.0,
                evidence={"reason": "No rule matched"},
                lineage=None
            ))
        return results