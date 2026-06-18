"""
Impact Scorer – Computes the historical impact of a capability.
"""

from typing import List, Dict, Any, Set
from src.models import AgentAction

class ImpactScorer:
    def __init__(self, traces: List[List[AgentAction]]):
        self.traces = traces

    def compute_impact(self, required_actions: List[Dict[str, str]]) -> int:
        """
        Count how many traces contain the exact set of required actions.
        """
        action_set = {(a["agent"], a["action"]) for a in required_actions}
        count = 0
        for trace in self.traces:
            trace_set = {(act.agent_id, act.action_type) for act in trace}
            if action_set.issubset(trace_set):
                count += 1
        return count