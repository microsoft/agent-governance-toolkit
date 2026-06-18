from typing import List, Dict, Any
from src.models import AgentAction
from src.adapters.base_adapter import BaseTraceAdapter

class LangGraphAdapter(BaseTraceAdapter):
    """
    Adapter for LangGraph traces.
    Expects a trace with 'steps' or 'nodes' and 'edges'.
    """

    def __init__(self):
        super().__init__()
        self.framework_name = "langgraph"

    def parse(self, trace: Dict[str, Any]) -> List[AgentAction]:
        actions = []
        # LangGraph traces often have 'nodes' with agent actions
        nodes = trace.get("nodes", [])
        for node in nodes:
            agent_id = node.get("agent_id", "unknown")
            action_type = node.get("action", "unknown")
            tool = node.get("tool", None)
            params = node.get("params", {})
            actions.append(AgentAction(
                agent_id=agent_id,
                action_type=action_type,
                tool=tool,
                params=params
            ))
        return actions

    def get_agent_ids(self, trace: Dict[str, Any]) -> List[str]:
        agents = set()
        for node in trace.get("nodes", []):
            if "agent_id" in node:
                agents.add(node["agent_id"])
        return list(agents)