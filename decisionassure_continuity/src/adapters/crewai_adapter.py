from typing import List, Dict, Any
from src.models import AgentAction
from src.adapters.base_adapter import BaseTraceAdapter

class CrewAIAdapter(BaseTraceAdapter):
    """
    Adapter for CrewAI traces.
    Expects a trace with a list of 'tasks' and 'agents'.
    """

    def __init__(self):
        super().__init__()
        self.framework_name = "crewai"

    def parse(self, trace: Dict[str, Any]) -> List[AgentAction]:
        actions = []
        tasks = trace.get("tasks", [])
        for task in tasks:
            agent_id = task.get("agent", "unknown")
            action_type = task.get("action", "unknown")
            tool = task.get("tool", None)
            params = task.get("params", {})
            actions.append(AgentAction(
                agent_id=agent_id,
                action_type=action_type,
                tool=tool,
                params=params
            ))
        return actions

    def get_agent_ids(self, trace: Dict[str, Any]) -> List[str]:
        agents = set()
        for task in trace.get("tasks", []):
            if "agent" in task:
                agents.add(task["agent"])
        return list(agents)