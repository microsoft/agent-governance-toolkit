from typing import List, Dict, Any
from src.models import AgentAction
from src.adapters.base_adapter import BaseTraceAdapter

class OpenAIAdapter(BaseTraceAdapter):
    """
    Adapter for OpenAI Agents SDK traces.
    Expects a trace with 'steps' or 'tool_calls'.
    """

    def __init__(self):
        super().__init__()
        self.framework_name = "openai"

    def parse(self, trace: Dict[str, Any]) -> List[AgentAction]:
        actions = []
        steps = trace.get("steps", [])
        for step in steps:
            agent_id = step.get("agent_id", "unknown")
            tool_calls = step.get("tool_calls", [])
            for tc in tool_calls:
                actions.append(AgentAction(
                    agent_id=agent_id,
                    action_type=tc.get("name", "unknown_tool"),
                    tool=tc.get("name", "unknown"),
                    params=tc.get("arguments", {})
                ))
        return actions

    def get_agent_ids(self, trace: Dict[str, Any]) -> List[str]:
        agents = set()
        for step in trace.get("steps", []):
            if "agent_id" in step:
                agents.add(step["agent_id"])
        return list(agents)