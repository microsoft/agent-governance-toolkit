from typing import List, Dict, Any
from src.models import AgentAction
from src.adapters.base_adapter import BaseTraceAdapter

class AgentTrustAdapter(BaseTraceAdapter):
    """
    Adapter for Microsoft AgentTrust traces.
    Expects a trace with 'steps' containing agent actions and tool calls.
    """

    def __init__(self):
        super().__init__()
        self.framework_name = "agenttrust"

    def parse(self, trace: Dict[str, Any]) -> List[AgentAction]:
        actions = []
        steps = trace.get("steps", [])
        for step in steps:
            agent_id = step.get("agent_id") or step.get("observer_id", "unknown")
            tool_calls = step.get("tool_calls", [])
            if tool_calls:
                for tc in tool_calls:
                    actions.append(AgentAction(
                        agent_id=agent_id,
                        action_type=tc.get("name", "unknown_tool"),
                        tool=tc.get("name", "unknown"),
                        params=tc.get("args", {})
                    ))
            else:
                action_type = step.get("step_name", "unknown_step")
                actions.append(AgentAction(
                    agent_id=agent_id,
                    action_type=action_type,
                    params=step.get("metadata", {})
                ))
        return actions

    def get_agent_ids(self, trace: Dict[str, Any]) -> List[str]:
        agents = set()
        for step in trace.get("steps", []):
            if "agent_id" in step:
                agents.add(step["agent_id"])
            if "observer_id" in step:
                agents.add(step["observer_id"])
        return list(agents)