from typing import List, Dict, Any
from src.models import AgentAction
from src.adapters.base_adapter import BaseTraceAdapter

class AutoGenAdapter(BaseTraceAdapter):
    def __init__(self):
        super().__init__()
        self.framework_name = "autogen"

    def parse(self, trace: Dict[str, Any]) -> List[AgentAction]:
        actions = []
        messages = trace.get("messages", [])
        for msg in messages:
            sender = msg.get("sender", "unknown")
            tool_calls = msg.get("tool_calls", [])
            if tool_calls:
                for tc in tool_calls:
                    actions.append(AgentAction(
                        agent_id=sender,
                        action_type=tc.get("name", "unknown_tool"),
                        tool=tc.get("name", "unknown"),
                        params=tc.get("arguments", {})
                    ))
            else:
                actions.append(AgentAction(
                    agent_id=sender,
                    action_type="send_message",
                    params={"content": msg.get("content", "")}
                ))
        return actions

    def get_agent_ids(self, trace: Dict[str, Any]) -> List[str]:
        agents = set()
        for msg in trace.get("messages", []):
            if "sender" in msg:
                agents.add(msg["sender"])
            if "receiver" in msg:
                agents.add(msg["receiver"])
        return list(agents)