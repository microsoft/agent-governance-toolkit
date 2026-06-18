"""
Base adapter for converting agent framework traces to AgentAction lists.
"""

from typing import List, Dict, Any
from src.models import AgentAction

class BaseTraceAdapter:
    """Base class for framework-specific trace adapters."""

    def __init__(self):
        self.framework_name = "base"

    def parse(self, trace: Dict[str, Any]) -> List[AgentAction]:
        """
        Parse a trace from the framework into a list of AgentActions.
        Must be implemented by subclasses.
        """
        raise NotImplementedError("Subclasses must implement parse()")

    def get_agent_ids(self, trace: Dict[str, Any]) -> List[str]:
        """Extract agent IDs from the trace."""
        raise NotImplementedError("Subclasses must implement get_agent_ids()")