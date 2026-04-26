# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""
LangChain Client Adapter - Drop-In Middleware for Agent Control Plane

This adapter wraps LangChain clients to automatically intercept and govern
tool calls made by LangChain agents. It provides similar integration as the 
OpenAI adapter, but for LangChain's framework.

Usage:
    from langchain.chat_models import ChatOpenAI
    from agent_control_plane import AgentControlPlane
    from agent_control_plane.langchain_adapter import LangChainAdapter
    
    # Standard setup
    llm = ChatOpenAI(temperature=0)
    control_plane = AgentControlPlane()
    agent_context = control_plane.create_agent("my-agent", permissions)
    
    # Wrap with adapter
    governed_llm = LangChainAdapter(
        control_plane=control_plane,
        agent_context=agent_context,
        langchain_client=llm
    )
    
    # Use in LangChain agents
    from langchain.agents import initialize_agent
    agent = initialize_agent(tools, governed_llm, agent="zero-shot-react-description")
    agent.run("Your task here")
    # Tool calls are automatically governed by the control plane!
"""

from typing import Any, Dict, List, Optional, Callable, Sequence
import json
import logging
from datetime import datetime

from .agent_kernel import ActionType, AgentContext
from .control_plane import AgentControlPlane


# Mapping from common LangChain tool names to ActionType
DEFAULT_LANGCHAIN_TOOL_MAPPING = {
    # File operations
    "read_file": ActionType.FILE_READ,
    "write_file": ActionType.FILE_WRITE,
    "file_read": ActionType.FILE_READ,
    "file_write": ActionType.FILE_WRITE,
    "readfile": ActionType.FILE_READ,
    "writefile": ActionType.FILE_WRITE,
    
    # Code execution
    "python_repl": ActionType.CODE_EXECUTION,
    "python": ActionType.CODE_EXECUTION,
    "terminal": ActionType.CODE_EXECUTION,
    "shell": ActionType.CODE_EXECUTION,
    "bash": ActionType.CODE_EXECUTION,
    
    # Database operations
    "sql_db_query": ActionType.DATABASE_QUERY,
    "sql_db_schema": ActionType.DATABASE_QUERY,
    "sql_db_list_tables": ActionType.DATABASE_QUERY,
    "sql_db_query_checker": ActionType.DATABASE_QUERY,
    
    # API calls
    "requests_get": ActionType.API_CALL,
    "requests_post": ActionType.API_CALL,
    "requests": ActionType.API_CALL,
    "api_request": ActionType.API_CALL,
    
    # Search and retrieval
    "google_search": ActionType.API_CALL,
    "serpapi": ActionType.API_CALL,
    "wikipedia": ActionType.API_CALL,
}


class LangChainAdapter:
    """
    LangChain Client Adapter with Agent Control Plane Governance.
    
    This class wraps a LangChain LLM or agent to provide automatic governance
    of tool calls. It intercepts tool invocations and checks them against the
    control plane's policies before allowing execution.
    
    The adapter works by wrapping the tool execution layer, similar to how
    the OpenAI adapter wraps chat completions.
    
    Example:
        # Before (ungoverned):
        from langchain.chat_models import ChatOpenAI
        llm = ChatOpenAI()
        agent = initialize_agent(tools, llm, agent="zero-shot-react-description")
        
        # After (governed):
        governed_llm = LangChainAdapter(control_plane, agent_context, llm)
        agent = initialize_agent(tools, governed_llm, agent="zero-shot-react-description")
        # Same API, but now with governance!
    """
    
    def __init__(
        self,
        control_plane: AgentControlPlane,
        agent_context: AgentContext,
        langchain_client: Any,
        tool_mapping: Optional[Dict[str, ActionType]] = None,
        on_block: Optional[Callable[[str, Dict, Dict], None]] = None,
        logger: Optional[logging.Logger] = None
    ):
        """
        Initialize the LangChain adapter.
        
        Args:
            control_plane: The AgentControlPlane instance for governance
            agent_context: The AgentContext for the agent using this client
            langchain_client: The original LangChain LLM or agent instance
            tool_mapping: Optional custom mapping from tool names to ActionTypes
            on_block: Optional callback called when an action is blocked
                      Signature: on_block(tool_name: str, tool_args: dict, result: dict)
            logger: Optional logger instance
        """
        self.control_plane = control_plane
        self.agent_context = agent_context
        self.client = langchain_client
        self.logger = logger or logging.getLogger("LangChainAdapter")
        self.on_block = on_block
        
        # Merge default mapping with custom mapping
        self.tool_mapping = DEFAULT_LANGCHAIN_TOOL_MAPPING.copy()
        if tool_mapping:
            self.tool_mapping.update({k.lower(): v for k, v in tool_mapping.items()})
        
        # Store original methods to wrap
        self._original_call = None
        self._original_generate = None
        self._original_invoke = None
        
        # Wrap the client methods
        self._wrap_client()
        
        self.logger.info(
            f"Initialized LangChainAdapter for agent {agent_context.agent_id}"
        )
    
    def _wrap_client(self):
        """Wrap the LangChain client's methods to intercept tool calls."""
        # LangChain uses different methods depending on the version
        # We wrap common invocation methods
        
        if hasattr(self.client, '__call__'):
            self._original_call = self.client.__call__
            self.client.__call__ = self._governed_call
        
        if hasattr(self.client, 'generate'):
            self._original_generate = self.client.generate
            self.client.generate = self._governed_generate
        
        if hasattr(self.client, 'invoke'):
            self._original_invoke = self.client.invoke
            self.client.invoke = self._governed_invoke
    
    def _governed_call(self, *args, **kwargs):
        """Wrapped __call__ method with governance."""
        return self._execute_with_governance(self._original_call, *args, **kwargs)
    
    def _governed_generate(self, *args, **kwargs):
        """Wrapped generate method with governance."""
        return self._execute_with_governance(self._original_generate, *args, **kwargs)
    
    def _governed_invoke(self, *args, **kwargs):
        """Wrapped invoke method with governance."""
        return self._execute_with_governance(self._original_invoke, *args, **kwargs)
    
    def _execute_with_governance(self, original_method, *args, **kwargs):
        """
        Execute the original method while intercepting tool calls.
        
        This is the core governance logic that checks tool calls against
        the control plane before allowing execution.
        """
        # Call the original method
        result = original_method(*args, **kwargs)
        
        # Check if the result contains tool calls or actions
        # LangChain formats vary, so we handle multiple formats
        tool_calls = self._extract_tool_calls(result)
        
        if tool_calls:
            self.logger.info(
                f"Agent {self.agent_context.agent_id}: Intercepting {len(tool_calls)} tool call(s)"
            )
            
            # Check each tool call
            for tool_call in tool_calls:
                self._check_tool_call(tool_call)
        
        return result
    
    def _extract_tool_calls(self, result: Any) -> List[Dict]:
        """
        Extract tool calls from LangChain result.
        
        LangChain can return results in various formats depending on the
        agent type and version. This method handles common formats.
        """
        tool_calls = []
        
        # Handle AIMessage format (newer LangChain versions)
        if hasattr(result, 'tool_calls') and result.tool_calls:
            for tc in result.tool_calls:
                tool_calls.append({
                    'name': tc.get('name', ''),
                    'args': tc.get('args', {}),
                    'id': tc.get('id', '')
                })
        
        # Handle additional_kwargs format
        elif hasattr(result, 'additional_kwargs') and 'tool_calls' in result.additional_kwargs:
            for tc in result.additional_kwargs['tool_calls']:
                if isinstance(tc, dict):
                    tool_calls.append({
                        'name': tc.get('name', tc.get('function', {}).get('name', '')),
                        'args': tc.get('args', tc.get('function', {}).get('arguments', {})),
                        'id': tc.get('id', '')
                    })
        
        # Handle list of generations
        elif isinstance(result, list):
            for item in result:
                if hasattr(item, 'message'):
                    tool_calls.extend(self._extract_tool_calls(item.message))
        
        return tool_calls
    
    def _check_tool_call(self, tool_call: Dict):
        """
        Check a single tool call against the control plane.
        
        Args:
            tool_call: Dictionary with 'name', 'args', and optionally 'id'
        """
        tool_name = tool_call.get('name', '')
        tool_args = tool_call.get('args', {})
        
        # Parse arguments if they're a JSON string
        if isinstance(tool_args, str):
            try:
                tool_args = json.loads(tool_args)
            except json.JSONDecodeError:
                self.logger.warning(
                    f"Could not parse arguments for tool '{tool_name}': {tool_args}"
                )
                tool_args = {}
        
        # Map tool name to ActionType
        action_type = self._map_tool_to_action(tool_name)
        
        if action_type is None:
            # Security: Unknown tools are denied by default
            self.logger.warning(f"Unknown tool '{tool_name}', denying by default")
            raise PermissionError(f"Unknown tool: {tool_name}. Tool must be mapped to an ActionType.")
        
        # THE KERNEL CHECK - This is where governance happens
        self.logger.debug(f"Checking permission for {tool_name} -> {action_type.value}")
        
        # Check permission through control plane
        check_result = self.control_plane.execute_action(
            self.agent_context,
            action_type,
            tool_args
        )
        
        if not check_result['success']:
            # Action is BLOCKED by the control plane
            error_msg = (
                f"BLOCKED: Agent {self.agent_context.agent_id} attempted {tool_name} "
                f"but was denied: {check_result.get('error', 'Unknown reason')}"
            )
            self.logger.warning(error_msg)
            
            # Call the optional callback
            if self.on_block:
                self.on_block(tool_name, tool_args, check_result)
            
            # Raise an exception to prevent execution
            # This follows the "Mute Agent" pattern - return NULL/error
            raise PermissionError(
                f"Action blocked by Agent Control Plane: {check_result.get('error', 'Policy violation')}"
            )
        else:
            self.logger.info(f"ALLOWED: {tool_name} for agent {self.agent_context.agent_id}")
    
    def _map_tool_to_action(self, tool_name: str) -> Optional[ActionType]:
        """
        Map a LangChain tool name to an ActionType.
        
        This uses both the provided mapping and pattern matching
        to handle various naming conventions.
        
        Args:
            tool_name: The name of the tool from LangChain
            
        Returns:
            ActionType if mapped, None if unknown
        """
        # Check exact match first
        tool_name_lower = tool_name.lower()
        if tool_name_lower in self.tool_mapping:
            return self.tool_mapping[tool_name_lower]
        
        # Pattern matching for common variations
        if any(pattern in tool_name_lower for pattern in ['read', 'get', 'fetch', 'load']) and \
           any(pattern in tool_name_lower for pattern in ['file', 'document']):
            return ActionType.FILE_READ
        
        if any(pattern in tool_name_lower for pattern in ['write', 'save', 'create', 'update']) and \
           any(pattern in tool_name_lower for pattern in ['file', 'document']):
            return ActionType.FILE_WRITE
        
        if any(pattern in tool_name_lower for pattern in ['exec', 'run', 'execute', 'eval', 'repl', 'python', 'terminal', 'shell', 'bash']):
            return ActionType.CODE_EXECUTION
        
        if any(pattern in tool_name_lower for pattern in ['sql', 'query', 'database', 'db']):
            # Check if it's a write operation
            if any(pattern in tool_name_lower for pattern in ['insert', 'update', 'delete', 'drop', 'create', 'alter']):
                return ActionType.DATABASE_WRITE
            return ActionType.DATABASE_QUERY
        
        if any(pattern in tool_name_lower for pattern in ['api', 'http', 'request', 'search', 'serpapi', 'google', 'wikipedia']):
            return ActionType.API_CALL
        
        if any(pattern in tool_name_lower for pattern in ['workflow', 'trigger', 'pipeline']):
            return ActionType.WORKFLOW_TRIGGER
        
        return None
    
    def add_tool_mapping(self, tool_name: str, action_type: ActionType):
        """
        Add a custom tool name to ActionType mapping.
        
        Args:
            tool_name: The name of the tool as used in LangChain
            action_type: The ActionType it should map to
        """
        self.tool_mapping[tool_name.lower()] = action_type
        self.logger.debug(f"Added tool mapping: {tool_name} -> {action_type.value}")
    
    def get_statistics(self) -> Dict[str, Any]:
        """
        Get statistics about the adapter's activity.
        
        Returns:
            Dictionary with statistics from the control plane
        """
        return {
            "agent_id": self.agent_context.agent_id,
            "session_id": self.agent_context.session_id,
            "control_plane_audit": self.control_plane.get_audit_log(limit=100),
            "execution_history": self.control_plane.get_execution_history(
                agent_id=self.agent_context.agent_id,
                limit=100
            )
        }
    
    # Proxy common LangChain methods to the wrapped client
    def __getattr__(self, name):
        """Proxy all other attributes to the wrapped client."""
        return getattr(self.client, name)


def create_governed_langchain_client(
    control_plane: AgentControlPlane,
    agent_id: str,
    langchain_client: Any,
    permissions: Optional[Dict[ActionType, Any]] = None,
    tool_mapping: Optional[Dict[str, ActionType]] = None
) -> LangChainAdapter:
    """
    Convenience function to create a governed LangChain client.
    
    This creates both the agent in the control plane and the adapter,
    providing a one-line setup for governed LangChain interactions.
    
    Args:
        control_plane: The AgentControlPlane instance
        agent_id: ID for the agent
        langchain_client: The LangChain LLM or agent to wrap
        permissions: Optional permissions for the agent
        tool_mapping: Optional custom tool name mappings
        
    Returns:
        A LangChainAdapter ready to use
        
    Example:
        from langchain.chat_models import ChatOpenAI
        from agent_control_plane import AgentControlPlane, PermissionLevel, ActionType
        from agent_control_plane.langchain_adapter import create_governed_langchain_client
        
        control_plane = AgentControlPlane()
        llm = ChatOpenAI(temperature=0)
        
        governed_llm = create_governed_langchain_client(
            control_plane,
            "my-agent",
            llm,
            permissions={
                ActionType.FILE_READ: PermissionLevel.READ_ONLY,
                ActionType.DATABASE_QUERY: PermissionLevel.READ_ONLY
            }
        )
        
        # Use in LangChain agents
        from langchain.agents import initialize_agent
        agent = initialize_agent(tools, governed_llm, agent="zero-shot-react-description")
    """
    agent_context = control_plane.create_agent(agent_id, permissions)
    
    return LangChainAdapter(
        control_plane=control_plane,
        agent_context=agent_context,
        langchain_client=langchain_client,
        tool_mapping=tool_mapping
    )
