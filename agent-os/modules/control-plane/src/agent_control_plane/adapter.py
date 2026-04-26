# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""
OpenAI Client Adapter - Drop-In Middleware for Agent Control Plane

This adapter wraps the OpenAI client to automatically intercept and govern
tool calls made by LLMs. It provides "zero-friction" integration - developers
can continue using the standard OpenAI SDK while benefiting from the control
plane's governance and safety features.

Usage:
    from openai import OpenAI
    from agent_control_plane import AgentControlPlane
    from agent_control_plane.adapter import ControlPlaneAdapter
    
    # Standard setup
    client = OpenAI(api_key="your-key")
    control_plane = AgentControlPlane()
    agent_context = control_plane.create_agent("my-agent", permissions)
    
    # Wrap with adapter
    governed_client = ControlPlaneAdapter(
        control_plane=control_plane,
        agent_context=agent_context,
        original_client=client
    )
    
    # Use exactly as you would use OpenAI client
    response = governed_client.chat.completions.create(
        model="gpt-4",
        messages=[...],
        tools=[...]
    )
    # Tool calls are automatically governed by the control plane!
"""

from typing import Any, Dict, List, Optional, Callable
import json
import logging
from datetime import datetime

from .agent_kernel import ActionType, AgentContext
from .control_plane import AgentControlPlane


# Mapping from common OpenAI tool names to ActionType
DEFAULT_TOOL_MAPPING = {
    # File operations
    "read_file": ActionType.FILE_READ,
    "write_file": ActionType.FILE_WRITE,
    "file_read": ActionType.FILE_READ,
    "file_write": ActionType.FILE_WRITE,
    
    # Code execution
    "execute_code": ActionType.CODE_EXECUTION,
    "run_code": ActionType.CODE_EXECUTION,
    "python": ActionType.CODE_EXECUTION,
    "bash": ActionType.CODE_EXECUTION,
    "code_interpreter": ActionType.CODE_EXECUTION,
    
    # Database operations
    "database_query": ActionType.DATABASE_QUERY,
    "sql_query": ActionType.DATABASE_QUERY,
    "db_query": ActionType.DATABASE_QUERY,
    "database_write": ActionType.DATABASE_WRITE,
    "sql_write": ActionType.DATABASE_WRITE,
    "db_write": ActionType.DATABASE_WRITE,
    
    # API calls
    "api_call": ActionType.API_CALL,
    "http_request": ActionType.API_CALL,
    "make_request": ActionType.API_CALL,
    
    # Workflow operations
    "trigger_workflow": ActionType.WORKFLOW_TRIGGER,
    "start_workflow": ActionType.WORKFLOW_TRIGGER,
}


class ChatCompletionsWrapper:
    """
    Wrapper for chat.completions that intercepts tool calls.
    
    This class mimics the OpenAI client's chat.completions interface
    while adding governance checks for tool calls.
    """
    
    def __init__(
        self,
        original_completions: Any,
        control_plane: AgentControlPlane,
        agent_context: AgentContext,
        tool_mapping: Dict[str, ActionType],
        logger: logging.Logger,
        on_block: Optional[Callable] = None
    ):
        self.original = original_completions
        self.control_plane = control_plane
        self.agent_context = agent_context
        self.tool_mapping = tool_mapping
        self.logger = logger
        self.on_block = on_block
    
    def create(self, **kwargs) -> Any:
        """
        Create a chat completion with automatic tool call governance.
        
        This method:
        1. Calls the OpenAI API to get the LLM's response
        2. Intercepts any tool_calls in the response
        3. Checks each tool call against the control plane
        4. Blocks or modifies tool calls that violate policies
        5. Returns the (possibly modified) response
        
        Args:
            **kwargs: All standard OpenAI chat.completions.create parameters
            
        Returns:
            The OpenAI ChatCompletion response, with tool calls governed
        """
        # 1. Let the LLM think - call the original OpenAI API
        self.logger.debug(f"Agent {self.agent_context.agent_id}: Calling OpenAI API")
        response = self.original.create(**kwargs)
        
        # 2. Check if there are tool calls to intercept
        if not hasattr(response, 'choices') or not response.choices:
            return response
        
        choice = response.choices[0]
        if not hasattr(choice, 'message') or not hasattr(choice.message, 'tool_calls'):
            return response
        
        if not choice.message.tool_calls:
            return response
        
        # 3. Intercept and govern each tool call
        self.logger.info(
            f"Agent {self.agent_context.agent_id}: Intercepting {len(choice.message.tool_calls)} tool call(s)"
        )
        
        for tool_call in choice.message.tool_calls:
            if not hasattr(tool_call, 'function'):
                continue
            
            tool_name = tool_call.function.name
            
            # Parse arguments (they come as JSON string from OpenAI)
            try:
                tool_args = json.loads(tool_call.function.arguments) if tool_call.function.arguments else {}
            except json.JSONDecodeError as e:
                self.logger.warning(
                    f"Could not parse arguments for tool '{tool_name}': {tool_call.function.arguments}. "
                    f"Error: {e}. Using empty dict."
                )
                tool_args = {}
            
            # Map tool name to ActionType
            action_type = self._map_tool_to_action(tool_name)
            
            if action_type is None:
                self.logger.warning(f"Unknown tool '{tool_name}', allowing by default")
                continue
            
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
                self.logger.warning(
                    f"BLOCKED: Agent {self.agent_context.agent_id} attempted {tool_name} "
                    f"but was denied: {check_result.get('error', 'Unknown reason')}"
                )
                
                # Overwrite the tool call with a "blocked" indicator
                # The Mute Agent pattern: return NULL/minimal response
                tool_call.function.name = "blocked_action"
                tool_call.function.arguments = json.dumps({
                    "original_tool": tool_name,
                    "reason": "Action blocked by Agent Control Plane",
                    "error": check_result.get('error', 'Policy violation')
                })
                
                # Call the optional callback
                if self.on_block:
                    self.on_block(tool_name, tool_args, check_result)
            else:
                self.logger.info(f"ALLOWED: {tool_name} for agent {self.agent_context.agent_id}")
        
        return response
    
    def _map_tool_to_action(self, tool_name: str) -> Optional[ActionType]:
        """
        Map an OpenAI tool name to an ActionType.
        
        This uses both the provided mapping and pattern matching
        to handle various naming conventions.
        
        Args:
            tool_name: The name of the tool from OpenAI
            
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
        
        if any(pattern in tool_name_lower for pattern in ['exec', 'run', 'execute', 'eval']) and \
           any(pattern in tool_name_lower for pattern in ['code', 'python', 'script', 'command', 'bash']):
            return ActionType.CODE_EXECUTION
        
        if any(pattern in tool_name_lower for pattern in ['select', 'query', 'search']) and \
           any(pattern in tool_name_lower for pattern in ['database', 'db', 'sql', 'table']):
            return ActionType.DATABASE_QUERY
        
        if any(pattern in tool_name_lower for pattern in ['insert', 'update', 'delete', 'drop', 'create', 'alter']) and \
           any(pattern in tool_name_lower for pattern in ['database', 'db', 'sql', 'table']):
            return ActionType.DATABASE_WRITE
        
        if any(pattern in tool_name_lower for pattern in ['api', 'http', 'request', 'call', 'post', 'get']):
            return ActionType.API_CALL
        
        if any(pattern in tool_name_lower for pattern in ['workflow', 'trigger', 'pipeline']):
            return ActionType.WORKFLOW_TRIGGER
        
        return None


class ChatWrapper:
    """Wrapper for chat namespace"""
    
    def __init__(
        self,
        original_chat: Any,
        control_plane: AgentControlPlane,
        agent_context: AgentContext,
        tool_mapping: Dict[str, ActionType],
        logger: logging.Logger,
        on_block: Optional[Callable] = None
    ):
        self.original = original_chat
        self.completions = ChatCompletionsWrapper(
            original_chat.completions,
            control_plane,
            agent_context,
            tool_mapping,
            logger,
            on_block
        )


class ControlPlaneAdapter:
    """
    OpenAI Client Adapter with Agent Control Plane Governance.
    
    This class wraps an OpenAI client to provide automatic governance
    of tool calls. It's designed as a drop-in replacement that requires
    minimal code changes.
    
    The adapter intercepts tool_calls in LLM responses and checks them
    against the control plane's policies before allowing execution.
    Blocked actions are replaced with error indicators following the
    "Mute Agent" pattern.
    
    Example:
        # Before (ungovened):
        client = OpenAI()
        response = client.chat.completions.create(...)
        
        # After (governed):
        governed_client = ControlPlaneAdapter(control_plane, agent_context, client)
        response = governed_client.chat.completions.create(...)
        # Same API, but now with governance!
    """
    
    def __init__(
        self,
        control_plane: AgentControlPlane,
        agent_context: AgentContext,
        original_client: Any,
        tool_mapping: Optional[Dict[str, ActionType]] = None,
        on_block: Optional[Callable[[str, Dict, Dict], None]] = None,
        logger: Optional[logging.Logger] = None
    ):
        """
        Initialize the adapter.
        
        Args:
            control_plane: The AgentControlPlane instance for governance
            agent_context: The AgentContext for the agent using this client
            original_client: The original OpenAI client instance
            tool_mapping: Optional custom mapping from tool names to ActionTypes
            on_block: Optional callback called when an action is blocked
                      Signature: on_block(tool_name: str, tool_args: dict, result: dict)
            logger: Optional logger instance
        """
        self.control_plane = control_plane
        self.agent_context = agent_context
        self.client = original_client
        self.logger = logger or logging.getLogger("ControlPlaneAdapter")
        self.on_block = on_block
        
        # Merge default mapping with custom mapping
        self.tool_mapping = DEFAULT_TOOL_MAPPING.copy()
        if tool_mapping:
            self.tool_mapping.update({k.lower(): v for k, v in tool_mapping.items()})
        
        self.logger.info(
            f"Initialized ControlPlaneAdapter for agent {agent_context.agent_id}"
        )
    
    @property
    def chat(self) -> ChatWrapper:
        """Access the wrapped chat API"""
        return ChatWrapper(
            self.client.chat,
            self.control_plane,
            self.agent_context,
            self.tool_mapping,
            self.logger,
            self.on_block
        )
    
    def add_tool_mapping(self, tool_name: str, action_type: ActionType):
        """
        Add a custom tool name to ActionType mapping.
        
        Args:
            tool_name: The name of the tool as used in OpenAI
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


def create_governed_client(
    control_plane: AgentControlPlane,
    agent_id: str,
    openai_client: Any,
    permissions: Optional[Dict[ActionType, Any]] = None,
    tool_mapping: Optional[Dict[str, ActionType]] = None
) -> ControlPlaneAdapter:
    """
    Convenience function to create a governed OpenAI client.
    
    This creates both the agent in the control plane and the adapter,
    providing a one-line setup for governed LLM interactions.
    
    Args:
        control_plane: The AgentControlPlane instance
        agent_id: ID for the agent
        openai_client: The OpenAI client to wrap
        permissions: Optional permissions for the agent
        tool_mapping: Optional custom tool name mappings
        
    Returns:
        A ControlPlaneAdapter ready to use
        
    Example:
        control_plane = AgentControlPlane()
        openai_client = OpenAI(api_key="...")
        
        governed = create_governed_client(
            control_plane,
            "my-agent",
            openai_client,
            permissions={
                ActionType.FILE_READ: PermissionLevel.READ_ONLY,
                ActionType.DATABASE_QUERY: PermissionLevel.READ_ONLY
            }
        )
        
        # Use like normal OpenAI client
        response = governed.chat.completions.create(...)
    """
    agent_context = control_plane.create_agent(agent_id, permissions)
    
    return ControlPlaneAdapter(
        control_plane=control_plane,
        agent_context=agent_context,
        original_client=openai_client,
        tool_mapping=tool_mapping
    )
