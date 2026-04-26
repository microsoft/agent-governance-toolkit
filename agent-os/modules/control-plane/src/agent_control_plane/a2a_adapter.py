# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""
A2A (Agent-to-Agent) Protocol Adapter - Agent Control Plane Integration

This adapter provides governance for A2A protocol communications between agents.
A2A is an open standard (originally from Google, now Linux Foundation) that enables
secure interoperability between AI agents from different frameworks and vendors.

The A2A adapter intercepts agent-to-agent messages and applies Agent Control Plane
governance rules to ensure safe and auditable inter-agent communication.

Usage:
    from agent_control_plane import AgentControlPlane
    from agent_control_plane.a2a_adapter import A2AAdapter, A2AAgent
    
    # Setup control plane
    control_plane = AgentControlPlane()
    agent_context = control_plane.create_agent("my-agent", permissions)
    
    # Create governed A2A agent
    a2a_agent = A2AAgent(
        agent_id="my-agent",
        agent_card={
            "name": "My Agent",
            "capabilities": ["data_processing"],
            "description": "An agent that processes data"
        },
        control_plane=control_plane,
        agent_context=agent_context
    )
    
    # Register capabilities
    a2a_agent.register_capability("data_processing", handle_data_processing)
    
    # All A2A communications are now governed!
    a2a_agent.start()
"""

from typing import Any, Dict, List, Optional, Callable, Union
import json
import logging
from datetime import datetime
from enum import Enum
import uuid

from .agent_kernel import ActionType, AgentContext
from .control_plane import AgentControlPlane


class A2AMessageType(Enum):
    """A2A protocol message types"""
    TASK_REQUEST = "task_request"
    TASK_RESPONSE = "task_response"
    TASK_DELEGATION = "task_delegation"
    QUERY = "query"
    RESPONSE = "response"
    NEGOTIATE = "negotiate"
    HANDSHAKE = "handshake"
    DISCOVERY = "discovery"


# Mapping from A2A operations to ActionTypes
DEFAULT_A2A_MAPPING = {
    # Task operations
    "task_request": ActionType.WORKFLOW_TRIGGER,
    "task_delegation": ActionType.WORKFLOW_TRIGGER,
    
    # Data operations
    "query": ActionType.DATABASE_QUERY,
    "data_request": ActionType.FILE_READ,
    
    # Code/compute operations
    "execute": ActionType.CODE_EXECUTION,
    "compute": ActionType.CODE_EXECUTION,
    
    # API/external operations
    "api_call": ActionType.API_CALL,
    "external_request": ActionType.API_CALL,
}


class A2AAdapter:
    """
    A2A Protocol Adapter with Agent Control Plane Governance.
    
    This adapter intercepts A2A protocol messages between agents and applies
    governance rules. A2A enables agents to:
    - Discover other agents via Agent Cards
    - Delegate tasks to specialized agents
    - Request information from other agents
    - Coordinate multi-step workflows
    - Negotiate task parameters
    
    The adapter ensures all inter-agent communications respect permissions
    and policies defined in the control plane.
    """
    
    def __init__(
        self,
        control_plane: AgentControlPlane,
        agent_context: AgentContext,
        agent_card: Dict[str, Any],
        capability_mapping: Optional[Dict[str, ActionType]] = None,
        on_block: Optional[Callable[[str, Dict, Dict], None]] = None,
        logger: Optional[logging.Logger] = None
    ):
        """
        Initialize the A2A adapter.
        
        Args:
            control_plane: The AgentControlPlane instance for governance
            agent_context: The AgentContext for this agent
            agent_card: The Agent Card describing this agent's capabilities
            capability_mapping: Optional mapping from capabilities to ActionTypes
            on_block: Optional callback when an action is blocked
            logger: Optional logger instance
        """
        self.control_plane = control_plane
        self.agent_context = agent_context
        self.agent_card = agent_card
        self.logger = logger or logging.getLogger("A2AAdapter")
        self.on_block = on_block
        
        # Merge default mapping with custom mapping
        self.capability_mapping = DEFAULT_A2A_MAPPING.copy()
        if capability_mapping:
            self.capability_mapping.update({k.lower(): v for k, v in capability_mapping.items()})
        
        # Track registered capabilities and their handlers
        self.capabilities: Dict[str, Callable] = {}
        
        # Track known peer agents (for discovery)
        self.peer_agents: Dict[str, Dict] = {}
        
        self.logger.info(
            f"Initialized A2AAdapter for agent {agent_context.agent_id}"
        )
    
    def handle_message(self, message: Dict[str, Any], from_agent: str) -> Dict[str, Any]:
        """
        Handle an A2A protocol message with governance.
        
        This is the main entry point for A2A messages from other agents.
        It validates the message, applies governance, and returns a response.
        
        Args:
            message: A2A protocol message
            from_agent: ID of the sending agent
            
        Returns:
            A2A protocol response
        """
        msg_type = message.get("type", "")
        msg_id = message.get("id", str(uuid.uuid4()))
        payload = message.get("payload", {})
        
        self.logger.debug(f"Received A2A message from {from_agent}: type={msg_type}, id={msg_id}")
        
        try:
            # Route to appropriate handler based on message type
            if msg_type == A2AMessageType.TASK_REQUEST.value:
                result = self._handle_task_request(payload, from_agent)
            elif msg_type == A2AMessageType.TASK_DELEGATION.value:
                result = self._handle_task_delegation(payload, from_agent)
            elif msg_type == A2AMessageType.QUERY.value:
                result = self._handle_query(payload, from_agent)
            elif msg_type == A2AMessageType.DISCOVERY.value:
                result = self._handle_discovery(payload, from_agent)
            elif msg_type == A2AMessageType.HANDSHAKE.value:
                result = self._handle_handshake(payload, from_agent)
            elif msg_type == A2AMessageType.NEGOTIATE.value:
                result = self._handle_negotiate(payload, from_agent)
            else:
                return self._create_error_response(msg_id, f"Unknown message type: {msg_type}")
            
            # Success response
            return {
                "id": msg_id,
                "type": A2AMessageType.RESPONSE.value,
                "from": self.agent_context.agent_id,
                "to": from_agent,
                "timestamp": datetime.now().isoformat(),
                "payload": result
            }
        
        except PermissionError as e:
            # Governance blocked the action
            self.logger.warning(f"Permission denied from {from_agent}: {str(e)}")
            return self._create_error_response(msg_id, str(e))
        
        except Exception as e:
            # Other errors
            self.logger.error(f"Error handling A2A message: {str(e)}")
            return self._create_error_response(msg_id, f"Internal error: {str(e)}")
    
    def _handle_task_request(self, payload: Dict, from_agent: str) -> Dict:
        """Handle a task request from another agent."""
        task_type = payload.get("task_type", "")
        task_params = payload.get("parameters", {})
        
        self.logger.info(f"Task request from {from_agent}: {task_type}")
        
        # Map task type to capability
        capability = task_type.lower()
        
        # Check if we have this capability
        if capability not in self.capabilities:
            raise PermissionError(f"Capability not available: {task_type}")
        
        # Map to ActionType
        action_type = self._map_capability_to_action(capability)
        
        # THE KERNEL CHECK - This is where governance happens
        check_result = self.control_plane.execute_action(
            self.agent_context,
            action_type,
            task_params
        )
        
        if not check_result['success']:
            # Action is BLOCKED
            error_msg = f"Task blocked: {check_result.get('error', 'Policy violation')}"
            self.logger.warning(f"BLOCKED: {task_type} from {from_agent} - {error_msg}")
            
            if self.on_block:
                self.on_block(task_type, task_params, check_result)
            
            raise PermissionError(error_msg)
        
        self.logger.info(f"ALLOWED: {task_type} from {from_agent}")
        
        # Execute the capability handler
        handler = self.capabilities[capability]
        result = handler(task_params)
        
        return {
            "status": "completed",
            "result": result
        }
    
    def _handle_task_delegation(self, payload: Dict, from_agent: str) -> Dict:
        """Handle task delegation (this agent delegating to another)."""
        target_agent = payload.get("target_agent", "")
        task_type = payload.get("task_type", "")
        task_params = payload.get("parameters", {})
        
        self.logger.info(f"Task delegation to {target_agent}: {task_type}")
        
        # Check if we have permission to delegate tasks
        action_type = ActionType.WORKFLOW_TRIGGER
        
        check_result = self.control_plane.execute_action(
            self.agent_context,
            action_type,
            {"target_agent": target_agent, "task_type": task_type}
        )
        
        if not check_result['success']:
            error_msg = f"Task delegation blocked: {check_result.get('error', 'Policy violation')}"
            self.logger.warning(f"BLOCKED: delegation to {target_agent} - {error_msg}")
            
            if self.on_block:
                self.on_block(task_type, task_params, check_result)
            
            raise PermissionError(error_msg)
        
        self.logger.info(f"ALLOWED: delegation to {target_agent}")
        
        return {
            "status": "delegated",
            "target_agent": target_agent,
            "task_type": task_type
        }
    
    def _handle_query(self, payload: Dict, from_agent: str) -> Dict:
        """Handle a data query from another agent."""
        query_type = payload.get("query_type", "")
        query_params = payload.get("parameters", {})
        
        self.logger.info(f"Query from {from_agent}: {query_type}")
        
        # Map query to action type
        if "database" in query_type.lower() or "sql" in query_type.lower():
            action_type = ActionType.DATABASE_QUERY
        elif "file" in query_type.lower() or "data" in query_type.lower():
            action_type = ActionType.FILE_READ
        else:
            action_type = ActionType.API_CALL
        
        check_result = self.control_plane.execute_action(
            self.agent_context,
            action_type,
            query_params
        )
        
        if not check_result['success']:
            error_msg = f"Query blocked: {check_result.get('error', 'Policy violation')}"
            self.logger.warning(f"BLOCKED: {query_type} from {from_agent} - {error_msg}")
            
            if self.on_block:
                self.on_block(query_type, query_params, check_result)
            
            raise PermissionError(error_msg)
        
        self.logger.info(f"ALLOWED: {query_type} from {from_agent}")
        
        return {
            "status": "success",
            "data": check_result.get('result', {})
        }
    
    def _handle_discovery(self, payload: Dict, from_agent: str) -> Dict:
        """Handle agent discovery request."""
        self.logger.info(f"Discovery request from {from_agent}")
        
        # Discovery is generally safe - return our Agent Card
        return {
            "agent_card": self.agent_card,
            "agent_id": self.agent_context.agent_id
        }
    
    def _handle_handshake(self, payload: Dict, from_agent: str) -> Dict:
        """Handle handshake for establishing connection."""
        self.logger.info(f"Handshake from {from_agent}")
        
        # Store peer agent info
        peer_card = payload.get("agent_card", {})
        if peer_card:
            self.peer_agents[from_agent] = peer_card
        
        return {
            "status": "connected",
            "agent_card": self.agent_card
        }
    
    def _handle_negotiate(self, payload: Dict, from_agent: str) -> Dict:
        """
        Handle task parameter negotiation.
        
        TODO: Implement actual negotiation logic with validation and governance.
        Currently accepts all parameters as a placeholder.
        """
        self.logger.info(f"Negotiation from {from_agent}")
        
        # Negotiation typically involves discussing task parameters
        # Return accepted parameters
        proposed_params = payload.get("parameters", {})
        
        return {
            "status": "accepted",
            "parameters": proposed_params
        }
    
    def _map_capability_to_action(self, capability: str) -> ActionType:
        """Map a capability to an ActionType."""
        capability_lower = capability.lower()
        
        # Check exact match
        if capability_lower in self.capability_mapping:
            return self.capability_mapping[capability_lower]
        
        # Pattern matching
        if any(p in capability_lower for p in ['read', 'get', 'fetch', 'query']):
            if any(p in capability_lower for p in ['file', 'document']):
                return ActionType.FILE_READ
            elif any(p in capability_lower for p in ['database', 'db', 'sql']):
                return ActionType.DATABASE_QUERY
            else:
                return ActionType.API_CALL
        
        if any(p in capability_lower for p in ['write', 'save', 'update', 'create']):
            if any(p in capability_lower for p in ['file', 'document']):
                return ActionType.FILE_WRITE
            elif any(p in capability_lower for p in ['database', 'db', 'sql']):
                return ActionType.DATABASE_WRITE
        
        if any(p in capability_lower for p in ['execute', 'run', 'compute', 'process']):
            return ActionType.CODE_EXECUTION
        
        if any(p in capability_lower for p in ['workflow', 'task', 'delegate']):
            return ActionType.WORKFLOW_TRIGGER
        
        # Default to workflow trigger for unknown capabilities
        return ActionType.WORKFLOW_TRIGGER
    
    def _create_error_response(self, msg_id: str, error_message: str) -> Dict:
        """Create an A2A error response."""
        return {
            "id": msg_id,
            "type": "error",
            "from": self.agent_context.agent_id,
            "timestamp": datetime.now().isoformat(),
            "error": {
                "message": error_message
            }
        }
    
    def register_capability(self, capability: str, handler: Callable):
        """
        Register a capability that this agent can perform.
        
        Args:
            capability: Name of the capability
            handler: Function to handle requests for this capability
        """
        self.capabilities[capability.lower()] = handler
        self.logger.debug(f"Registered capability: {capability}")
        
        # Update Agent Card
        if "capabilities" not in self.agent_card:
            self.agent_card["capabilities"] = []
        if capability not in self.agent_card["capabilities"]:
            self.agent_card["capabilities"].append(capability)
    
    def add_capability_mapping(self, capability: str, action_type: ActionType):
        """Add a custom capability to ActionType mapping."""
        self.capability_mapping[capability.lower()] = action_type
        self.logger.debug(f"Added capability mapping: {capability} -> {action_type.value}")
    
    def get_agent_card(self) -> Dict:
        """Get this agent's Agent Card for discovery."""
        return {
            **self.agent_card,
            "agent_id": self.agent_context.agent_id,
            "capabilities": list(self.capabilities.keys())
        }
    
    def discover_agents(self) -> List[Dict]:
        """Get list of discovered peer agents."""
        return [
            {"agent_id": agent_id, **card}
            for agent_id, card in self.peer_agents.items()
        ]


class A2AAgent:
    """
    Simplified A2A Agent with built-in governance.
    
    This class provides a simple way to create an A2A-compliant agent
    with Agent Control Plane governance built in.
    """
    
    def __init__(
        self,
        agent_id: str,
        control_plane: AgentControlPlane,
        agent_context: AgentContext,
        agent_card: Optional[Dict[str, Any]] = None,
        logger: Optional[logging.Logger] = None
    ):
        """
        Initialize an A2A agent.
        
        Args:
            agent_id: Unique identifier for this agent
            control_plane: Agent Control Plane instance
            agent_context: Agent context
            agent_card: Optional Agent Card (description, capabilities, etc.)
            logger: Optional logger
        """
        self.agent_id = agent_id
        self.logger = logger or logging.getLogger(f"A2AAgent.{agent_id}")
        
        # Create default Agent Card if not provided
        if agent_card is None:
            agent_card = {
                "name": agent_id,
                "description": f"Agent {agent_id}",
                "version": "1.0.0",
                "capabilities": []
            }
        
        # Create the adapter
        self.adapter = A2AAdapter(
            control_plane=control_plane,
            agent_context=agent_context,
            agent_card=agent_card,
            logger=self.logger
        )
        
        self.logger.info(f"Initialized A2A agent: {agent_id}")
    
    def register_capability(self, capability: str, handler: Callable):
        """Register a capability with the agent."""
        self.adapter.register_capability(capability, handler)
    
    def handle_message(self, message: Dict, from_agent: str) -> Dict:
        """Handle an A2A message."""
        return self.adapter.handle_message(message, from_agent)
    
    def send_task_request(self, to_agent: str, task_type: str, parameters: Dict) -> Dict:
        """Send a task request to another agent."""
        message = {
            "id": str(uuid.uuid4()),
            "type": A2AMessageType.TASK_REQUEST.value,
            "from": self.agent_id,
            "to": to_agent,
            "timestamp": datetime.now().isoformat(),
            "payload": {
                "task_type": task_type,
                "parameters": parameters
            }
        }
        self.logger.info(f"Sending task request to {to_agent}: {task_type}")
        return message
    
    def get_agent_card(self) -> Dict:
        """Get this agent's Agent Card."""
        return self.adapter.get_agent_card()
    
    def start(self):
        """Start the A2A agent (placeholder for actual implementation)."""
        self.logger.info(f"A2A agent '{self.agent_id}' started")


def create_governed_a2a_agent(
    control_plane: AgentControlPlane,
    agent_id: str,
    agent_card: Optional[Dict[str, Any]] = None,
    permissions: Optional[Dict[ActionType, Any]] = None
) -> A2AAgent:
    """
    Convenience function to create a governed A2A agent.
    
    Args:
        control_plane: Agent Control Plane instance
        agent_id: Agent ID
        agent_card: Optional Agent Card
        permissions: Optional agent permissions
        
    Returns:
        A governed A2AAgent instance
    """
    agent_context = control_plane.create_agent(agent_id, permissions)
    
    return A2AAgent(
        agent_id=agent_id,
        control_plane=control_plane,
        agent_context=agent_context,
        agent_card=agent_card
    )
