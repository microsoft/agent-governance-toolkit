# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""
The Hands - The Execution Agent
"""

from typing import Dict, List, Optional, Any, Callable
from .handshake_protocol import HandshakeProtocol, HandshakeSession, HandshakeState


class ExecutionAgent:
    """
    The Hands - The Execution Agent
    
    This agent is responsible for executing actions that have been negotiated
    and validated through the Handshake Protocol. It does not reason about
    actions but simply executes them when properly authorized.
    """
    
    def __init__(self, protocol: HandshakeProtocol):
        self.protocol = protocol
        self.execution_handlers: Dict[str, Callable] = {}
        self.execution_history: List[Dict[str, Any]] = []
    
    def register_action_handler(
        self,
        action_id: str,
        handler: Callable[[Dict[str, Any]], Dict[str, Any]]
    ) -> None:
        """
        Register a handler function for a specific action.
        The handler receives parameters and returns results.
        """
        self.execution_handlers[action_id] = handler
    
    def execute(self, session_id: str) -> HandshakeSession:
        """
        Execute an action from an accepted handshake session.
        This is the main execution entry point.
        """
        session = self.protocol.get_session(session_id)
        
        if not session:
            raise ValueError(f"Session {session_id} not found")
        
        if session.state != HandshakeState.ACCEPTED:
            raise ValueError(
                f"Cannot execute session in state {session.state}. "
                f"Session must be in ACCEPTED state."
            )
        
        if not session.proposal:
            raise ValueError("Session has no proposal")
        
        # Mark as executing
        self.protocol.start_execution(session_id)
        
        try:
            # Execute the action
            result = self._execute_action(
                session.proposal.action_id,
                session.proposal.parameters,
                session.proposal.context
            )
            
            # Mark as completed
            self.protocol.complete_execution(session_id, result)
            
            # Store in history
            self.execution_history.append({
                "session_id": session_id,
                "action_id": session.proposal.action_id,
                "result": result,
                "success": True
            })
            
        except Exception as e:
            # Mark as failed
            self.protocol.fail_execution(session_id, str(e))
            
            # Store in history
            self.execution_history.append({
                "session_id": session_id,
                "action_id": session.proposal.action_id,
                "error": str(e),
                "success": False
            })
            
            raise
        
        return self.protocol.get_session(session_id)
    
    def _execute_action(
        self,
        action_id: str,
        parameters: Dict[str, Any],
        context: Dict[str, Any]
    ) -> Dict[str, Any]:
        """
        Execute a specific action using its registered handler.
        """
        handler = self.execution_handlers.get(action_id)
        
        if not handler:
            # If no handler registered, return a default result
            return {
                "status": "no_handler",
                "message": f"No handler registered for action {action_id}",
                "action_id": action_id,
                "parameters": parameters
            }
        
        # Call the handler
        result = handler(parameters)
        
        return {
            "status": "success",
            "action_id": action_id,
            "result": result
        }
    
    def can_execute(self, session_id: str) -> bool:
        """Check if a session can be executed."""
        session = self.protocol.get_session(session_id)
        
        if not session:
            return False
        
        if session.state != HandshakeState.ACCEPTED:
            return False
        
        if not session.proposal:
            return False
        
        # Check if handler is registered (optional)
        return True
    
    def get_execution_statistics(self) -> Dict[str, Any]:
        """Get statistics about execution operations."""
        if not self.execution_history:
            return {
                "total_executions": 0,
                "successful_executions": 0,
                "failed_executions": 0,
                "success_rate": 0.0
            }
        
        total = len(self.execution_history)
        successful = sum(1 for exec in self.execution_history if exec["success"])
        failed = total - successful
        
        return {
            "total_executions": total,
            "successful_executions": successful,
            "failed_executions": failed,
            "success_rate": successful / total if total > 0 else 0.0,
            "actions_executed": self._get_action_counts()
        }
    
    def _get_action_counts(self) -> Dict[str, int]:
        """Get counts of how many times each action was executed."""
        counts = {}
        for exec in self.execution_history:
            action_id = exec["action_id"]
            counts[action_id] = counts.get(action_id, 0) + 1
        return counts
