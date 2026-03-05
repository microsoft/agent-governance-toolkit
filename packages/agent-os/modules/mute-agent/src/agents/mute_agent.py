# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""
Mute Agent - Graph-Constrained Agent with State Awareness

This agent uses the Mute Agent architecture with enhancements for:
1. State-aware graph constraints (resource states, current focus)
2. Permission-based edge pruning
3. Deterministic action validation through graph traversal

The key advantage: Context is encoded in the graph structure,
not retrieved probabilistically at runtime.
"""

from typing import Dict, Any, List, Optional
from dataclasses import dataclass, field
from datetime import datetime
import sys
import os

# Import the shared infrastructure API
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '../..'))
from src.core.tools import (
    MockInfrastructureAPI,
    SessionContext,
    User,
    UserRole,
    Environment,
    ResourceState,
    Service,
)

# Import Mute Agent core
from mute_agent import (
    ReasoningAgent,
    ExecutionAgent,
    HandshakeProtocol,
    MultidimensionalKnowledgeGraph,
    SuperSystemRouter,
)
from mute_agent.knowledge_graph.graph_elements import Node, Edge, NodeType, EdgeType
from mute_agent.knowledge_graph.subgraph import Dimension


@dataclass
class MuteAgentResult:
    """Result from Mute Agent execution."""
    success: bool
    action_taken: Optional[str]
    parameters_used: Optional[Dict[str, Any]]
    final_result: Optional[Dict[str, Any]]
    
    # Failure analysis
    constraint_violation: Optional[str]
    blocked_by_graph: bool
    safety_violation: bool
    state_misalignment: bool
    
    # Performance metrics
    token_count: int
    graph_traversals: int
    latency_ms: float
    
    # No clarification needed - graph is deterministic
    needed_clarification: bool = False


class GraphEngine:
    """
    Graph Engine for Mute Agent - builds state-aware constraint graphs.
    
    This is extracted as a separate component per the PRD structure.
    """
    
    def __init__(self, api: MockInfrastructureAPI):
        """Initialize graph engine with access to infrastructure state."""
        self.api = api
        self.kg = MultidimensionalKnowledgeGraph()
        self._initialize_dimensions()
    
    def _initialize_dimensions(self):
        """Initialize the dimensional subgraphs."""
        # Dimension 1: Operations (what actions are available)
        operations_dim = Dimension(
            name="operations",
            description="Available operations on infrastructure",
            priority=10
        )
        self.kg.add_dimension(operations_dim)
        
        # Dimension 2: Permissions (who can do what)
        permissions_dim = Dimension(
            name="permissions",
            description="Permission constraints",
            priority=9
        )
        self.kg.add_dimension(permissions_dim)
        
        # Dimension 3: State (resource state constraints)
        state_dim = Dimension(
            name="state",
            description="Resource state constraints",
            priority=8
        )
        self.kg.add_dimension(state_dim)
        
        # Dimension 4: Context (current focus tracking)
        context_dim = Dimension(
            name="context",
            description="Session context and focus",
            priority=7
        )
        self.kg.add_dimension(context_dim)
    
    def build_graph_from_state(self, context: SessionContext) -> MultidimensionalKnowledgeGraph:
        """
        Build a constraint graph from current infrastructure state.
        
        This is the key difference from baseline: The graph encodes
        ALL context, so the agent doesn't need to reason about it.
        """
        # Get current system state
        system_state = self.api.get_system_state(context)
        
        # Clear existing nodes (rebuild fresh each time)
        self.kg = MultidimensionalKnowledgeGraph()
        self._initialize_dimensions()
        
        # Build graph for current state
        self._add_operation_nodes()
        self._add_service_nodes(system_state, context)
        self._add_permission_constraints(context.user, system_state)
        self._add_state_constraints(system_state)
        self._add_context_constraints(context, system_state)
        
        return self.kg
    
    def _add_operation_nodes(self):
        """Add operation action nodes."""
        operations = [
            ("restart_service", "Restart a service"),
            ("scale_service", "Scale service replicas"),
            ("rollback_deployment", "Rollback a deployment"),
            ("force_delete", "Force delete a resource"),
            ("get_logs", "Get service logs"),
        ]
        
        for op_id, description in operations:
            node = Node(
                id=op_id,
                node_type=NodeType.ACTION,
                attributes={"description": description}
            )
            self.kg.add_node_to_dimension("operations", node)
    
    def _add_service_nodes(self, system_state: Dict[str, Any], context: SessionContext):
        """Add nodes for each service."""
        services = system_state.get("services", {})
        
        for service_id, service_data in services.items():
            node = Node(
                id=service_id,
                node_type=NodeType.RESOURCE,
                attributes={
                    "name": service_data["name"],
                    "environment": service_data["environment"],
                    "state": service_data["state"],
                    "replicas": service_data.get("replicas", 0),
                }
            )
            self.kg.add_node_to_dimension("operations", node)
            
            # Add to context dimension if this is the current focus
            if context.current_focus == service_id:
                focus_node = Node(
                    id=f"focus_{service_id}",
                    node_type=NodeType.CONTEXT,
                    attributes={"service_id": service_id, "is_current_focus": True}
                )
                self.kg.add_node_to_dimension("context", focus_node)
                
                # Add edge from operations to focused service
                # This makes operations on the focused service valid
                for operation in ["restart_service", "scale_service", "force_delete"]:
                    edge = Edge(
                        source_id=operation,
                        target_id=service_id,
                        edge_type=EdgeType.ENABLES,
                        attributes={"reason": "service_in_focus"}
                    )
                    self.kg.add_edge_to_dimension("context", edge)
    
    def _add_permission_constraints(self, user: User, system_state: Dict[str, Any]):
        """Add permission-based constraints."""
        # Add user node
        user_node = Node(
            id=f"user_{user.name}",
            node_type=NodeType.CONTEXT,
            attributes={"role": user.role.value}
        )
        self.kg.add_node_to_dimension("permissions", user_node)
        
        services = system_state.get("services", {})
        
        for service_id, service_data in services.items():
            env_str = service_data["environment"]
            env = Environment[env_str.upper()] if env_str.upper() in Environment.__members__ else Environment.DEV
            
            # Add permission edges based on user role and environment
            if user.can_write_to(env):
                # User can perform write operations on this service
                for operation in ["restart_service", "scale_service"]:
                    edge = Edge(
                        source_id=operation,
                        target_id=service_id,
                        edge_type=EdgeType.ENABLES,
                        attributes={"permission": "write", "environment": env_str}
                    )
                    self.kg.add_edge_to_dimension("permissions", edge)
            
            # Force delete requires SRE/Admin
            if user.role in [UserRole.SRE, UserRole.ADMIN]:
                edge = Edge(
                    source_id="force_delete",
                    target_id=service_id,
                    edge_type=EdgeType.ENABLES,
                    attributes={"permission": "force_delete"}
                )
                self.kg.add_edge_to_dimension("permissions", edge)
    
    def _add_state_constraints(self, system_state: Dict[str, Any]):
        """Add state-based constraints (e.g., can't restart PARTIAL services)."""
        services = system_state.get("services", {})
        
        for service_id, service_data in services.items():
            state = service_data["state"]
            
            if state == "partial":
                # PARTIAL services can't be restarted or scaled
                # Only force_delete is allowed
                for operation in ["restart_service", "scale_service", "rollback_deployment"]:
                    # Add a CONFLICTS_WITH edge to block these operations
                    edge = Edge(
                        source_id=operation,
                        target_id=service_id,
                        edge_type=EdgeType.CONFLICTS_WITH,
                        attributes={"reason": f"service_in_{state}_state", 
                                   "suggestion": "use_force_delete"}
                    )
                    self.kg.add_edge_to_dimension("state", edge)
            
            elif state == "running":
                # Running services can be restarted and scaled
                for operation in ["restart_service", "scale_service"]:
                    edge = Edge(
                        source_id=operation,
                        target_id=service_id,
                        edge_type=EdgeType.ENABLES,
                        attributes={"state": state}
                    )
                    self.kg.add_edge_to_dimension("state", edge)
            
            elif state == "stopped":
                # Stopped services can be started but not restarted
                edge = Edge(
                    source_id="start_service",
                    target_id=service_id,
                    edge_type=EdgeType.ENABLES,
                    attributes={"state": state}
                )
                self.kg.add_edge_to_dimension("state", edge)
    
    def _add_context_constraints(self, context: SessionContext, system_state: Dict[str, Any]):
        """
        Add context-based constraints.
        
        This is the KEY to solving the "Stale State" scenario:
        The graph encodes which service is currently in focus.
        """
        if context.current_focus:
            # Add a strong constraint that operations without explicit
            # service target should use the current focus
            focus_node = Node(
                id="current_focus",
                node_type=NodeType.CONTEXT,
                attributes={"service_id": context.current_focus}
            )
            self.kg.add_node_to_dimension("context", focus_node)
            
            # Add edge prioritizing current focus for ambiguous operations
            for operation in ["restart_service", "scale_service"]:
                edge = Edge(
                    source_id=operation,
                    target_id="current_focus",
                    edge_type=EdgeType.REQUIRES,
                    attributes={"priority": "high", "reason": "default_target"}
                )
                self.kg.add_edge_to_dimension("context", edge)


class MuteAgent:
    """
    The Mute Agent - Graph-Constrained Agent
    
    Uses the Mute Agent architecture with state-aware graph constraints.
    """
    
    # Token costs (much lower due to graph pruning)
    BASE_SYSTEM_PROMPT_TOKENS = 200  # No tool definitions needed
    GRAPH_TRAVERSAL_TOKENS = 50  # Per graph query
    VALIDATION_TOKENS = 100  # Constraint checking
    
    def __init__(self, api: MockInfrastructureAPI):
        """Initialize with access to infrastructure API."""
        self.api = api
        self.graph_engine = GraphEngine(api)
        self.execution_history: List[MuteAgentResult] = []
    
    def execute_request(
        self,
        user_command: str,
        context: SessionContext
    ) -> MuteAgentResult:
        """
        Execute a user request using graph-based constraints.
        
        No reflection loops, no clarification needed - the graph
        encodes all context deterministically.
        """
        start_time = datetime.now()
        token_count = self.BASE_SYSTEM_PROMPT_TOKENS
        graph_traversals = 0
        
        # Build graph from current state
        kg = self.graph_engine.build_graph_from_state(context)
        token_count += self.GRAPH_TRAVERSAL_TOKENS
        graph_traversals += 1
        
        # Parse command to determine intent
        intent = self._parse_command(user_command)
        
        # Resolve parameters using graph
        resolution = self._resolve_with_graph(intent, user_command, context, kg)
        token_count += self.GRAPH_TRAVERSAL_TOKENS
        graph_traversals += 1
        
        if resolution["blocked"]:
            # Graph constraint prevented execution
            latency = (datetime.now() - start_time).total_seconds() * 1000
            
            result = MuteAgentResult(
                success=False,
                action_taken=intent,
                parameters_used=resolution.get("parameters"),
                final_result=None,
                constraint_violation=resolution["reason"],
                blocked_by_graph=True,
                safety_violation=resolution.get("safety_violation", False),
                state_misalignment=False,
                token_count=token_count,
                graph_traversals=graph_traversals,
                latency_ms=latency,
            )
            
            self.execution_history.append(result)
            return result
        
        # Execute the action
        token_count += self.VALIDATION_TOKENS
        result = self._execute_action(
            resolution["action"],
            resolution["parameters"],
            context,
            token_count,
            graph_traversals
        )
        
        latency = (datetime.now() - start_time).total_seconds() * 1000
        result.latency_ms = latency
        
        self.execution_history.append(result)
        return result
    
    def _parse_command(self, command: str) -> str:
        """Parse user command to determine intent."""
        command_lower = command.lower()
        
        if "restart" in command_lower:
            return "restart_service"
        elif "scale" in command_lower:
            return "scale_service"
        elif "rollback" in command_lower:
            return "rollback_deployment"
        elif "force delete" in command_lower or "force-delete" in command_lower:
            return "force_delete"
        elif "delete" in command_lower or "remove" in command_lower or "clean" in command_lower:
            return "force_delete"
        elif "fix" in command_lower:
            return "restart_service"
        else:
            return "unknown"
    
    def _resolve_with_graph(
        self,
        intent: str,
        command: str,
        context: SessionContext,
        kg: MultidimensionalKnowledgeGraph
    ) -> Dict[str, Any]:
        """
        Resolve parameters using graph constraints.
        
        This is deterministic - no guessing, no hallucination.
        """
        # Get current focus from context
        target_service = None
        
        # Check if service is explicitly mentioned in command
        system_state = self.api.get_system_state(context)
        services = system_state.get("services", {})
        
        # Try explicit match first
        for service_id, service_data in services.items():
            service_name = service_data.get("name", "").lower()
            if service_name in command.lower():
                # Check if environment is also mentioned
                env = service_data.get("environment", "").lower()
                if env in command.lower():
                    target_service = service_id
                    break
                # If only one service with this name, use it
                matching = [
                    sid for sid, sdata in services.items()
                    if sdata.get("name", "").lower() == service_name
                ]
                if len(matching) == 1:
                    target_service = service_id
                    break
        
        # If no explicit match and command uses pronoun ("it", "the service")
        # Use current focus from graph
        if not target_service and any(word in command.lower() for word in ["it", "the service", "this"]):
            target_service = context.current_focus
        
        # If still no target, check for last log viewed
        if not target_service and context.last_log_viewed:
            target_service = context.last_log_viewed
        
        if not target_service:
            return {
                "blocked": True,
                "reason": "No service target could be determined from command or context",
                "action": intent,
                "parameters": None,
                "safety_violation": False,
            }
        
        # Check graph constraints for this action + target
        validation = self._validate_action_in_graph(intent, target_service, kg, context)
        
        if not validation["valid"]:
            return {
                "blocked": True,
                "reason": validation["reason"],
                "action": intent,
                "parameters": {"service_id": target_service},
                "safety_violation": validation.get("safety_violation", False),
            }
        
        # Action is valid - prepare parameters
        parameters = {"service_id": target_service}
        
        # Add extra parameters for specific actions
        if intent == "scale_service":
            import re
            # Look for "scale to N" or "N replicas" patterns specifically
            # This avoids matching numbers in service names
            scale_patterns = [
                r'(?:scale|set|to)\s+(\d+)',  # "scale to 5", "set 5"
                r'(\d+)\s+replica',  # "5 replicas"
            ]
            replicas = None
            for pattern in scale_patterns:
                match = re.search(pattern, command.lower())
                if match:
                    replicas = int(match.group(1))
                    break
            
            if replicas is not None:
                parameters["replicas"] = replicas
            else:
                return {
                    "blocked": True,
                    "reason": "Scale command requires replica count",
                    "action": intent,
                    "parameters": parameters,
                    "safety_violation": False,
                }
        
        return {
            "blocked": False,
            "action": intent,
            "parameters": parameters,
        }
    
    def _validate_action_in_graph(
        self,
        action: str,
        service_id: str,
        kg: MultidimensionalKnowledgeGraph,
        context: SessionContext
    ) -> Dict[str, Any]:
        """
        Validate if action is allowed by checking all graph constraints.
        
        This checks:
        1. Permission dimension - does user have rights?
        2. State dimension - is service in right state?
        3. Context dimension - is this the right target?
        """
        # Check for CONFLICTS_WITH edges in state dimension
        state_subgraph = kg.get_subgraph("state")
        if state_subgraph:
            for edge in state_subgraph.edges:
                if edge.source_id == action and edge.target_id == service_id:
                    if edge.edge_type == EdgeType.CONFLICTS_WITH:
                        suggestion = edge.attributes.get("suggestion", "")
                        return {
                            "valid": False,
                            "reason": f"Action {action} conflicts with service state. {suggestion}",
                            "safety_violation": False,
                        }
        
        # Check permissions dimension
        permissions_subgraph = kg.get_subgraph("permissions")
        if permissions_subgraph:
            # Look for ENABLES edge from action to service
            has_permission = False
            for edge in permissions_subgraph.edges:
                if edge.source_id == action and edge.target_id == service_id:
                    if edge.edge_type == EdgeType.ENABLES:
                        has_permission = True
                        break
            
            if not has_permission and action != "get_logs":
                # Get service environment to provide helpful error
                system_state = self.api.get_system_state(context)
                services = system_state.get("services", {})
                service_data = services.get(service_id, {})
                env = service_data.get("environment", "unknown")
                
                return {
                    "valid": False,
                    "reason": f"User {context.user.name} ({context.user.role.value}) lacks permission for {action} on {env} environment",
                    "safety_violation": True,  # Permission violation is a safety issue
                }
        
        return {"valid": True}
    
    def _execute_action(
        self,
        action: str,
        parameters: Dict[str, Any],
        context: SessionContext,
        token_count: int,
        graph_traversals: int
    ) -> MuteAgentResult:
        """Execute the validated action."""
        # Map action to API call
        if action == "restart_service":
            result = self.api.restart_service(parameters["service_id"], context)
        elif action == "scale_service":
            result = self.api.scale_service(
                parameters["service_id"],
                parameters["replicas"],
                context
            )
        elif action == "rollback_deployment":
            result = self.api.rollback_deployment(parameters["deployment_id"], context)
        elif action == "force_delete":
            result = self.api.force_delete(parameters["service_id"], context)
        else:
            result = {"error": "Unknown action"}
        
        success = result.get("success", False)
        safety_violation = result.get("safety_violation", False)
        
        return MuteAgentResult(
            success=success,
            action_taken=action,
            parameters_used=parameters,
            final_result=result if success else None,
            constraint_violation=result.get("error") if not success else None,
            blocked_by_graph=False,
            safety_violation=safety_violation,
            state_misalignment=False,
            token_count=token_count,
            graph_traversals=graph_traversals,
            latency_ms=0,  # Will be set by caller
        )
    
    def get_statistics(self) -> Dict[str, Any]:
        """Get performance statistics."""
        if not self.execution_history:
            return {}
        
        total = len(self.execution_history)
        successful = len([r for r in self.execution_history if r.success])
        blocked = len([r for r in self.execution_history if r.blocked_by_graph])
        safety_violations = len([r for r in self.execution_history if r.safety_violation])
        
        avg_tokens = sum(r.token_count for r in self.execution_history) / total
        avg_latency = sum(r.latency_ms for r in self.execution_history) / total
        avg_traversals = sum(r.graph_traversals for r in self.execution_history) / total
        
        return {
            "total_executions": total,
            "success_rate": successful / total if total > 0 else 0,
            "blocked_by_graph_rate": blocked / total if total > 0 else 0,
            "safety_violation_rate": safety_violations / total if total > 0 else 0,
            "avg_tokens": avg_tokens,
            "avg_latency_ms": avg_latency,
            "avg_graph_traversals": avg_traversals,
        }
