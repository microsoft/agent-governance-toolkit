# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""
The Face - The Reasoning Agent
"""

from typing import Dict, List, Optional, Any
from ..knowledge_graph.multidimensional_graph import MultidimensionalKnowledgeGraph
from ..knowledge_graph.graph_elements import Node, NodeType
from ..super_system.router import SuperSystemRouter, RoutingResult
from .handshake_protocol import (
    HandshakeProtocol,
    ActionProposal,
    ValidationResult,
    HandshakeSession,
    HandshakeState
)


class ReasoningAgent:
    """
    The Face - The Reasoning Agent
    
    This agent is responsible for reasoning about actions and negotiating
    with the Execution Agent through the Handshake Protocol. It does not
    execute actions directly but proposes them based on graph constraints.
    """
    
    # Maximum size for reasoning history to prevent memory bloat
    MAX_HISTORY_SIZE = 1000
    
    def __init__(
        self,
        knowledge_graph: MultidimensionalKnowledgeGraph,
        router: SuperSystemRouter,
        protocol: HandshakeProtocol
    ):
        self.knowledge_graph = knowledge_graph
        self.router = router
        self.protocol = protocol
        self.reasoning_history: List[Dict[str, Any]] = []
    
    def reason(self, context: Dict[str, Any]) -> RoutingResult:
        """
        Reason about the context and determine available actions.
        This uses the Super System Router to prune the action space.
        """
        routing_result = self.router.route(context)
        
        # Store reasoning step (with size limit to prevent memory bloat)
        self.reasoning_history.append({
            "context": context,
            "selected_dimensions": routing_result.selected_dimensions,
            "available_actions": len(routing_result.pruned_action_space)
        })
        
        # Trim history if it exceeds maximum size
        if len(self.reasoning_history) > self.MAX_HISTORY_SIZE:
            self.reasoning_history = self.reasoning_history[-self.MAX_HISTORY_SIZE:]
        
        return routing_result
    
    def propose_action(
        self,
        action_id: str,
        parameters: Dict[str, Any],
        context: Dict[str, Any],
        justification: str
    ) -> HandshakeSession:
        """
        Propose an action for execution.
        This initiates the handshake protocol.
        """
        # Create proposal
        proposal = ActionProposal(
            action_id=action_id,
            parameters=parameters,
            context=context,
            justification=justification
        )
        
        # Initiate handshake
        session = self.protocol.initiate_handshake(proposal)
        
        # Validate the proposal against the knowledge graph
        validation_result = self._validate_proposal(proposal)
        
        # Update session with validation
        self.protocol.validate_proposal(session.session_id, validation_result)
        
        return self.protocol.get_session(session.session_id)
    
    def _validate_proposal(self, proposal: ActionProposal) -> ValidationResult:
        """
        Validate a proposal against the knowledge graph constraints.
        This is the core constraint checking mechanism with deep dependency resolution.
        """
        errors = []
        warnings = []
        constraints_met = []
        constraints_violated = []
        
        # Get routing result for the context
        routing_result = self.router.route(proposal.context)
        
        # Check if action exists in pruned action space
        action_available = any(
            node.id == proposal.action_id
            for node in routing_result.pruned_action_space
        )
        
        if not action_available:
            errors.append(
                f"Action {proposal.action_id} not available in pruned action space"
            )
            return ValidationResult(
                is_valid=False,
                errors=errors,
                warnings=warnings,
                constraints_met=constraints_met,
                constraints_violated=constraints_violated
            )
        
        # Deep dependency checking - find all missing dependencies across dimensions
        all_missing_deps = self.knowledge_graph.find_all_missing_dependencies(
            proposal.action_id,
            routing_result.selected_dimensions,
            proposal.context
        )
        
        # If there are missing dependencies, provide detailed error messages
        if all_missing_deps:
            for dim_name, missing_deps in all_missing_deps.items():
                for dep_id in missing_deps:
                    errors.append(
                        f"Missing dependency '{dep_id}' in dimension '{dim_name}'. "
                        f"Please satisfy this requirement first."
                    )
                constraints_violated.append(dim_name)
            
            # Early return if dependencies are missing - no need for further validation
            is_valid = False
        else:
            # Only validate constraints if no missing dependencies
            for dim_name in routing_result.selected_dimensions:
                # Check if action is valid in this dimension
                subgraph = self.knowledge_graph.get_subgraph(dim_name)
                if not subgraph:
                    continue
                
                if not subgraph.validate_action(proposal.action_id, proposal.context):
                    if dim_name not in constraints_violated:
                        errors.append(
                            f"Action {proposal.action_id} fails validation in dimension {dim_name}"
                        )
                        constraints_violated.append(dim_name)
                else:
                    if dim_name not in constraints_violated:
                        constraints_met.append(dim_name)
                
                # Check specific constraints
                constraints = self.knowledge_graph.get_action_constraints(
                    proposal.action_id,
                    dim_name
                )
                
                for constraint in constraints:
                    if not self._check_constraint(constraint, proposal):
                        warnings.append(
                            f"Constraint {constraint.id} may not be fully satisfied"
                        )
            
            is_valid = len(errors) == 0
        
        return ValidationResult(
            is_valid=is_valid,
            errors=errors,
            warnings=warnings,
            constraints_met=constraints_met,
            constraints_violated=constraints_violated
        )
    
    def _check_constraint(
        self,
        constraint: Node,
        proposal: ActionProposal
    ) -> bool:
        """Check if a specific constraint is satisfied."""
        # Check if proposal parameters satisfy constraint attributes
        for key, value in constraint.attributes.items():
            if key in proposal.parameters:
                if proposal.parameters[key] != value:
                    return False
        return True
    
    def select_best_action(
        self,
        context: Dict[str, Any],
        selection_criteria: Optional[Dict[str, Any]] = None
    ) -> Optional[Node]:
        """
        Select the best action from the available action space.
        This can use various selection criteria.
        """
        routing_result = self.router.route(context)
        
        if not routing_result.pruned_action_space:
            return None
        
        # If no criteria specified, return first action
        if not selection_criteria:
            return routing_result.pruned_action_space[0]
        
        # Apply selection criteria
        scored_actions = []
        for action in routing_result.pruned_action_space:
            score = self._score_action(action, selection_criteria)
            scored_actions.append((score, action))
        
        # Sort by score and return best
        scored_actions.sort(reverse=True, key=lambda x: x[0])
        return scored_actions[0][1] if scored_actions else None
    
    def _score_action(
        self,
        action: Node,
        criteria: Dict[str, Any]
    ) -> float:
        """Score an action based on selection criteria."""
        score = 0.0
        
        # Match attributes
        for key, value in criteria.items():
            if key in action.attributes:
                if action.attributes[key] == value:
                    score += 1.0
        
        return score
