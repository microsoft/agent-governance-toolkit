# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

"""
Constraint Graphs - Multi-Dimensional Context

Context in an enterprise isn't flat; it's a graph. The Constraint Graph system
provides multi-dimensional constraints that act as the "physics" of the agent's world.

Three types of graphs:
1. Data Graph: Tables, schemas, and data the agent can access
2. Policy Graph: Corporate rules (e.g., "No PII in output")
3. Temporal Graph: What is true RIGHT NOW (e.g., "Maintenance Window is Active")

If an agent tries to access something that exists in the Data Graph but is
blocked in the Policy Graph, the Control Plane intercepts it. The request
never even reaches the database.

Research Foundations:
    - Context-aware access control from ABAC research (NIST SP 800-162)
    - Multi-dimensional policy evaluation
    - Graph-based constraint modeling for complex policy interactions
    - Temporal logic for time-based constraints
    - Privacy controls informed by "Privacy in Agentic Systems" (arXiv:2409.1087, 2024)

See docs/RESEARCH_FOUNDATION.md for complete references.
"""

from typing import Any, Dict, List, Optional, Set, Callable, Tuple
from dataclasses import dataclass, field
from datetime import datetime, time
from enum import Enum
from .agent_kernel import ExecutionRequest, ActionType


class GraphNodeType(Enum):
    """Types of nodes in constraint graphs"""
    DATA_RESOURCE = "data_resource"
    POLICY_RULE = "policy_rule"
    TEMPORAL_CONSTRAINT = "temporal_constraint"
    AGENT_ROLE = "agent_role"


@dataclass
class GraphNode:
    """A node in a constraint graph"""
    node_id: str
    node_type: GraphNodeType
    name: str
    properties: Dict[str, Any] = field(default_factory=dict)
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class GraphEdge:
    """An edge connecting nodes in a constraint graph"""
    from_node: str
    to_node: str
    edge_type: str  # e.g., "blocks", "allows", "requires", "inherits"
    properties: Dict[str, Any] = field(default_factory=dict)


class ConstraintGraph:
    """Base class for constraint graphs"""
    
    def __init__(self, name: str):
        self.name = name
        self.nodes: Dict[str, GraphNode] = {}
        self.edges: List[GraphEdge] = []
    
    def add_node(self, node: GraphNode):
        """Add a node to the graph"""
        self.nodes[node.node_id] = node
    
    def add_edge(self, edge: GraphEdge):
        """Add an edge to the graph"""
        self.edges.append(edge)
    
    def get_node(self, node_id: str) -> Optional[GraphNode]:
        """Get a node by ID"""
        return self.nodes.get(node_id)
    
    def get_edges_from(self, node_id: str) -> List[GraphEdge]:
        """Get all edges originating from a node"""
        return [e for e in self.edges if e.from_node == node_id]
    
    def get_edges_to(self, node_id: str) -> List[GraphEdge]:
        """Get all edges pointing to a node"""
        return [e for e in self.edges if e.to_node == node_id]
    
    def is_allowed(self, from_node: str, to_node: str) -> bool:
        """Check if there's an 'allows' edge between nodes"""
        return any(
            e.from_node == from_node and e.to_node == to_node and e.edge_type == "allows"
            for e in self.edges
        )
    
    def is_blocked(self, from_node: str, to_node: str) -> bool:
        """Check if there's a 'blocks' edge between nodes"""
        return any(
            e.from_node == from_node and e.to_node == to_node and e.edge_type == "blocks"
            for e in self.edges
        )


class DataGraph(ConstraintGraph):
    """
    Data Graph - Defines what data resources exist and can be accessed.
    
    Examples:
    - Database tables and schemas
    - File systems and directories
    - API endpoints
    - Data lakes and warehouses
    """
    
    def __init__(self):
        super().__init__("DataGraph")
    
    def add_database_table(self, table_name: str, schema: Dict[str, Any], metadata: Optional[Dict] = None):
        """Add a database table to the graph"""
        node = GraphNode(
            node_id=f"table:{table_name}",
            node_type=GraphNodeType.DATA_RESOURCE,
            name=table_name,
            properties={"schema": schema, "resource_type": "database_table"},
            metadata=metadata or {}
        )
        self.add_node(node)
    
    def add_file_path(self, path: str, access_level: str = "read", metadata: Optional[Dict] = None):
        """Add a file path to the graph"""
        node = GraphNode(
            node_id=f"file:{path}",
            node_type=GraphNodeType.DATA_RESOURCE,
            name=path,
            properties={"resource_type": "file", "access_level": access_level},
            metadata=metadata or {}
        )
        self.add_node(node)
    
    def add_api_endpoint(self, endpoint: str, methods: List[str], metadata: Optional[Dict] = None):
        """Add an API endpoint to the graph"""
        node = GraphNode(
            node_id=f"api:{endpoint}",
            node_type=GraphNodeType.DATA_RESOURCE,
            name=endpoint,
            properties={"resource_type": "api", "methods": methods},
            metadata=metadata or {}
        )
        self.add_node(node)
    
    def get_accessible_tables(self) -> List[str]:
        """Get all accessible database tables"""
        return [
            node.name for node in self.nodes.values()
            if node.properties.get("resource_type") == "database_table"
        ]
    
    def get_accessible_paths(self) -> List[str]:
        """Get all accessible file paths"""
        return [
            node.name for node in self.nodes.values()
            if node.properties.get("resource_type") == "file"
        ]


class PolicyGraph(ConstraintGraph):
    """
    Policy Graph - Defines corporate rules and compliance constraints.
    
    Examples:
    - "No PII in output"
    - "Finance data requires approval"
    - "Healthcare data is HIPAA protected"
    - "Cannot access production during deployment"
    """
    
    def __init__(self):
        super().__init__("PolicyGraph")
    
    def add_policy_rule(
        self,
        rule_id: str,
        name: str,
        applies_to: List[str],  # Node IDs this rule applies to
        rule_type: str,  # "allow", "deny", "require_approval"
        validator: Optional[Callable] = None
    ):
        """Add a policy rule to the graph"""
        node = GraphNode(
            node_id=f"policy:{rule_id}",
            node_type=GraphNodeType.POLICY_RULE,
            name=name,
            properties={
                "rule_type": rule_type,
                "applies_to": applies_to,
                "validator": validator
            }
        )
        self.add_node(node)
        
        # Create edges to resources this policy applies to
        for resource_id in applies_to:
            edge = GraphEdge(
                from_node=node.node_id,
                to_node=resource_id,
                edge_type=rule_type
            )
            self.add_edge(edge)
    
    def add_pii_protection(self, resource_ids: List[str]):
        """Add PII protection policy to resources"""
        self.add_policy_rule(
            rule_id="pii_protection",
            name="No PII in output",
            applies_to=resource_ids,
            rule_type="deny",
            validator=lambda req: not self._contains_pii(req.parameters)
        )
    
    def add_approval_requirement(self, resource_ids: List[str], approver_role: str):
        """Add approval requirement for resources"""
        self.add_policy_rule(
            rule_id=f"require_approval_{approver_role}",
            name=f"Requires approval from {approver_role}",
            applies_to=resource_ids,
            rule_type="require_approval",
        )
    
    @staticmethod
    def _contains_pii(parameters: Dict[str, Any]) -> bool:
        """Check if parameters might contain PII"""
        pii_keywords = ['ssn', 'social_security', 'email', 'phone', 'address', 'credit_card']
        params_str = str(parameters).lower()
        return any(keyword in params_str for keyword in pii_keywords)
    
    def check_policy_violations(self, agent_role: str, resource_id: str) -> List[str]:
        """Check if accessing a resource would violate policies"""
        violations = []
        
        # Find policies that apply to this resource
        for edge in self.get_edges_to(resource_id):
            if edge.edge_type == "deny":
                policy_node = self.get_node(edge.from_node)
                violations.append(f"Policy '{policy_node.name}' blocks access to resource '{resource_id}' for role '{agent_role}'")
        
        return violations


class TemporalGraph(ConstraintGraph):
    """
    Temporal Graph - Defines what is true RIGHT NOW.
    
    Examples:
    - "Maintenance Window is Active (no writes)"
    - "Business hours (9-5 EST)"
    - "End of quarter freeze period"
    - "Peak traffic hours (throttle)"
    """
    
    def __init__(self):
        super().__init__("TemporalGraph")
        self.time_constraints: Dict[str, Callable[[], bool]] = {}
    
    def add_maintenance_window(
        self,
        window_id: str,
        start_time: time,
        end_time: time,
        blocked_actions: List[ActionType]
    ):
        """Add a maintenance window constraint"""
        node = GraphNode(
            node_id=f"temporal:{window_id}",
            node_type=GraphNodeType.TEMPORAL_CONSTRAINT,
            name=f"Maintenance Window: {start_time}-{end_time}",
            properties={
                "start_time": start_time,
                "end_time": end_time,
                "blocked_actions": blocked_actions
            }
        )
        self.add_node(node)
        
        # Add constraint checker
        self.time_constraints[window_id] = lambda: self._is_in_time_range(start_time, end_time)
    
    def add_business_hours(
        self,
        hours_id: str,
        start_time: time,
        end_time: time,
        required_for: List[ActionType]
    ):
        """Add business hours constraint"""
        node = GraphNode(
            node_id=f"temporal:{hours_id}",
            node_type=GraphNodeType.TEMPORAL_CONSTRAINT,
            name=f"Business Hours: {start_time}-{end_time}",
            properties={
                "start_time": start_time,
                "end_time": end_time,
                "required_for": required_for
            }
        )
        self.add_node(node)
        
        self.time_constraints[hours_id] = lambda: self._is_in_time_range(start_time, end_time)
    
    def add_freeze_period(
        self,
        freeze_id: str,
        start_date: datetime,
        end_date: datetime,
        reason: str
    ):
        """Add a freeze period (e.g., end of quarter, holidays)"""
        node = GraphNode(
            node_id=f"temporal:{freeze_id}",
            node_type=GraphNodeType.TEMPORAL_CONSTRAINT,
            name=f"Freeze Period: {reason}",
            properties={
                "start_date": start_date,
                "end_date": end_date,
                "reason": reason
            }
        )
        self.add_node(node)
        
        self.time_constraints[freeze_id] = lambda: self._is_in_date_range(start_date, end_date)
    
    @staticmethod
    def _is_in_time_range(start_time: time, end_time: time) -> bool:
        """Check if current time is within range"""
        now = datetime.now().time()
        if start_time <= end_time:
            # Normal range (e.g., 9:00 to 17:00)
            return start_time <= now <= end_time
        else:
            # Crosses midnight (e.g., 23:00 to 01:00)
            return now >= start_time or now <= end_time
    
    @staticmethod
    def _is_in_date_range(start_date: datetime, end_date: datetime) -> bool:
        """Check if current date is within range"""
        now = datetime.now()
        return start_date <= now <= end_date
    
    def is_action_allowed_now(self, action_type: ActionType) -> Tuple[bool, Optional[str]]:
        """Check if an action is allowed at the current time"""
        for node in self.nodes.values():
            if node.node_type == GraphNodeType.TEMPORAL_CONSTRAINT:
                # Check maintenance windows
                blocked_actions = node.properties.get("blocked_actions", [])
                if action_type in blocked_actions:
                    constraint_id = node.node_id.split(":")[-1]
                    if self.time_constraints.get(constraint_id, lambda: False)():
                        return False, f"Action blocked by: {node.name}"
                
                # Check business hours requirements
                required_for = node.properties.get("required_for", [])
                if action_type in required_for:
                    constraint_id = node.node_id.split(":")[-1]
                    if not self.time_constraints.get(constraint_id, lambda: True)():
                        return False, f"Action requires: {node.name}"
        
        return True, None


class ConstraintGraphValidator:
    """
    Validates requests against multi-dimensional constraint graphs.
    
    This is deterministic enforcement. The LLM can "think" whatever it wants,
    but it can only ACT on what the graphs permit.
    """
    
    def __init__(
        self,
        data_graph: DataGraph,
        policy_graph: PolicyGraph,
        temporal_graph: TemporalGraph
    ):
        self.data_graph = data_graph
        self.policy_graph = policy_graph
        self.temporal_graph = temporal_graph
        self.validation_log: List[Dict[str, Any]] = []
    
    def validate_request(self, request: ExecutionRequest) -> Tuple[bool, List[str]]:
        """
        Validate request against all constraint graphs.
        
        Returns:
            (is_valid, reasons_if_invalid)
        """
        violations = []
        
        # 1. Check Data Graph - does the resource exist and is it accessible?
        data_valid, data_reason = self._validate_data_graph(request)
        if not data_valid:
            violations.append(f"Data Graph: {data_reason}")
        
        # 2. Check Policy Graph - does this violate any policies?
        policy_valid, policy_reasons = self._validate_policy_graph(request)
        if not policy_valid:
            violations.extend([f"Policy Graph: {r}" for r in policy_reasons])
        
        # 3. Check Temporal Graph - is this allowed right now?
        temporal_valid, temporal_reason = self._validate_temporal_graph(request)
        if not temporal_valid:
            violations.append(f"Temporal Graph: {temporal_reason}")
        
        # Log validation
        self.validation_log.append({
            "request_id": request.request_id,
            "timestamp": datetime.now().isoformat(),
            "valid": len(violations) == 0,
            "violations": violations
        })
        
        return len(violations) == 0, violations
    
    def _validate_data_graph(self, request: ExecutionRequest) -> Tuple[bool, Optional[str]]:
        """Validate against data graph"""
        # Check if accessing a database table
        if request.action_type in [ActionType.DATABASE_QUERY, ActionType.DATABASE_WRITE]:
            table = request.parameters.get('table', request.parameters.get('database'))
            if table:
                node = self.data_graph.get_node(f"table:{table}")
                if not node:
                    return False, f"Table '{table}' not in accessible data graph"
        
        # Check if accessing a file
        elif request.action_type in [ActionType.FILE_READ, ActionType.FILE_WRITE]:
            path = request.parameters.get('path')
            if path:
                # Check if path is in data graph
                accessible_paths = self.data_graph.get_accessible_paths()
                if not any(path.startswith(p) for p in accessible_paths):
                    return False, f"Path '{path}' not in accessible data graph"
        
        return True, None
    
    def _validate_policy_graph(self, request: ExecutionRequest) -> Tuple[bool, List[str]]:
        """Validate against policy graph"""
        violations = []
        
        # Build resource ID based on action type
        resource_id = self._build_resource_id(request)
        if resource_id:
            policy_violations = self.policy_graph.check_policy_violations(
                request.agent_context.agent_id,
                resource_id
            )
            violations.extend(policy_violations)
        
        return len(violations) == 0, violations
    
    def _validate_temporal_graph(self, request: ExecutionRequest) -> Tuple[bool, Optional[str]]:
        """Validate against temporal graph"""
        allowed, reason = self.temporal_graph.is_action_allowed_now(request.action_type)
        return allowed, reason
    
    @staticmethod
    def _build_resource_id(request: ExecutionRequest) -> Optional[str]:
        """Build a resource ID from the request"""
        if request.action_type in [ActionType.DATABASE_QUERY, ActionType.DATABASE_WRITE]:
            table = request.parameters.get('table', request.parameters.get('database'))
            return f"table:{table}" if table else None
        elif request.action_type in [ActionType.FILE_READ, ActionType.FILE_WRITE]:
            path = request.parameters.get('path')
            return f"file:{path}" if path else None
        return None
    
    def get_validation_log(self) -> List[Dict[str, Any]]:
        """Get validation log"""
        return self.validation_log.copy()
