# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""
Configuration Examples for Agent Control Plane

This file shows how to configure agents with different profiles.
"""

from agent_control_plane import AgentControlPlane
from agent_control_plane.agent_kernel import ActionType, PermissionLevel, PolicyRule
from agent_control_plane.policy_engine import ResourceQuota, RiskPolicy
import uuid


# Configuration Profile 1: Development/Testing Agent
def create_dev_agent_config():
    """Configuration for development and testing"""
    permissions = {
        ActionType.FILE_READ: PermissionLevel.READ_ONLY,
        ActionType.FILE_WRITE: PermissionLevel.READ_WRITE,
        ActionType.CODE_EXECUTION: PermissionLevel.READ_WRITE,
        ActionType.API_CALL: PermissionLevel.READ_WRITE,
    }
    
    quota = ResourceQuota(
        agent_id="dev-agent",
        max_requests_per_minute=120,
        max_requests_per_hour=2000,
        max_concurrent_executions=10,
        allowed_action_types=[
            ActionType.FILE_READ,
            ActionType.FILE_WRITE,
            ActionType.CODE_EXECUTION,
            ActionType.API_CALL,
        ]
    )
    
    return permissions, quota


# Configuration Profile 2: Production Agent (Strict)
def create_production_agent_config():
    """Configuration for production with strict limits"""
    permissions = {
        ActionType.FILE_READ: PermissionLevel.READ_ONLY,
        ActionType.API_CALL: PermissionLevel.READ_WRITE,
        ActionType.DATABASE_QUERY: PermissionLevel.READ_ONLY,
        ActionType.WORKFLOW_TRIGGER: PermissionLevel.READ_WRITE,
    }
    
    quota = ResourceQuota(
        agent_id="prod-agent",
        max_requests_per_minute=30,
        max_requests_per_hour=500,
        max_concurrent_executions=3,
        allowed_action_types=[
            ActionType.FILE_READ,
            ActionType.API_CALL,
            ActionType.DATABASE_QUERY,
            ActionType.WORKFLOW_TRIGGER,
        ]
    )
    
    return permissions, quota


# Configuration Profile 3: Data Analysis Agent
def create_analytics_agent_config():
    """Configuration for data analysis workloads"""
    permissions = {
        ActionType.FILE_READ: PermissionLevel.READ_ONLY,
        ActionType.DATABASE_QUERY: PermissionLevel.READ_ONLY,
        ActionType.CODE_EXECUTION: PermissionLevel.READ_WRITE,
    }
    
    quota = ResourceQuota(
        agent_id="analytics-agent",
        max_requests_per_minute=60,
        max_requests_per_hour=1000,
        max_concurrent_executions=5,
        allowed_action_types=[
            ActionType.FILE_READ,
            ActionType.DATABASE_QUERY,
            ActionType.CODE_EXECUTION,
        ]
    )
    
    return permissions, quota


# Configuration Profile 4: Integration Agent
def create_integration_agent_config():
    """Configuration for API integration workloads"""
    permissions = {
        ActionType.API_CALL: PermissionLevel.READ_WRITE,
        ActionType.FILE_READ: PermissionLevel.READ_ONLY,
        ActionType.FILE_WRITE: PermissionLevel.READ_WRITE,
    }
    
    quota = ResourceQuota(
        agent_id="integration-agent",
        max_requests_per_minute=90,
        max_requests_per_hour=1500,
        max_concurrent_executions=8,
        allowed_action_types=[
            ActionType.API_CALL,
            ActionType.FILE_READ,
            ActionType.FILE_WRITE,
        ]
    )
    
    return permissions, quota


# Risk Policy Configurations

def create_strict_risk_policy():
    """Strict risk policy for sensitive environments"""
    return RiskPolicy(
        max_risk_score=0.3,
        require_approval_above=0.5,
        deny_above=0.7,
        blocked_domains=[
            "malicious.com",
            "untrusted.net",
            "suspicious.org"
        ],
        allowed_domains=[
            "trusted-api.com",
            "internal.company.com"
        ]
    )


def create_balanced_risk_policy():
    """Balanced risk policy for general use"""
    return RiskPolicy(
        max_risk_score=0.6,
        require_approval_above=0.8,
        deny_above=0.9,
        blocked_domains=[
            "malicious.com",
            "dangerous.net"
        ]
    )


def create_permissive_risk_policy():
    """Permissive risk policy for development"""
    return RiskPolicy(
        max_risk_score=0.8,
        require_approval_above=0.9,
        deny_above=0.95,
        blocked_domains=[]
    )


# Custom Policy Rules

def create_data_protection_policies():
    """Policies to protect sensitive data"""
    
    def no_pii_access(request):
        """Prevent access to files containing PII"""
        path = request.parameters.get('path', '')
        sensitive_patterns = ['pii', 'personal', 'ssn', 'credit_card']
        return not any(pattern in path.lower() for pattern in sensitive_patterns)
    
    def no_production_db_writes(request):
        """Prevent writes to production databases"""
        if request.action_type == ActionType.DATABASE_WRITE:
            db_name = request.parameters.get('database', '')
            return 'prod' not in db_name.lower() and 'production' not in db_name.lower()
        return True
    
    def require_code_review(request):
        """Flag code execution for review (simplified)"""
        # In real implementation, this would integrate with review system
        return True
    
    return [
        PolicyRule(
            rule_id=str(uuid.uuid4()),
            name="no_pii_access",
            description="Prevent access to PII data",
            action_types=[ActionType.FILE_READ, ActionType.FILE_WRITE],
            validator=no_pii_access,
            priority=10
        ),
        PolicyRule(
            rule_id=str(uuid.uuid4()),
            name="no_production_db_writes",
            description="Prevent writes to production databases",
            action_types=[ActionType.DATABASE_WRITE],
            validator=no_production_db_writes,
            priority=10
        ),
        PolicyRule(
            rule_id=str(uuid.uuid4()),
            name="require_code_review",
            description="Require review for code execution",
            action_types=[ActionType.CODE_EXECUTION],
            validator=require_code_review,
            priority=5
        ),
    ]


# Example: Setting up a complete environment

def setup_production_environment():
    """Set up a complete production environment"""
    
    # Create control plane
    control_plane = AgentControlPlane()
    
    # Add data protection policies
    for policy in create_data_protection_policies():
        control_plane.add_policy_rule(policy)
    
    # Set strict risk policy
    control_plane.set_risk_policy("strict", create_strict_risk_policy())
    
    # Create production agent
    permissions, quota = create_production_agent_config()
    agent = control_plane.create_agent("prod-agent-001", permissions, quota)
    
    print("✓ Production environment configured")
    print(f"  Agent ID: {agent.agent_id}")
    print(f"  Policies: {len(control_plane.kernel.policy_rules)}")
    print(f"  Rate limit: {quota.max_requests_per_minute}/min")
    
    return control_plane, agent


def setup_development_environment():
    """Set up a development environment"""
    
    # Create control plane with default policies
    control_plane = AgentControlPlane()
    
    # Set permissive risk policy
    control_plane.set_risk_policy("permissive", create_permissive_risk_policy())
    
    # Create dev agent
    permissions, quota = create_dev_agent_config()
    agent = control_plane.create_agent("dev-agent-001", permissions, quota)
    
    print("✓ Development environment configured")
    print(f"  Agent ID: {agent.agent_id}")
    print(f"  Rate limit: {quota.max_requests_per_minute}/min")
    
    return control_plane, agent


if __name__ == "__main__":
    print("=== Agent Configuration Examples ===\n")
    
    print("1. Production Environment:")
    prod_cp, prod_agent = setup_production_environment()
    print()
    
    print("2. Development Environment:")
    dev_cp, dev_agent = setup_development_environment()
    print()
    
    print("Configuration examples completed!")
