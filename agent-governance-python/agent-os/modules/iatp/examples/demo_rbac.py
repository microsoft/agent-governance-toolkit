#!/usr/bin/env python3
# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""
Demo: RBAC (Role-Based Access Control) with IATP

This demo showcases how different agent types can have different permissions:
- Coder Agent: Has both read and write access (repo:read, repo:write)
- Reviewer Agent: Has only read access (repo:read)

The handshake validation ensures agents have required scopes before proceeding.
"""

from typing import List

from iatp.models import (
    AgentCapabilities,
    CapabilityManifest,
    PrivacyContract,
    RetentionPolicy,
    ReversibilityLevel,
    TrustLevel,
)
from iatp.policy_engine import IATPPolicyEngine


def create_coder_agent_manifest() -> CapabilityManifest:
    """Create a manifest for a Coder Agent with write permissions."""
    return CapabilityManifest(
        agent_id="coder-agent-v1.0",
        agent_version="1.0.0",
        trust_level=TrustLevel.TRUSTED,
        capabilities=AgentCapabilities(
            idempotency=True,
            reversibility=ReversibilityLevel.FULL,
            undo_window="24h",
            sla_latency="2000ms"
        ),
        privacy_contract=PrivacyContract(
            retention=RetentionPolicy.EPHEMERAL,
            storage_location="us-west",
            human_review=False,
            encryption_at_rest=True,
            encryption_in_transit=True,
        ),
        scopes=["repo:read", "repo:write"]  # Full access
    )


def create_reviewer_agent_manifest() -> CapabilityManifest:
    """Create a manifest for a Reviewer Agent with read-only permissions."""
    return CapabilityManifest(
        agent_id="reviewer-agent-v1.0",
        agent_version="1.0.0",
        trust_level=TrustLevel.STANDARD,
        capabilities=AgentCapabilities(
            idempotency=True,
            reversibility=ReversibilityLevel.NONE,
            sla_latency="1000ms"
        ),
        privacy_contract=PrivacyContract(
            retention=RetentionPolicy.TEMPORARY,
            storage_location="us-east",
            human_review=False,
            encryption_at_rest=True,
            encryption_in_transit=True,
        ),
        scopes=["repo:read"]  # Read-only access
    )


def validate_agent(manifest: CapabilityManifest, operation: str, required_scopes: List[str]):
    """Validate an agent's permissions for a specific operation."""
    engine = IATPPolicyEngine()
    
    print(f"\n{'='*70}")
    print(f"Agent: {manifest.agent_id}")
    print(f"Operation: {operation}")
    print(f"Agent Scopes: {manifest.scopes}")
    print(f"Required Scopes: {required_scopes}")
    print(f"{'='*70}")
    
    is_compatible, error_msg = engine.validate_handshake(
        manifest,
        required_scopes=required_scopes
    )
    
    if is_compatible:
        print(f"✅ SUCCESS: Agent authorized for {operation}")
        print(f"   Trust Level: {manifest.trust_level.value}")
        print(f"   Trust Score: {manifest.calculate_trust_score()}/10")
    else:
        print(f"❌ DENIED: Agent not authorized for {operation}")
        print(f"   Reason: {error_msg}")
    
    return is_compatible


def main():
    """Run RBAC demo scenarios."""
    print("\n" + "="*70)
    print("IATP RBAC (Role-Based Access Control) Demo")
    print("="*70)
    
    # Create agent manifests
    coder = create_coder_agent_manifest()
    reviewer = create_reviewer_agent_manifest()
    
    # Scenario 1: Coder Agent attempting write operation (should succeed)
    print("\n\n📝 SCENARIO 1: Coder Agent Writing Code")
    validate_agent(coder, "Write code to repository", ["repo:write"])
    
    # Scenario 2: Coder Agent attempting read operation (should succeed)
    print("\n\n📖 SCENARIO 2: Coder Agent Reading Code")
    validate_agent(coder, "Read code from repository", ["repo:read"])
    
    # Scenario 3: Reviewer Agent attempting read operation (should succeed)
    print("\n\n👀 SCENARIO 3: Reviewer Agent Reading Code")
    validate_agent(reviewer, "Read code from repository", ["repo:read"])
    
    # Scenario 4: Reviewer Agent attempting write operation (should fail)
    print("\n\n🚫 SCENARIO 4: Reviewer Agent Attempting to Write Code")
    validate_agent(reviewer, "Write code to repository", ["repo:write"])
    
    # Scenario 5: Agent requiring multiple scopes
    print("\n\n🔐 SCENARIO 5: Admin Operation Requiring Multiple Scopes")
    validate_agent(coder, "Deploy changes", ["repo:read", "repo:write"])
    
    # Scenario 6: Reviewer attempting admin operation
    print("\n\n⛔ SCENARIO 6: Reviewer Attempting Admin Operation")
    validate_agent(reviewer, "Deploy changes", ["repo:read", "repo:write"])
    
    print("\n\n" + "="*70)
    print("Demo Complete!")
    print("="*70)
    print("\nKey Takeaways:")
    print("1. Coder Agent (repo:write) can perform both read and write operations")
    print("2. Reviewer Agent (repo:read) can only perform read operations")
    print("3. RBAC scopes are enforced during handshake validation")
    print("4. Missing scopes result in clear error messages")
    print("="*70 + "\n")


if __name__ == "__main__":
    main()
