# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""
Integration example demonstrating Agent Attestation and Reputation Slashing.

This example shows:
1. Creating an attestation for an agent
2. Setting up agents with attestation
3. Simulating hallucination detection and reputation slashing
4. Network-wide reputation propagation
"""
import asyncio
from iatp import (
    CapabilityManifest,
    AgentCapabilities,
    PrivacyContract,
    TrustLevel,
    ReversibilityLevel,
    RetentionPolicy,
    AttestationRecord,
)
from iatp.attestation import AttestationValidator, ReputationManager


def demo_attestation():
    """Demonstrate agent attestation functionality."""
    print("\n" + "=" * 80)
    print("DEMO 1: Agent Attestation (Verifiable Credentials)")
    print("=" * 80)
    
    # Create an attestation validator (Control Plane)
    validator = AttestationValidator()
    
    # Add a trusted Control Plane public key
    validator.add_trusted_key(
        key_id="control-plane-prod-2026",
        public_key="-----BEGIN PUBLIC KEY-----\nMFkwEwYHKoZIzj...\n-----END PUBLIC KEY-----"
    )
    print("✓ Control Plane public key registered")
    
    # Compute codebase hash
    agent_code = "def process_request(data): return data"
    codebase_hash = validator.compute_codebase_hash(agent_code)
    config_hash = validator.compute_codebase_hash('{"timeout": 30}')
    
    print(f"✓ Codebase hash: {codebase_hash[:16]}...")
    print(f"✓ Config hash: {config_hash[:16]}...")
    
    # Create attestation (done by Control Plane)
    attestation = validator.create_attestation(
        agent_id="banking-agent-v1.2.3",
        codebase_hash=codebase_hash,
        config_hash=config_hash,
        signing_key_id="control-plane-prod-2026",
        expires_in_hours=24
    )
    print(f"✓ Attestation created: {attestation.agent_id}")
    print(f"  Expires: {attestation.expires_at}")
    
    # Validate attestation (done by receiving agent)
    is_valid, error = validator.validate_attestation(
        attestation,
        verify_signature=False  # Simplified for demo
    )
    
    if is_valid:
        print("✅ Attestation VALID - Agent is running verified code")
    else:
        print(f"❌ Attestation INVALID: {error}")
    
    # Simulate tampered agent
    print("\n--- Simulating Tampered Agent ---")
    tampered_attestation = AttestationRecord(
        agent_id="hacked-agent",
        codebase_hash="different_hash",
        config_hash=config_hash,
        signature="invalid_signature",
        signing_key_id="unknown-key",
        timestamp="2026-01-25T10:00:00Z",
        expires_at=None
    )
    
    is_valid, error = validator.validate_attestation(
        tampered_attestation,
        verify_signature=False
    )
    
    if not is_valid:
        print(f"✅ Correctly rejected tampered agent: {error}")


def demo_reputation_slashing():
    """Demonstrate reputation slashing and recovery."""
    print("\n" + "=" * 80)
    print("DEMO 2: Reputation Slashing")
    print("=" * 80)
    
    manager = ReputationManager()
    
    # Start with a good agent
    agent_id = "summarizer-agent-v2"
    
    # Record some successful operations
    print(f"\n--- Agent '{agent_id}' performing successfully ---")
    for i in range(10):
        manager.record_success(agent_id, trace_id=f"trace-{i}")
    
    score = manager.get_score(agent_id)
    print(f"✓ After 10 successful operations: Score = {score.score:.2f}/10")
    print(f"  Trust Level: {score.get_trust_level().value}")
    
    # Simulate hallucination detected by cmvk
    print(f"\n--- cmvk detects hallucination (HIGH severity) ---")
    manager.record_hallucination(
        agent_id=agent_id,
        severity="high",
        trace_id="trace-hallucination-1",
        details={
            "reason": "Generated fabricated customer data",
            "context": "Responding to query about user profile"
        }
    )
    
    score = manager.get_score(agent_id)
    print(f"⚠️  After hallucination: Score = {score.score:.2f}/10 (slashed by 1.0)")
    print(f"  Trust Level: {score.get_trust_level().value}")
    print(f"  Negative events: {score.negative_events}")
    
    # Another hallucination
    print(f"\n--- cmvk detects another hallucination (CRITICAL severity) ---")
    manager.record_hallucination(
        agent_id=agent_id,
        severity="critical",
        trace_id="trace-hallucination-2",
        details={
            "reason": "Made up financial transaction data",
            "context": "Banking query"
        }
    )
    
    score = manager.get_score(agent_id)
    print(f"❌ After critical hallucination: Score = {score.score:.2f}/10 (slashed by 2.0)")
    print(f"  Trust Level: {score.get_trust_level().value}")
    print(f"  🚨 Agent is now UNTRUSTED - other agents stop listening!")
    
    # Show recent events
    print(f"\n--- Recent Events (last 3) ---")
    for event in score.recent_events[-3:]:
        symbol = "✅" if event.score_delta > 0 else "❌"
        print(f"{symbol} {event.event_type} ({event.severity}): "
              f"delta={event.score_delta:+.2f}, detected_by={event.detected_by}")


def demo_network_propagation():
    """Demonstrate network-wide reputation propagation."""
    print("\n" + "=" * 80)
    print("DEMO 3: Network-Wide Reputation Propagation")
    print("=" * 80)
    
    # Create two reputation managers (two different nodes)
    node1 = ReputationManager()
    node2 = ReputationManager()
    
    # Node 1 detects misbehavior
    print("\n--- Node 1: Detecting misbehavior from 'data-agent-x' ---")
    node1.record_hallucination(
        agent_id="data-agent-x",
        severity="high",
        details={"reason": "Fabricated statistics"}
    )
    
    score1 = node1.get_score("data-agent-x")
    print(f"✓ Node 1 reputation for 'data-agent-x': {score1.score:.2f}/10")
    
    # Export reputation data from node 1
    print("\n--- Exporting reputation data from Node 1 ---")
    reputation_data = node1.export_reputation_data()
    print(f"✓ Exported data for {len(reputation_data)} agents")
    
    # Import to node 2
    print("\n--- Importing reputation data to Node 2 ---")
    node2.import_reputation_data(reputation_data)
    
    score2 = node2.get_score("data-agent-x")
    if score2:
        print(f"✅ Node 2 now knows about 'data-agent-x': {score2.score:.2f}/10")
        print(f"   Trust Level: {score2.get_trust_level().value}")
        print(f"   🌐 Reputation propagated across network!")
    
    # Show conservative merging
    print("\n--- Conservative Reputation Merging ---")
    node1.get_or_create_score("trusted-agent-y").score = 8.0
    node2.get_or_create_score("trusted-agent-y").score = 3.0  # Node 2 has concerns
    
    print(f"Node 1 view: 'trusted-agent-y' = 8.0/10")
    print(f"Node 2 view: 'trusted-agent-y' = 3.0/10")
    
    # Node 2 exports to Node 1
    data_from_node2 = node2.export_reputation_data()
    node1.import_reputation_data(data_from_node2)
    
    merged_score = node1.get_score("trusted-agent-y")
    print(f"After merge: Node 1 takes conservative (lower) score = {merged_score.score:.2f}/10")
    print(f"✓ System prefers safety: when in doubt, trust less")


def demo_integration_with_manifest():
    """Show how reputation integrates with capability manifests."""
    print("\n" + "=" * 80)
    print("DEMO 4: Integration with Capability Manifests")
    print("=" * 80)
    
    manager = ReputationManager()
    
    # Create an agent with initial trust level
    manifest = CapabilityManifest(
        agent_id="analytics-agent",
        trust_level=TrustLevel.STANDARD,
        capabilities=AgentCapabilities(
            idempotency=True,
            reversibility=ReversibilityLevel.PARTIAL
        ),
        privacy_contract=PrivacyContract(
            retention=RetentionPolicy.TEMPORARY
        )
    )
    
    print(f"Initial manifest trust: {manifest.trust_level.value}")
    print(f"Initial trust score: {manifest.calculate_trust_score()}/10")
    
    # Record multiple hallucinations
    print("\n--- Agent misbehaves multiple times ---")
    for i in range(3):
        manager.record_hallucination(
            agent_id="analytics-agent",
            severity="medium"
        )
    
    # Get reputation-based trust level
    reputation_score = manager.get_score("analytics-agent")
    reputation_trust = reputation_score.get_trust_level()
    
    print(f"\nAfter misbehavior:")
    print(f"  Reputation score: {reputation_score.score:.2f}/10")
    print(f"  Reputation-based trust: {reputation_trust.value}")
    print(f"  🔒 Other agents can use this to reject requests!")
    
    # Show the decision process
    if reputation_trust == TrustLevel.UNTRUSTED:
        print(f"\n❌ REQUEST REJECTED:")
        print(f"   Agent 'analytics-agent' has been slashed to UNTRUSTED")
        print(f"   Even though manifest says {manifest.trust_level.value},")
        print(f"   network reputation overrides: {reputation_trust.value}")


if __name__ == "__main__":
    print("\n" + "🔒" * 40)
    print("IATP: Removing Implicit Trust")
    print("Agent Attestation + Reputation Slashing Demo")
    print("🔒" * 40)
    
    demo_attestation()
    demo_reputation_slashing()
    demo_network_propagation()
    demo_integration_with_manifest()
    
    print("\n" + "=" * 80)
    print("✅ Demo Complete!")
    print("=" * 80)
    print("\nKey Takeaways:")
    print("1. ✅ Attestation prevents agents from running hacked code")
    print("2. ✅ Reputation slashing penalizes misbehavior (hallucinations)")
    print("3. ✅ Network-wide propagation shares reputation across nodes")
    print("4. ✅ cmvk integration automatically detects and reports issues")
    print("5. ✅ No implicit trust - everything is verified and tracked!")
    print("\n")
