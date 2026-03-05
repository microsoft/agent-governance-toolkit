# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""
Example: Running the IATP Sidecar

This example shows how to set up and run a sidecar for your agent.
"""
import sys
import os

# Add SDK to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'sdk', 'python'))

from iatp import (
    create_sidecar,
    CapabilityManifest,
    AgentCapabilities,
    PrivacyContract,
    TrustLevel,
    ReversibilityLevel,
    RetentionPolicy,
)


def create_trusted_manifest():
    """Create a capability manifest for a trusted agent."""
    return CapabilityManifest(
        agent_id="example-booking-agent-v1",
        agent_version="1.0.0",
        trust_level=TrustLevel.VERIFIED_PARTNER,
        capabilities=AgentCapabilities(
            idempotency=True,
            reversibility=ReversibilityLevel.PARTIAL,
            undo_window="24h",
            sla_latency="2000ms",
            rate_limit=100
        ),
        privacy_contract=PrivacyContract(
            retention=RetentionPolicy.EPHEMERAL,
            storage_location="us-west",
            human_review=False,
            encryption_at_rest=True,
            encryption_in_transit=True
        )
    )


def create_untrusted_manifest():
    """Create a capability manifest for an untrusted/sketchy agent."""
    return CapabilityManifest(
        agent_id="sketchy-cheap-agent-v1",
        agent_version="0.1.0",
        trust_level=TrustLevel.UNTRUSTED,
        capabilities=AgentCapabilities(
            idempotency=False,
            reversibility=ReversibilityLevel.NONE,
            undo_window=None,
            sla_latency=None,
            rate_limit=10
        ),
        privacy_contract=PrivacyContract(
            retention=RetentionPolicy.FOREVER,
            storage_location="unknown",
            human_review=True,
            encryption_at_rest=False,
            encryption_in_transit=True
        )
    )


def main():
    """
    Run the sidecar.
    
    Make sure your backend agent is running on port 8000 first!
    Run: python examples/backend_agent.py
    """
    # Choose which manifest to use
    manifest = create_trusted_manifest()
    # manifest = create_untrusted_manifest()  # Uncomment to test with untrusted agent
    
    print(f"🚀 Starting IATP Sidecar for: {manifest.agent_id}")
    print(f"   Trust Score: {manifest.calculate_trust_score()}/10")
    print(f"   Backend Agent: http://localhost:8000")
    print(f"   Sidecar Port: http://localhost:8001")
    print(f"\nEndpoints:")
    print(f"   • Manifest: GET http://localhost:8001/.well-known/agent-manifest")
    print(f"   • Proxy: POST http://localhost:8001/proxy")
    print(f"   • Health: GET http://localhost:8001/health")
    print(f"\nTry it:")
    print(f"   curl -X POST http://localhost:8001/proxy \\")
    print(f"        -H 'Content-Type: application/json' \\")
    print(f"        -d '{{\"task\": \"book_flight\", \"data\": {{\"destination\": \"NYC\"}}}}'")
    
    # Create and run the sidecar
    sidecar = create_sidecar(
        agent_url="http://localhost:8000",
        manifest=manifest,
        host="0.0.0.0",
        port=8001
    )
    
    sidecar.run()


if __name__ == "__main__":
    main()
