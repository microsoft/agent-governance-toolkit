# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""
Example: Running an UNTRUSTED agent with the IATP Sidecar

This demonstrates the warning and override mechanism.
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


def main():
    """
    Run the sidecar with an UNTRUSTED manifest.
    This simulates a "sketchy" agent with poor security practices.
    """
    manifest = CapabilityManifest(
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
    
    print(f"🚨 Starting IATP Sidecar for UNTRUSTED agent: {manifest.agent_id}")
    print(f"   Trust Score: {manifest.calculate_trust_score()}/10 (LOW)")
    print(f"   Backend Agent: http://localhost:8000")
    print(f"   Sidecar Port: http://localhost:8002")
    print(f"\n⚠️  WARNING: This agent has poor security characteristics:")
    print(f"   • No idempotency guarantee")
    print(f"   • No transaction reversibility")
    print(f"   • Stores data FOREVER")
    print(f"   • Humans may review your data")
    print(f"   • No encryption at rest")
    print(f"\nEndpoints:")
    print(f"   • Manifest: GET http://localhost:8002/.well-known/agent-manifest")
    print(f"   • Proxy: POST http://localhost:8002/proxy")
    print(f"   • Health: GET http://localhost:8002/health")
    print(f"\nTry it:")
    print(f"   python examples/test_untrusted.py")
    
    # Create and run the sidecar on port 8002 (different from trusted agent)
    sidecar = create_sidecar(
        agent_url="http://localhost:8000",
        manifest=manifest,
        host="0.0.0.0",
        port=8002
    )
    
    sidecar.run()


if __name__ == "__main__":
    main()
