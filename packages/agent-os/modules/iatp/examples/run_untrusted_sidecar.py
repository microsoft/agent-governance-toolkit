# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""
Example: Running an UNTRUSTED agent with the IATP Sidecar

This demonstrates the warning and override mechanism.
"""

import os
import sys

# Add SDK to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "sdk", "python"))

from iatp import (
    AgentCapabilities,
    CapabilityManifest,
    PrivacyContract,
    RetentionPolicy,
    ReversibilityLevel,
    TrustLevel,
    create_sidecar,
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
            rate_limit=10,
        ),
        privacy_contract=PrivacyContract(
            retention=RetentionPolicy.FOREVER,
            storage_location="unknown",
            human_review=True,
            encryption_at_rest=False,
            encryption_in_transit=True,
        ),
    )

    print(f"🚨 Starting IATP Sidecar for UNTRUSTED agent: {manifest.agent_id}")
    print(f"   Trust Score: {manifest.calculate_trust_score()}/10 (LOW)")
    print("   Backend Agent: http://localhost:8000")
    print("   Sidecar Port: http://localhost:8002")
    print("\n⚠️  WARNING: This agent has poor security characteristics:")
    print("   • No idempotency guarantee")
    print("   • No transaction reversibility")
    print("   • Stores data FOREVER")
    print("   • Humans may review your data")
    print("   • No encryption at rest")
    print("\nEndpoints:")
    print("   • Manifest: GET http://localhost:8002/.well-known/agent-manifest")
    print("   • Proxy: POST http://localhost:8002/proxy")
    print("   • Health: GET http://localhost:8002/health")
    print("\nTry it:")
    print("   python examples/test_untrusted.py")

    # Create and run the sidecar on port 8002 (different from trusted agent)
    sidecar = create_sidecar(
        agent_url="http://localhost:8000", manifest=manifest, host="0.0.0.0", port=8002
    )

    sidecar.run()


if __name__ == "__main__":
    main()
