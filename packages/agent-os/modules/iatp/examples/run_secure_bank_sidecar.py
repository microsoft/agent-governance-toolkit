# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""
Example: Run IATP Sidecar for Secure Bank Agent

This configures a sidecar for a high-trust banking agent with:
- Verified partner status
- Full reversibility
- Ephemeral data retention
- High trust score (10/10)
"""
import sys
import os

# Add parent directory to path to import iatp
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'sdk', 'python'))

from iatp.sidecar import create_sidecar
from iatp.models import (
    CapabilityManifest,
    TrustLevel,
    AgentCapabilities,
    ReversibilityLevel,
    PrivacyContract,
    RetentionPolicy
)


def main():
    # Define the capability manifest for a secure bank agent
    manifest = CapabilityManifest(
        agent_id="secure-bank-agent-v1.0.0",
        agent_version="1.0.0",
        trust_level=TrustLevel.VERIFIED_PARTNER,
        capabilities=AgentCapabilities(
            idempotency=True,
            reversibility=ReversibilityLevel.FULL,
            undo_window="5m",  # 5-minute fraud detection window
            sla_latency="1000ms"
        ),
        privacy_contract=PrivacyContract(
            retention=RetentionPolicy.EPHEMERAL,  # Data not retained
            storage_location="us-east-1",
            human_review=False,
            encryption_at_rest=True,
            encryption_in_transit=True
        )
    )
    
    # Calculate and display trust score
    trust_score = manifest.calculate_trust_score()
    
    print("=" * 60)
    print("IATP Sidecar: Secure Bank Agent")
    print("=" * 60)
    print(f"Agent ID: {manifest.agent_id}")
    print(f"Trust Level: {manifest.trust_level}")
    print(f"Trust Score: {trust_score}/10")
    print(f"Reversibility: {manifest.capabilities.reversibility} ({manifest.capabilities.undo_window})")
    print(f"Data Retention: {manifest.privacy_contract.retention}")
    print("")
    print("✓ This agent has strong security guarantees")
    print("✓ Requests will be processed immediately")
    print("✓ No warnings or blocks expected")
    print("")
    print("Backend Agent: http://localhost:8000")
    print("Sidecar: http://localhost:8001")
    print("")
    print("Test with:")
    print("  curl -X POST http://localhost:8001/proxy \\")
    print("    -H 'Content-Type: application/json' \\")
    print("    -d '{\"task\":\"transfer\",\"data\":{\"amount\":100,\"from_account\":\"123\",\"to_account\":\"456\"}}'")
    print("")
    
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
