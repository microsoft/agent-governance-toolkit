# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""
Example demonstrating the IATP Policy Engine and Recovery Engine integration.

This shows how the built-in policy engine and scak library are integrated
into the IATP sidecar to provide policy validation and failure recovery.
"""
import asyncio
from iatp import (
    CapabilityManifest,
    AgentCapabilities,
    PrivacyContract,
    TrustLevel,
    ReversibilityLevel,
    RetentionPolicy,
    IATPPolicyEngine,
    IATPRecoveryEngine,
)


async def demo_policy_engine():
    """Demonstrate the Policy Engine integration."""
    print("=" * 60)
    print("DEMO 1: Policy Engine")
    print("=" * 60)
    
    # Create a policy engine
    engine = IATPPolicyEngine()
    
    # Test Case 1: Trusted agent with good policies
    print("\n1. Testing TRUSTED agent with ephemeral retention:")
    trusted_manifest = CapabilityManifest(
        agent_id="secure-bank-agent",
        trust_level=TrustLevel.VERIFIED_PARTNER,
        capabilities=AgentCapabilities(
            idempotency=True,
            reversibility=ReversibilityLevel.FULL,
            undo_window="24h",
        ),
        privacy_contract=PrivacyContract(
            retention=RetentionPolicy.EPHEMERAL,
            human_review=False,
        )
    )
    
    is_allowed, error_msg, warning_msg = engine.validate_manifest(trusted_manifest)
    print(f"   ✅ Allowed: {is_allowed}")
    print(f"   Error: {error_msg}")
    print(f"   Warning: {warning_msg}")
    
    # Test Case 2: Untrusted agent
    print("\n2. Testing UNTRUSTED agent:")
    untrusted_manifest = CapabilityManifest(
        agent_id="sketchy-agent",
        trust_level=TrustLevel.UNTRUSTED,
        capabilities=AgentCapabilities(
            idempotency=False,
            reversibility=ReversibilityLevel.NONE,
        ),
        privacy_contract=PrivacyContract(
            retention=RetentionPolicy.FOREVER,
            human_review=True,
        )
    )
    
    is_allowed, error_msg, warning_msg = engine.validate_manifest(untrusted_manifest)
    print(f"   ⚠️  Allowed: {is_allowed}")
    print(f"   Error: {error_msg}")
    print(f"   Warning: {warning_msg}")
    
    # Test Case 3: Custom policy rule
    print("\n3. Adding custom policy rule:")
    engine.add_custom_rule({
        "name": "RequireIdempotency",
        "description": "Block agents without idempotency",
        "action": "deny",
        "conditions": {"idempotency": [False]}
    })
    
    is_allowed, error_msg, warning_msg = engine.validate_manifest(untrusted_manifest)
    print(f"   🚫 Allowed: {is_allowed} (custom rule applied)")
    print(f"   Error: {error_msg}")


async def demo_recovery_engine():
    """Demonstrate the Recovery Engine integration with scak."""
    print("\n" + "=" * 60)
    print("DEMO 2: Recovery Engine (scak integration)")
    print("=" * 60)
    
    # Create a recovery engine
    engine = IATPRecoveryEngine()
    
    # Test Case 1: Reversible agent with compensation
    print("\n1. Testing failure recovery with REVERSIBLE agent:")
    reversible_manifest = CapabilityManifest(
        agent_id="payment-processor",
        trust_level=TrustLevel.TRUSTED,
        capabilities=AgentCapabilities(
            idempotency=True,
            reversibility=ReversibilityLevel.FULL,
            undo_window="1h",
        ),
        privacy_contract=PrivacyContract(
            retention=RetentionPolicy.TEMPORARY,
            human_review=False,
        )
    )
    
    # Simulate a failure
    error = Exception("Payment gateway timeout")
    payload = {"amount": 100, "currency": "USD"}
    
    # Define a compensation callback
    compensation_executed = False
    async def refund_payment():
        nonlocal compensation_executed
        print("   💰 Executing compensation: Refunding payment...")
        compensation_executed = True
    
    result = await engine.handle_failure(
        trace_id="trace-001",
        error=error,
        manifest=reversible_manifest,
        payload=payload,
        compensation_callback=refund_payment
    )
    
    print(f"   Strategy: {result['strategy']}")
    print(f"   Success: {result['success']}")
    print(f"   Actions: {result['actions_taken']}")
    print(f"   Compensation executed: {compensation_executed}")
    
    # Test Case 2: Non-reversible agent
    print("\n2. Testing failure with NON-REVERSIBLE agent:")
    non_reversible_manifest = CapabilityManifest(
        agent_id="email-sender",
        trust_level=TrustLevel.STANDARD,
        capabilities=AgentCapabilities(
            idempotency=False,
            reversibility=ReversibilityLevel.NONE,
        ),
        privacy_contract=PrivacyContract(
            retention=RetentionPolicy.TEMPORARY,
            human_review=False,
        )
    )
    
    error = Exception("SMTP server unavailable")
    result = await engine.handle_failure(
        trace_id="trace-002",
        error=error,
        manifest=non_reversible_manifest,
        payload={"to": "user@example.com"},
        compensation_callback=None
    )
    
    print(f"   Strategy: {result['strategy']}")
    print(f"   Actions: {result['actions_taken']}")
    if 'message' in result:
        print(f"   Message: {result['message']}")
    
    # Test Case 3: Timeout error (retryable)
    print("\n3. Testing TIMEOUT error (retryable):")
    error = TimeoutError("Request timeout after 30s")
    result = await engine.handle_failure(
        trace_id="trace-003",
        error=error,
        manifest=non_reversible_manifest,
        payload={"to": "user@example.com"},
        compensation_callback=None
    )
    
    print(f"   Strategy: {result['strategy']}")
    print(f"   Retry possible: {result.get('retry_possible', False)}")
    print(f"   Actions: {result['actions_taken']}")


def demo_sidecar_integration():
    """Demonstrate how the integrations work in the sidecar."""
    print("\n" + "=" * 60)
    print("DEMO 3: Sidecar Integration")
    print("=" * 60)
    
    print("""
The IATP Sidecar integrates both engines:

1. **Policy Validation (built-in)**:
   - Validates incoming requests against policy rules
   - Checks capability manifests before routing
   - Provides customizable policy enforcement
   
2. **Failure Recovery (scak)**:
   - Handles timeouts and errors with intelligent recovery
   - Executes compensation transactions for reversible agents
   - Provides structured failure tracking with AgentFailure models

Integration Flow:
-----------------
Request → Policy Engine Check → Security Check → Route to Agent
           ↓ (if blocked)          ↓ (if blocked)     ↓ (if error)
        Block with policy error   Block privacy     Recovery Engine
                                    violation         ↓
                                                  Attempt compensation
                                                  Log failure
                                                  Return recovery info

Example Usage:
--------------
from iatp import create_sidecar, CapabilityManifest

# Create manifest
manifest = CapabilityManifest(...)

# Create sidecar with integrated engines
sidecar = create_sidecar(
    agent_url="http://localhost:8000",
    manifest=manifest
)

# The sidecar automatically uses:
# - IATPPolicyEngine for validation
# - IATPRecoveryEngine for error handling

sidecar.run()  # Start the proxy server
""")


async def main():
    """Run all demos."""
    print("\n" + "=" * 60)
    print("IATP Integration Demo")
    print("Demonstrating Policy Engine and scak integration")
    print("=" * 60)
    
    await demo_policy_engine()
    await demo_recovery_engine()
    demo_sidecar_integration()
    
    print("\n" + "=" * 60)
    print("Demo complete!")
    print("=" * 60)


if __name__ == "__main__":
    asyncio.run(main())
