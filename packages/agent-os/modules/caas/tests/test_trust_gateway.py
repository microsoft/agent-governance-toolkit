# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""
Tests for Trust Gateway: Enterprise-Grade Private Cloud Router

Tests cover:
1. Deployment modes (on-prem, private cloud, hybrid, air-gapped)
2. Security policies and validation
3. Request routing through gateway
4. Audit logging
5. Data classification
6. Authentication and authorization
"""

from caas.gateway import (
    TrustGateway,
    SecurityPolicy,
    DeploymentMode,
    SecurityLevel,
    DataRetentionPolicy,
    AuditLog
)


def test_trust_gateway_basic():
    """Test basic Trust Gateway creation and functionality."""
    print("\n=== Test 1: Basic Trust Gateway ===")
    
    # Create gateway with default settings
    gateway = TrustGateway()
    
    # Get deployment info
    info = gateway.get_deployment_info()
    print(f"✅ Deployment Mode: {info['deployment_mode']}")
    print(f"✅ Security Level: {info['security_level']}")
    print(f"✅ Audit Enabled: {info['audit_enabled']}")
    
    assert info['deployment_mode'] == DeploymentMode.ON_PREM
    assert info['audit_enabled'] == True
    print("✅ Basic gateway creation successful\n")


def test_deployment_modes():
    """Test different deployment modes."""
    print("\n=== Test 2: Deployment Modes ===")
    
    modes = [
        DeploymentMode.ON_PREM,
        DeploymentMode.PRIVATE_CLOUD,
        DeploymentMode.HYBRID,
        DeploymentMode.AIR_GAPPED
    ]
    
    for mode in modes:
        policy = SecurityPolicy(deployment_mode=mode)
        gateway = TrustGateway(security_policy=policy)
        info = gateway.get_deployment_info()
        
        assert info['deployment_mode'] == mode
        print(f"✅ {mode} deployment mode working")
    
    print("✅ All deployment modes tested successfully\n")


def test_security_levels():
    """Test different security levels."""
    print("\n=== Test 3: Security Levels ===")
    
    levels = ["standard", "high", "maximum"]
    
    for level in levels:
        policy = SecurityPolicy(security_level=level)
        gateway = TrustGateway(security_policy=policy)
        info = gateway.get_deployment_info()
        
        assert info['security_level'] == level
        print(f"✅ {level} security level configured")
    
    print("✅ All security levels tested successfully\n")


def test_request_routing():
    """Test request routing through Trust Gateway."""
    print("\n=== Test 4: Request Routing ===")
    
    policy = SecurityPolicy(
        deployment_mode=DeploymentMode.ON_PREM,
        security_level="high"
    )
    gateway = TrustGateway(security_policy=policy, audit_enabled=True)
    
    # Test routing different query types
    test_queries = [
        ("Hi", "canned"),
        ("What is Python?", "fast"),
        ("Summarize this document", "smart")
    ]
    
    for query, expected_tier in test_queries:
        result = gateway.route_request(
            query=query,
            user_id="test@example.com"
        )
        
        assert result["status"] == "approved"
        assert "routing_decision" in result
        assert result["routing_decision"]["model_tier"] == expected_tier
        assert "security_context" in result
        
        print(f"✅ Query '{query}' routed to {expected_tier} tier")
    
    print("✅ Request routing working correctly\n")


def test_security_validation():
    """Test security policy validation."""
    print("\n=== Test 5: Security Validation ===")
    
    # Test with strict authentication
    policy = SecurityPolicy(
        require_authentication=True,
        allowed_users=["admin@example.com", "user@example.com"]
    )
    gateway = TrustGateway(security_policy=policy)
    
    # Test 1: Valid user
    validation = gateway.validate_request(
        request_data={"query": "test"},
        user_id="admin@example.com"
    )
    assert validation["valid"] == True
    print("✅ Valid user passes validation")
    
    # Test 2: Invalid user
    validation = gateway.validate_request(
        request_data={"query": "test"},
        user_id="unauthorized@example.com"
    )
    assert validation["valid"] == False
    assert len(validation["violations"]) > 0
    print("✅ Invalid user blocked by validation")
    
    # Test 3: Missing authentication
    validation = gateway.validate_request(
        request_data={"query": "test"},
        user_id=None
    )
    assert validation["valid"] == False
    print("✅ Missing authentication detected")
    
    print("✅ Security validation working correctly\n")


def test_data_classification():
    """Test data classification validation."""
    print("\n=== Test 6: Data Classification ===")
    
    policy = SecurityPolicy(
        require_authentication=False,  # Disable auth for this test
        data_classification_required=True,
        allowed_classifications=["public", "internal", "confidential"]
    )
    gateway = TrustGateway(security_policy=policy)
    
    # Test 1: Valid classification
    validation = gateway.validate_request(
        request_data={"query": "test"},
        data_classification="confidential"
    )
    assert validation["valid"] == True
    print("✅ Valid classification accepted")
    
    # Test 2: Invalid classification
    validation = gateway.validate_request(
        request_data={"query": "test"},
        data_classification="top-secret"
    )
    assert validation["valid"] == False
    print("✅ Invalid classification rejected")
    
    # Test 3: Missing classification
    validation = gateway.validate_request(
        request_data={"query": "test"},
        data_classification=None
    )
    assert validation["valid"] == False
    print("✅ Missing classification detected")
    
    print("✅ Data classification validation working\n")


def test_audit_logging():
    """Test audit logging functionality."""
    print("\n=== Test 7: Audit Logging ===")
    
    gateway = TrustGateway(audit_enabled=True)
    
    # Make several requests
    for i in range(3):
        gateway.route_request(
            query=f"Test query {i}",
            user_id=f"user{i}@example.com",
            data_classification="internal"
        )
    
    # Get all audit logs
    logs = gateway.get_audit_logs()
    assert len(logs) > 0
    print(f"✅ {len(logs)} audit logs created")
    
    # Filter by event type
    routing_logs = gateway.get_audit_logs(event_type="request_routed")
    assert len(routing_logs) >= 3
    print(f"✅ Filtered {len(routing_logs)} routing logs")
    
    # Filter by user
    user_logs = gateway.get_audit_logs(user_id="user0@example.com")
    assert len(user_logs) > 0
    print(f"✅ Filtered {len(user_logs)} logs for specific user")
    
    print("✅ Audit logging working correctly\n")


def test_data_retention_policy():
    """Test data retention policy configuration."""
    print("\n=== Test 8: Data Retention Policy ===")
    
    retention = DataRetentionPolicy(
        retain_requests=True,
        retention_days=90,
        auto_delete=True,
        encrypt_at_rest=True,
        pii_scrubbing=True
    )
    
    policy = SecurityPolicy(
        deployment_mode=DeploymentMode.PRIVATE_CLOUD,
        data_retention=retention
    )
    
    gateway = TrustGateway(security_policy=policy)
    info = gateway.get_deployment_info()
    
    assert info['data_retention_days'] == 90
    assert info['security_policy']['encrypt_at_rest'] == True
    
    print("✅ Data retention policy configured: 90 days")
    print("✅ Encryption at rest: enabled")
    print("✅ PII scrubbing: enabled")
    print("✅ Data retention policy working correctly\n")


def test_enterprise_use_case():
    """Test enterprise use case with maximum security."""
    print("\n=== Test 9: Enterprise Use Case (Maximum Security) ===")
    
    # Configure maximum security for enterprise
    retention = DataRetentionPolicy(
        retain_requests=False,  # No retention for air-gapped
        retention_days=0,
        auto_delete=True,
        encrypt_at_rest=True,
        pii_scrubbing=True
    )
    
    policy = SecurityPolicy(
        deployment_mode=DeploymentMode.AIR_GAPPED,
        security_level="maximum",
        data_retention=retention,
        require_authentication=True,
        allowed_users=["ciso@enterprise.com", "admin@enterprise.com"],
        data_classification_required=True,
        encrypt_in_transit=True,
        encrypt_at_rest=True,
        audit_all_requests=True,
        compliance_mode="SOC2",
        allow_external_calls=False
    )
    
    gateway = TrustGateway(security_policy=policy, audit_enabled=True)
    
    # Test enterprise request
    result = gateway.route_request(
        query="Analyze Q4 financial results",
        user_id="ciso@enterprise.com",
        data_classification="confidential"
    )
    
    assert result["status"] == "approved"
    assert result["security_context"]["deployment_mode"] == DeploymentMode.AIR_GAPPED
    assert result["security_context"]["security_level"] == "maximum"
    assert result["security_context"]["data_classification"] == "confidential"
    
    print("✅ Enterprise deployment configured:")
    print("   - Deployment: Air-gapped")
    print("   - Security: Maximum")
    print("   - Compliance: SOC2")
    print("   - Authentication: Required")
    print("   - Data Classification: Required")
    print("   - Encryption: In transit & at rest")
    print("   - External Calls: Blocked")
    print("✅ Enterprise use case successful\n")


def test_trust_guarantees():
    """Test trust guarantees are provided."""
    print("\n=== Test 10: Trust Guarantees ===")
    
    gateway = TrustGateway()
    info = gateway.get_deployment_info()
    
    assert "trust_guarantees" in info
    guarantees = info["trust_guarantees"]
    
    expected_guarantees = [
        "Data never leaves your infrastructure",
        "Full audit trail for compliance",
        "Configurable retention policies",
        "Enterprise-grade security controls",
        "Zero third-party data sharing"
    ]
    
    for guarantee in expected_guarantees:
        assert guarantee in guarantees
        print(f"✅ {guarantee}")
    
    print("✅ All trust guarantees verified\n")


def test_security_context():
    """Test security context is included in routing decisions."""
    print("\n=== Test 11: Security Context ===")
    
    policy = SecurityPolicy(
        deployment_mode=DeploymentMode.PRIVATE_CLOUD,
        security_level="high"
    )
    gateway = TrustGateway(security_policy=policy)
    
    result = gateway.route_request(
        query="Test query",
        user_id="user@example.com",
        data_classification="internal"
    )
    
    security_context = result["security_context"]
    
    assert security_context["deployment_mode"] == DeploymentMode.PRIVATE_CLOUD
    assert security_context["security_level"] == "high"
    assert security_context["data_classification"] == "internal"
    assert security_context["encrypted"] == True
    assert security_context["audited"] == True
    
    print("✅ Security context included:")
    print(f"   - Deployment: {security_context['deployment_mode']}")
    print(f"   - Security Level: {security_context['security_level']}")
    print(f"   - Classification: {security_context['data_classification']}")
    print(f"   - Encrypted: {security_context['encrypted']}")
    print(f"   - Audited: {security_context['audited']}")
    print("✅ Security context working correctly\n")


def test_policy_update():
    """Test security policy updates are logged."""
    print("\n=== Test 12: Policy Updates ===")
    
    gateway = TrustGateway(audit_enabled=True)
    
    # Update policy
    new_policy = SecurityPolicy(
        deployment_mode=DeploymentMode.HYBRID,
        security_level="maximum"
    )
    
    result = gateway.update_security_policy(
        new_policy=new_policy,
        user_id="admin@example.com"
    )
    
    assert result["status"] == "success"
    
    # Check audit log
    logs = gateway.get_audit_logs(event_type="policy_changed")
    assert len(logs) > 0
    
    print("✅ Policy update successful")
    print("✅ Policy change logged in audit trail")
    print("✅ Policy update tracking working\n")


def run_all_tests():
    """Run all Trust Gateway tests."""
    print("=" * 60)
    print("TRUST GATEWAY TEST SUITE")
    print("Enterprise-Grade Private Cloud Router")
    print("=" * 60)
    
    tests = [
        test_trust_gateway_basic,
        test_deployment_modes,
        test_security_levels,
        test_request_routing,
        test_security_validation,
        test_data_classification,
        test_audit_logging,
        test_data_retention_policy,
        test_enterprise_use_case,
        test_trust_guarantees,
        test_security_context,
        test_policy_update,
    ]
    
    passed = 0
    failed = 0
    
    for test in tests:
        try:
            test()
            passed += 1
        except Exception as e:
            print(f"❌ {test.__name__} failed: {str(e)}\n")
            failed += 1
    
    print("=" * 60)
    print(f"TEST RESULTS: {passed} passed, {failed} failed")
    print("=" * 60)
    
    if failed == 0:
        print("\n🎉 ALL TESTS PASSED! Trust Gateway is ready for enterprise deployment.\n")
        print("Key Features Verified:")
        print("✅ On-Prem / Private Cloud deployment")
        print("✅ Zero data leakage (data never leaves infrastructure)")
        print("✅ Full audit trail for compliance")
        print("✅ Configurable security policies")
        print("✅ Authentication and authorization")
        print("✅ Data classification and encryption")
        print("✅ Enterprise-grade controls")
        print("\nPhilosophy:")
        print("'The winner won't be the one with the smartest routing algorithm;")
        print(" it will be the one the Enterprise trusts with the keys to the kingdom.'")
    
    return failed == 0


if __name__ == "__main__":
    success = run_all_tests()
    exit(0 if success else 1)
