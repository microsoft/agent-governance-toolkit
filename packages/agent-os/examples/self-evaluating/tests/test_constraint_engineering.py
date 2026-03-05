# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""
Tests for Constraint Engineering (Logic Firewall).

Tests validate that the deterministic safety layer correctly:
1. Blocks dangerous SQL operations
2. Blocks dangerous file operations
3. Enforces cost limits
4. Enforces email domain restrictions
5. Allows safe operations to pass through
"""

import sys
import constraint_engine
import os

# Add parent directory to path to allow imports
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from src.constraint_engine import (
    ConstraintEngine,
    ViolationSeverity,
    create_default_engine
)


def test_sql_injection_rule():
    """Test SQL injection prevention."""
    print("\n" + "="*60)
    print("TEST: SQL Injection Prevention")
    print("="*60)
    
    rule = constraint_engine.SQLInjectionRule()
    
    # Test 1: Dangerous DROP TABLE
    plan = {
        "action_type": "sql_query",
        "action_data": {
            "query": "DROP TABLE users"
        }
    }
    violations = rule.validate(plan)
    assert len(violations) > 0, "Should detect DROP TABLE"
    assert violations[0].severity == ViolationSeverity.CRITICAL
    print("✓ Blocked: DROP TABLE users")
    
    # Test 2: SQL injection with semicolon
    plan = {
        "action_type": "sql_query",
        "action_data": {
            "query": "SELECT * FROM users WHERE id = 1; DROP TABLE users"
        }
    }
    violations = rule.validate(plan)
    assert len(violations) > 0, "Should detect SQL injection"
    print("✓ Blocked: SQL injection with semicolon")
    
    # Test 3: DELETE with WHERE 1=1
    plan = {
        "action_type": "sql_query",
        "action_data": {
            "query": "DELETE FROM users WHERE 1=1"
        }
    }
    violations = rule.validate(plan)
    assert len(violations) > 0, "Should detect dangerous DELETE"
    print("✓ Blocked: DELETE FROM ... WHERE 1=1")
    
    # Test 4: Safe SELECT query should pass
    plan = {
        "action_type": "sql_query",
        "action_data": {
            "query": "SELECT * FROM users WHERE id = ?"
        }
    }
    violations = rule.validate(plan)
    assert len(violations) == 0, "Should allow safe SELECT"
    print("✓ Allowed: Safe parameterized SELECT")
    
    print("\n✅ SQL Injection Prevention: All tests passed\n")


def test_file_operation_rule():
    """Test file operation safety."""
    print("\n" + "="*60)
    print("TEST: File Operation Safety")
    print("="*60)
    
    rule = constraint_engine.FileOperationRule()
    
    # Test 1: Dangerous rm -rf /
    plan = {
        "action_type": "file_operation",
        "action_data": {
            "command": "rm -rf /",
            "path": "/"
        }
    }
    violations = rule.validate(plan)
    assert len(violations) > 0, "Should detect rm -rf /"
    assert violations[0].severity == ViolationSeverity.CRITICAL
    print("✓ Blocked: rm -rf /")
    
    # Test 2: Protected path /etc
    plan = {
        "action_type": "file_operation",
        "action_data": {
            "command": "rm config.txt",
            "path": "/etc/config.txt"
        }
    }
    violations = rule.validate(plan)
    assert len(violations) > 0, "Should protect /etc"
    assert violations[0].severity == ViolationSeverity.HIGH
    print("✓ Blocked: Operation on /etc")
    
    # Test 3: Safe user directory operation
    plan = {
        "action_type": "file_operation",
        "action_data": {
            "command": "rm temp.txt",
            "path": "/home/user/temp.txt"
        }
    }
    violations = rule.validate(plan)
    assert len(violations) == 0, "Should allow safe file operations"
    print("✓ Allowed: Safe operation on user directory")
    
    print("\n✅ File Operation Safety: All tests passed\n")


def test_cost_limit_rule():
    """Test cost limit enforcement."""
    print("\n" + "="*60)
    print("TEST: Cost Limit Enforcement")
    print("="*60)
    
    rule = constraint_engine.CostLimitRule(max_cost_per_action=0.05)
    
    # Test 1: Over limit
    plan = {
        "action_type": "api_call",
        "action_data": {
            "estimated_cost": 0.10
        }
    }
    violations = rule.validate(plan)
    assert len(violations) > 0, "Should detect cost over limit"
    assert violations[0].severity == ViolationSeverity.HIGH
    print("✓ Blocked: Cost $0.10 exceeds limit $0.05")
    
    # Test 2: Approaching limit (warning)
    plan = {
        "action_type": "api_call",
        "action_data": {
            "estimated_cost": 0.045
        }
    }
    violations = rule.validate(plan)
    assert len(violations) > 0, "Should warn when approaching limit"
    assert violations[0].severity == ViolationSeverity.LOW
    print("✓ Warning: Cost $0.045 approaching limit $0.05")
    
    # Test 3: Well under limit
    plan = {
        "action_type": "api_call",
        "action_data": {
            "estimated_cost": 0.01
        }
    }
    violations = rule.validate(plan)
    assert len(violations) == 0, "Should allow cost under limit"
    print("✓ Allowed: Cost $0.01 well under limit")
    
    print("\n✅ Cost Limit Enforcement: All tests passed\n")


def test_email_domain_rule():
    """Test email domain restriction."""
    print("\n" + "="*60)
    print("TEST: Email Domain Restriction")
    print("="*60)
    
    rule = constraint_engine.EmailDomainRule(allowed_domains=["example.com", "company.com"])
    
    # Test 1: Unapproved domain
    plan = {
        "action_type": "email",
        "action_data": {
            "recipient": "user@untrusted.com"
        }
    }
    violations = rule.validate(plan)
    assert len(violations) > 0, "Should block unapproved domain"
    assert violations[0].severity == ViolationSeverity.MEDIUM
    print("✓ Blocked: Email to untrusted.com")
    
    # Test 2: Approved domain
    plan = {
        "action_type": "email",
        "action_data": {
            "recipient": "user@example.com"
        }
    }
    violations = rule.validate(plan)
    assert len(violations) == 0, "Should allow approved domain"
    print("✓ Allowed: Email to example.com")
    
    # Test 3: Another approved domain
    plan = {
        "action_type": "email",
        "action_data": {
            "recipient": "admin@company.com"
        }
    }
    violations = rule.validate(plan)
    assert len(violations) == 0, "Should allow approved domain"
    print("✓ Allowed: Email to company.com")
    
    print("\n✅ Email Domain Restriction: All tests passed\n")


def test_rate_limit_rule():
    """Test rate limit enforcement."""
    print("\n" + "="*60)
    print("TEST: Rate Limit Enforcement")
    print("="*60)
    
    rule = constraint_engine.RateLimitRule(max_actions_per_minute=10)
    
    # Test 1: Over rate limit
    plan = {
        "action_type": "api_call",
        "action_data": {
            "current_rate": 15
        }
    }
    violations = rule.validate(plan)
    assert len(violations) > 0, "Should detect rate limit exceeded"
    assert violations[0].severity == ViolationSeverity.MEDIUM
    print("✓ Blocked: 15 actions/min exceeds limit of 10")
    
    # Test 2: Under rate limit
    plan = {
        "action_type": "api_call",
        "action_data": {
            "current_rate": 5
        }
    }
    violations = rule.validate(plan)
    assert len(violations) == 0, "Should allow under rate limit"
    print("✓ Allowed: 5 actions/min under limit")
    
    print("\n✅ Rate Limit Enforcement: All tests passed\n")


def test_constraint_engine_integration():
    """Test the full constraint engine."""
    print("\n" + "="*60)
    print("TEST: Constraint Engine Integration")
    print("="*60)
    
    engine = create_default_engine(max_cost=0.05)
    
    # Test 1: Dangerous SQL should be blocked
    plan = {
        "action_type": "sql_query",
        "action_data": {
            "query": "DROP TABLE users"
        }
    }
    result = engine.validate_plan(plan, verbose=False)
    assert not result.approved, "Should block dangerous SQL"
    assert result.has_blocking_violations(), "Should have blocking violations"
    print("✓ Engine blocked: DROP TABLE")
    
    # Test 2: Safe operation should pass
    plan = {
        "action_type": "sql_query",
        "action_data": {
            "query": "SELECT * FROM users WHERE id = ?"
        }
    }
    result = engine.validate_plan(plan, verbose=False)
    assert result.approved, "Should approve safe SQL"
    assert not result.has_blocking_violations(), "Should have no blocking violations"
    print("✓ Engine approved: Safe SELECT")
    
    # Test 3: Multiple violations
    plan = {
        "action_type": "sql_query",
        "action_data": {
            "query": "DROP DATABASE production",
            "estimated_cost": 1.0  # Also over cost limit
        }
    }
    result = engine.validate_plan(plan, verbose=False)
    assert not result.approved, "Should block multiple violations"
    assert len(result.violations) >= 2, "Should detect multiple violations"
    print("✓ Engine detected multiple violations")
    
    print("\n✅ Constraint Engine Integration: All tests passed\n")


def test_intercept_and_validate():
    """Test the intercept and validate flow."""
    print("\n" + "="*60)
    print("TEST: Intercept and Validate Flow")
    print("="*60)
    
    engine = create_default_engine()
    
    # Mock execution function
    executed_plans = []
    def mock_execute(plan):
        executed_plans.append(plan)
        return {"status": "executed", "plan": plan}
    
    # Test 1: Safe plan should be executed
    plan = {
        "action_type": "sql_query",
        "action_data": {
            "query": "SELECT * FROM users WHERE id = ?",
            "estimated_cost": 0.01
        }
    }
    executed, result, constraint_result = engine.intercept_and_validate(
        plan, execute_fn=mock_execute, verbose=False
    )
    assert executed, "Safe plan should be executed"
    assert result is not None, "Should return execution result"
    assert len(executed_plans) == 1, "Should have executed one plan"
    print("✓ Safe plan executed")
    
    # Test 2: Dangerous plan should not be executed
    plan = {
        "action_type": "sql_query",
        "action_data": {
            "query": "DROP TABLE users"
        }
    }
    executed_plans.clear()
    executed, result, constraint_result = engine.intercept_and_validate(
        plan, execute_fn=mock_execute, verbose=False
    )
    assert not executed, "Dangerous plan should not be executed"
    assert result is None, "Should not return execution result"
    assert len(executed_plans) == 0, "Should not have executed plan"
    assert not constraint_result.approved, "Should not be approved"
    print("✓ Dangerous plan blocked")
    
    print("\n✅ Intercept and Validate Flow: All tests passed\n")


def test_custom_rules():
    """Test adding custom rules to the engine."""
    print("\n" + "="*60)
    print("TEST: Custom Rules")
    print("="*60)
    
    # Create a custom rule using constraint_engine module
    class CustomAPIRule(constraint_engine.ConstraintRule):
        def __init__(self):
            super().__init__(
                name="custom_api_restriction",
                description="Custom rule for API restrictions"
            )
        
        def validate(self, plan):
            violations = []
            if plan.get("action_type") == "api_call":
                api_name = plan.get("action_data", {}).get("api_name", "")
                if api_name == "forbidden_api":
                    violations.append(constraint_engine.ConstraintViolation(
                        rule_name=self.name,
                        severity=ViolationSeverity.HIGH,
                        message="Access to forbidden_api is not allowed",
                        blocked_action=f"API call to {api_name}"
                    ))
            return violations
    
    # Create engine with custom rule
    engine = ConstraintEngine(rules=[CustomAPIRule()])
    
    # Test custom rule
    plan = {
        "action_type": "api_call",
        "action_data": {
            "api_name": "forbidden_api"
        }
    }
    result = engine.validate_plan(plan, verbose=False)
    assert not result.approved, "Should block forbidden API"
    print("✓ Custom rule blocked forbidden API")
    
    # Test allowed API
    plan = {
        "action_type": "api_call",
        "action_data": {
            "api_name": "allowed_api"
        }
    }
    result = engine.validate_plan(plan, verbose=False)
    assert result.approved, "Should allow other APIs"
    print("✓ Custom rule allowed other API")
    
    print("\n✅ Custom Rules: All tests passed\n")


def run_all_tests():
    """Run all constraint engineering tests."""
    print("\n" + "#"*60)
    print("CONSTRAINT ENGINEERING TEST SUITE")
    print("#"*60)
    
    tests = [
        test_sql_injection_rule,
        test_file_operation_rule,
        test_cost_limit_rule,
        test_email_domain_rule,
        test_rate_limit_rule,
        test_constraint_engine_integration,
        test_intercept_and_validate,
        test_custom_rules
    ]
    
    passed = 0
    failed = 0
    
    for test in tests:
        try:
            test()
            passed += 1
        except AssertionError as e:
            print(f"\n❌ FAILED: {test.__name__}")
            print(f"   Error: {str(e)}")
            failed += 1
        except Exception as e:
            print(f"\n❌ ERROR: {test.__name__}")
            print(f"   Error: {type(e).__name__}: {str(e)}")
            failed += 1
    
    print("\n" + "="*60)
    print("TEST SUMMARY")
    print("="*60)
    print(f"Total Tests: {len(tests)}")
    print(f"Passed: {passed}")
    print(f"Failed: {failed}")
    
    if failed == 0:
        print("\n🎉 ALL TESTS PASSED!")
        return 0
    else:
        print(f"\n❌ {failed} TEST(S) FAILED")
        return 1


if __name__ == "__main__":
    sys.exit(run_all_tests())
