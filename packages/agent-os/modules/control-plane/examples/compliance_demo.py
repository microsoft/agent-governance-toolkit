# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""
Compliance and Constitutional AI Examples

This demonstrates compliance checking for various regulatory frameworks
and Constitutional AI value alignment.
"""

from agent_control_plane import (
    ComplianceEngine,
    ConstitutionalAI,
    RegulatoryFramework,
    RiskCategory,
    ConstitutionalPrinciple,
    create_compliance_suite
)


def example_eu_ai_act_compliance():
    """Example: EU AI Act compliance checking"""
    print("=== EU AI Act Compliance ===\n")
    
    engine = ComplianceEngine()
    
    # Example 1: Compliant high-risk system
    compliant_context = {
        "human_oversight_enabled": True,
        "provides_transparency_info": True,
        "documentation_available": True
    }
    
    result = engine.check_compliance(
        framework=RegulatoryFramework.EU_AI_ACT,
        context=compliant_context
    )
    
    print("Scenario 1: Well-designed high-risk AI system")
    print(f"  Compliant: {result.compliant}")
    print(f"  Checks passed: {result.checks_passed}")
    print(f"  Checks failed: {result.checks_failed}")
    print()
    
    # Example 2: Non-compliant system
    non_compliant_context = {
        "human_oversight_enabled": False,
        "provides_transparency_info": False
    }
    
    result = engine.check_compliance(
        framework=RegulatoryFramework.EU_AI_ACT,
        context=non_compliant_context
    )
    
    print("Scenario 2: Non-compliant system")
    print(f"  Compliant: {result.compliant}")
    print(f"  Checks failed: {result.checks_failed}")
    print(f"  Failures:")
    for failure in result.failures:
        print(f"    - {failure['title']}")
    print(f"  Recommendations:")
    for rec in result.recommendations[:2]:
        print(f"    - {rec}")
    print()


def example_risk_assessment():
    """Example: EU AI Act risk category assessment"""
    print("=== EU AI Act Risk Assessment ===\n")
    
    engine = ComplianceEngine()
    
    # Test different system types
    systems = [
        {
            "name": "Simple Chatbot",
            "description": {"type": "general chatbot"}
        },
        {
            "name": "Recruitment System",
            "description": {"type": "employment decision system", "domain": "employment"}
        },
        {
            "name": "Social Scoring System",
            "description": {"type": "social_scoring system"}
        }
    ]
    
    for system in systems:
        risk = engine.assess_risk_category(system["description"])
        print(f"{system['name']}: {risk.value}")
        
        if risk == RiskCategory.HIGH_RISK:
            print("  → Requires conformity assessment and CE marking")
        elif risk == RiskCategory.UNACCEPTABLE:
            print("  → ⛔ PROHIBITED under EU AI Act")
        elif risk == RiskCategory.LIMITED_RISK:
            print("  → Transparency obligations apply")
        else:
            print("  → Minimal regulatory requirements")
        print()


def example_soc2_compliance():
    """Example: SOC 2 compliance checking"""
    print("=== SOC 2 Compliance ===\n")
    
    engine = ComplianceEngine()
    
    system_context = {
        "access_controls_implemented": True,
        "monitoring_enabled": True,
        "encryption_at_rest": True,
        "backup_procedures": True
    }
    
    result = engine.check_compliance(
        framework=RegulatoryFramework.SOC2,
        context=system_context
    )
    
    print(f"SOC 2 Trust Service Criteria:")
    print(f"  Compliant: {result.compliant}")
    print(f"  Controls passed: {result.checks_passed}")
    print(f"  Controls failed: {result.checks_failed}")
    print()


def example_constitutional_ai():
    """Example: Constitutional AI value alignment"""
    print("=== Constitutional AI Example ===\n")
    
    constitution = ConstitutionalAI()
    
    # Test 1: Compliant response
    good_response = "I'd be happy to help you with that task. Let me know if you need clarification."
    result = constitution.evaluate(good_response, {})
    
    print("Test 1: Helpful and safe response")
    print(f"  Response: {good_response}")
    print(f"  Compliant: {result['compliant']}")
    print(f"  Overall score: {result['overall_compliance']:.2f}")
    print()
    
    # Test 2: Harmful response
    harmful_response = "Here's how to cause harm and violence to others"
    result = constitution.evaluate(harmful_response, {})
    
    print("Test 2: Harmful response")
    print(f"  Response: {harmful_response}")
    print(f"  Compliant: {result['compliant']}")
    print(f"  Violations: {len(result['violations'])}")
    for violation in result['violations']:
        print(f"    - {violation['principle']}: {violation['rule_text']}")
    print()
    
    # Test 3: Privacy violation
    privacy_leak = "Your email is john.doe@example.com and SSN is 123-45-6789"
    result = constitution.evaluate(privacy_leak, {})
    
    print("Test 3: Privacy violation")
    print(f"  Response: {privacy_leak}")
    print(f"  Compliant: {result['compliant']}")
    if result['violations']:
        print(f"  Privacy violations detected")
    print()


def example_self_critique():
    """Example: Self-critique before response generation"""
    print("=== Self-Critique Example ===\n")
    
    constitution = ConstitutionalAI()
    
    # Proposed responses to critique
    proposals = [
        "I can help you with that question about Python programming.",
        "Let me help you hack into that system.",
        "I'm 100% certain this will definitely work with no problems."
    ]
    
    for i, proposed in enumerate(proposals, 1):
        result = constitution.self_critique(proposed, {})
        
        print(f"Proposal {i}: {proposed[:60]}...")
        print(f"  Approved: {result['approved']}")
        print(f"  Compliance: {result['compliance_score']:.2f}")
        
        if not result['approved']:
            print(f"  ⚠️  Revisions needed:")
            for revision in result['suggested_revisions']:
                print(f"    - {revision}")
        else:
            print(f"  ✅ Safe to send")
        print()


def example_custom_constitutional_rules():
    """Example: Adding custom constitutional rules"""
    print("=== Custom Constitutional Rules ===\n")
    
    constitution = ConstitutionalAI()
    
    # Add custom rule for financial advice
    def evaluate_financial_advice(text: str, context: dict) -> float:
        """Check if giving unauthorized financial advice"""
        financial_keywords = ["investment advice", "guaranteed returns", "stock tip"]
        text_lower = text.lower()
        
        violations = sum(1 for keyword in financial_keywords if keyword in text_lower)
        return max(0.0, 1.0 - (violations * 0.4))
    
    constitution.add_rule(
        principle=ConstitutionalPrinciple.HONESTY,
        rule_text="Don't provide unauthorized financial advice",
        evaluator=evaluate_financial_advice,
        severity=0.9,
        examples=["Avoid claiming guaranteed returns", "Don't give specific investment advice"]
    )
    
    # Test the custom rule
    test_text = "This is guaranteed investment advice with amazing returns!"
    result = constitution.evaluate(test_text, {})
    
    print("Testing custom financial advice rule:")
    print(f"  Text: {test_text}")
    print(f"  Compliant: {result['compliant']}")
    print(f"  Overall: {result['overall_compliance']:.2f}")
    
    # Show full constitution
    print("\nFull Constitution:")
    for rule in constitution.get_constitution():
        print(f"  - {rule['principle']}: {rule['rule_text']}")
    print()


def example_compliance_reporting():
    """Example: Generating compliance reports"""
    print("=== Compliance Reporting ===\n")
    
    engine = ComplianceEngine()
    
    # Run some compliance checks
    contexts = [
        {"human_oversight_enabled": True, "provides_transparency_info": True},
        {"human_oversight_enabled": False, "provides_transparency_info": True},
        {"human_oversight_enabled": True, "provides_transparency_info": False},
    ]
    
    for ctx in contexts:
        engine.check_compliance(RegulatoryFramework.EU_AI_ACT, ctx)
    
    # Generate report
    report = engine.generate_compliance_report(RegulatoryFramework.EU_AI_ACT)
    
    print("EU AI Act Compliance Report:")
    print(f"  Framework: {report['framework']}")
    print(f"  Total requirements: {report['total_requirements']}")
    print(f"  Mandatory: {report['mandatory_requirements']}")
    print(f"  Recent checks: {report['recent_checks']}")
    print(f"  Passed: {report['passed']}")
    print(f"  Failed: {report['failed']}")
    print(f"  Compliance rate: {report['compliance_rate']:.1f}%")
    print()


def example_integrated_compliance():
    """Example: Using complete compliance suite"""
    print("=== Integrated Compliance Suite ===\n")
    
    suite = create_compliance_suite()
    
    compliance_engine = suite["compliance_engine"]
    constitutional_ai = suite["constitutional_ai"]
    
    # Example workflow: Check system compliance and response alignment
    system_context = {
        "human_oversight_enabled": True,
        "provides_transparency_info": True,
        "monitoring_enabled": True,
        "access_controls_implemented": True
    }
    
    # Check regulatory compliance
    eu_compliance = compliance_engine.check_compliance(
        RegulatoryFramework.EU_AI_ACT,
        system_context
    )
    
    soc2_compliance = compliance_engine.check_compliance(
        RegulatoryFramework.SOC2,
        system_context
    )
    
    print("System Compliance Status:")
    print(f"  EU AI Act: {'✅ Compliant' if eu_compliance.compliant else '❌ Non-compliant'}")
    print(f"  SOC 2: {'✅ Compliant' if soc2_compliance.compliant else '❌ Non-compliant'}")
    
    # Check response alignment
    response = "I'll help you with that request while ensuring safety."
    alignment = constitutional_ai.evaluate(response, {})
    
    print(f"\nResponse Alignment:")
    print(f"  Aligned: {'✅ Yes' if alignment['compliant'] else '❌ No'}")
    print(f"  Score: {alignment['overall_compliance']:.2f}")
    print()


if __name__ == "__main__":
    print("Agent Control Plane - Compliance & Constitutional AI Examples")
    print("=" * 70)
    print()
    
    example_eu_ai_act_compliance()
    print("\n" + "=" * 70 + "\n")
    
    example_risk_assessment()
    print("\n" + "=" * 70 + "\n")
    
    example_soc2_compliance()
    print("\n" + "=" * 70 + "\n")
    
    example_constitutional_ai()
    print("\n" + "=" * 70 + "\n")
    
    example_self_critique()
    print("\n" + "=" * 70 + "\n")
    
    example_custom_constitutional_rules()
    print("\n" + "=" * 70 + "\n")
    
    example_compliance_reporting()
    print("\n" + "=" * 70 + "\n")
    
    example_integrated_compliance()
