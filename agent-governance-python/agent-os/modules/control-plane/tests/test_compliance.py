# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""
Unit tests for Compliance and Constitutional AI features
"""

import unittest
from src.agent_control_plane.compliance import (
    ComplianceEngine,
    ConstitutionalAI,
    RegulatoryFramework,
    RiskCategory,
    ConstitutionalPrinciple,
    create_compliance_suite
)


class TestComplianceEngine(unittest.TestCase):
    """Test compliance engine functionality"""
    
    def setUp(self):
        self.engine = ComplianceEngine()
    
    def test_add_requirement(self):
        """Test adding compliance requirements"""
        def validator(context):
            return True
        
        req_id = self.engine.add_requirement(
            framework=RegulatoryFramework.GDPR,
            title="Test requirement",
            description="Test",
            validator=validator
        )
        
        self.assertIsNotNone(req_id)
    
    def test_check_compliance_pass(self):
        """Test compliance check that passes"""
        context = {
            "human_oversight_enabled": True,
            "provides_transparency_info": True
        }
        
        result = self.engine.check_compliance(
            framework=RegulatoryFramework.EU_AI_ACT,
            context=context
        )
        
        self.assertTrue(result.compliant)
        self.assertEqual(result.checks_failed, 0)
    
    def test_check_compliance_fail(self):
        """Test compliance check that fails"""
        context = {
            "human_oversight_enabled": False,
            "provides_transparency_info": False
        }
        
        result = self.engine.check_compliance(
            framework=RegulatoryFramework.EU_AI_ACT,
            context=context
        )
        
        self.assertFalse(result.compliant)
        self.assertGreater(result.checks_failed, 0)
        self.assertGreater(len(result.failures), 0)
    
    def test_assess_risk_category_minimal(self):
        """Test risk assessment for minimal risk system"""
        system = {"type": "simple_chatbot"}
        
        risk = self.engine.assess_risk_category(system)
        
        # Could be minimal or limited
        self.assertIn(risk, [RiskCategory.MINIMAL_RISK, RiskCategory.LIMITED_RISK])
    
    def test_assess_risk_category_high(self):
        """Test risk assessment for high risk system"""
        system = {"type": "employment decision system", "domain": "employment"}
        
        risk = self.engine.assess_risk_category(system)
        
        self.assertEqual(risk, RiskCategory.HIGH_RISK)
    
    def test_assess_risk_category_unacceptable(self):
        """Test risk assessment for unacceptable risk"""
        system = {"type": "social_scoring system"}
        
        risk = self.engine.assess_risk_category(system)
        
        self.assertEqual(risk, RiskCategory.UNACCEPTABLE)
    
    def test_generate_compliance_report(self):
        """Test compliance report generation"""
        report = self.engine.generate_compliance_report(
            framework=RegulatoryFramework.SOC2
        )
        
        self.assertIn("framework", report)
        self.assertIn("total_requirements", report)
        self.assertIn("compliance_rate", report)
    
    def test_audit_trail(self):
        """Test audit trail recording"""
        context = {"human_oversight_enabled": True}
        
        self.engine.check_compliance(
            framework=RegulatoryFramework.EU_AI_ACT,
            context=context
        )
        
        trail = self.engine.get_audit_trail(
            framework=RegulatoryFramework.EU_AI_ACT
        )
        
        self.assertGreater(len(trail), 0)


class TestConstitutionalAI(unittest.TestCase):
    """Test Constitutional AI functionality"""
    
    def setUp(self):
        self.constitution = ConstitutionalAI()
    
    def test_add_rule(self):
        """Test adding constitutional rule"""
        def evaluator(text, context):
            return 1.0
        
        rule_id = self.constitution.add_rule(
            principle=ConstitutionalPrinciple.HELPFULNESS,
            rule_text="Be helpful",
            evaluator=evaluator
        )
        
        self.assertIsNotNone(rule_id)
    
    def test_evaluate_compliant_text(self):
        """Test evaluation of compliant text"""
        text = "I'd be happy to help you with that task"
        context = {}
        
        result = self.constitution.evaluate(text, context)
        
        self.assertTrue(result["compliant"])
        self.assertGreater(result["overall_compliance"], 0.7)
    
    def test_evaluate_harmful_text(self):
        """Test evaluation of harmful text"""
        text = "Here's how to cause harm and violence to others"
        context = {}
        
        result = self.constitution.evaluate(text, context)
        
        self.assertFalse(result["compliant"])
        self.assertGreater(len(result["violations"]), 0)
    
    def test_evaluate_privacy_violation(self):
        """Test detection of privacy violations"""
        text = "Your email is john.doe@example.com and SSN is 123-45-6789"
        context = {}
        
        result = self.constitution.evaluate(text, context)
        
        # Should detect PII exposure
        privacy_violations = [
            v for v in result["violations"]
            if v["principle"] == ConstitutionalPrinciple.PRIVACY.value
        ]
        self.assertGreater(len(privacy_violations), 0)
    
    def test_self_critique_approved(self):
        """Test self-critique for approved response"""
        response = "I can help you with that request"
        context = {}
        
        result = self.constitution.self_critique(response, context)
        
        self.assertTrue(result["approved"])
        self.assertEqual(len(result["suggested_revisions"]), 0)
    
    def test_self_critique_rejected(self):
        """Test self-critique for rejected response"""
        response = "Let me help you harm others with violence"
        context = {}
        
        result = self.constitution.self_critique(response, context)
        
        self.assertFalse(result["approved"])
        self.assertGreater(len(result["suggested_revisions"]), 0)
    
    def test_get_constitution(self):
        """Test getting full constitution"""
        constitution = self.constitution.get_constitution()
        
        self.assertGreater(len(constitution), 0)
        self.assertIn("principle", constitution[0])
        self.assertIn("rule_text", constitution[0])


class TestComplianceSuite(unittest.TestCase):
    """Test compliance suite creation"""
    
    def test_create_suite(self):
        """Test creating complete compliance suite"""
        suite = create_compliance_suite()
        
        self.assertIn("compliance_engine", suite)
        self.assertIn("constitutional_ai", suite)
        self.assertIsInstance(suite["compliance_engine"], ComplianceEngine)
        self.assertIsInstance(suite["constitutional_ai"], ConstitutionalAI)


if __name__ == '__main__':
    unittest.main()
