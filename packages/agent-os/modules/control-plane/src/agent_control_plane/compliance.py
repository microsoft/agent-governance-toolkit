# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""
Compliance and Regulatory Framework

This module provides compliance mechanisms for various regulatory frameworks
including EU AI Act, SOC 2, FedRAMP, GDPR, and industry-specific regulations.

Research Foundations:
    - EU AI Act (2024) - Risk-based classification and requirements
    - SOC 2 Trust Service Criteria - Security, availability, confidentiality
    - FedRAMP requirements for cloud service authorization
    - GDPR Article 22 - Automated decision-making and profiling
    - "Compliance by Design for AI Systems" (IEEE, 2024)
    - Constitutional AI from Anthropic research

See docs/RESEARCH_FOUNDATION.md for complete references.
"""

from typing import Any, Dict, List, Optional, Callable
from dataclasses import dataclass, field
from enum import Enum
from datetime import datetime, timedelta
import json


class RegulatoryFramework(Enum):
    """Supported regulatory frameworks"""
    EU_AI_ACT = "eu_ai_act"
    SOC2 = "soc2"
    FEDRAMP = "fedramp"
    GDPR = "gdpr"
    HIPAA = "hipaa"
    PCI_DSS = "pci_dss"
    ISO27001 = "iso27001"


class RiskCategory(Enum):
    """EU AI Act risk categories"""
    UNACCEPTABLE = "unacceptable"
    HIGH_RISK = "high_risk"
    LIMITED_RISK = "limited_risk"
    MINIMAL_RISK = "minimal_risk"


class ConstitutionalPrinciple(Enum):
    """Constitutional AI principles"""
    HELPFULNESS = "helpfulness"
    HARMLESSNESS = "harmlessness"
    HONESTY = "honesty"
    TRANSPARENCY = "transparency"
    FAIRNESS = "fairness"
    PRIVACY = "privacy"


@dataclass
class ComplianceRequirement:
    """
    A specific compliance requirement.
    
    Attributes:
        requirement_id: Unique identifier
        framework: Which regulatory framework
        title: Short description
        description: Detailed requirement
        validator: Function to check compliance
        mandatory: Whether this is mandatory
        control_id: Control identifier (e.g., SOC2-CC6.1)
    """
    requirement_id: str
    framework: RegulatoryFramework
    title: str
    description: str
    validator: Callable[[Dict[str, Any]], bool]
    mandatory: bool = True
    control_id: Optional[str] = None
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class ComplianceCheck:
    """Result of a compliance check"""
    compliant: bool
    framework: RegulatoryFramework
    checks_passed: int
    checks_failed: int
    failures: List[Dict[str, Any]]
    recommendations: List[str]
    timestamp: datetime = field(default_factory=datetime.now)


@dataclass
class ConstitutionalRule:
    """
    A constitutional rule inspired by Constitutional AI.
    
    These are high-level principles that guide agent behavior,
    evaluated before and after agent actions.
    """
    rule_id: str
    principle: ConstitutionalPrinciple
    rule_text: str
    evaluator: Callable[[str, Dict[str, Any]], float]  # Returns 0.0-1.0 compliance
    severity: float = 1.0
    examples: List[str] = field(default_factory=list)


class ComplianceEngine:
    """
    Compliance engine for regulatory adherence.
    
    Features:
    - Multi-framework compliance checking
    - Automated control validation
    - Audit trail generation
    - Compliance reporting
    - Risk assessment per EU AI Act
    
    Usage:
        engine = ComplianceEngine()
        
        # Add requirements
        engine.add_requirement(
            framework=RegulatoryFramework.EU_AI_ACT,
            title="Human oversight",
            validator=check_human_oversight
        )
        
        # Check compliance
        result = engine.check_compliance(
            framework=RegulatoryFramework.EU_AI_ACT,
            context=system_context
        )
    """
    
    def __init__(self):
        self._requirements: Dict[RegulatoryFramework, List[ComplianceRequirement]] = {}
        self._audit_trail: List[Dict[str, Any]] = []
        self._initialize_default_requirements()
    
    def add_requirement(
        self,
        framework: RegulatoryFramework,
        title: str,
        description: str,
        validator: Callable[[Dict[str, Any]], bool],
        mandatory: bool = True,
        control_id: Optional[str] = None
    ) -> str:
        """
        Add a compliance requirement.
        
        Args:
            framework: Regulatory framework
            title: Short description
            description: Detailed requirement
            validator: Function to check compliance
            mandatory: Whether this is mandatory
            control_id: Control identifier
            
        Returns:
            requirement_id
        """
        import uuid
        requirement_id = str(uuid.uuid4())
        
        requirement = ComplianceRequirement(
            requirement_id=requirement_id,
            framework=framework,
            title=title,
            description=description,
            validator=validator,
            mandatory=mandatory,
            control_id=control_id
        )
        
        if framework not in self._requirements:
            self._requirements[framework] = []
        
        self._requirements[framework].append(requirement)
        return requirement_id
    
    def check_compliance(
        self,
        framework: RegulatoryFramework,
        context: Dict[str, Any]
    ) -> ComplianceCheck:
        """
        Check compliance with a regulatory framework.
        
        Args:
            framework: Framework to check against
            context: System context for validation
            
        Returns:
            ComplianceCheck with results
        """
        requirements = self._requirements.get(framework, [])
        
        passed = 0
        failed = 0
        failures = []
        recommendations = []
        
        for req in requirements:
            try:
                is_compliant = req.validator(context)
                
                if is_compliant:
                    passed += 1
                else:
                    failed += 1
                    failures.append({
                        "requirement_id": req.requirement_id,
                        "title": req.title,
                        "description": req.description,
                        "control_id": req.control_id,
                        "mandatory": req.mandatory
                    })
                    
                    if req.mandatory:
                        recommendations.append(
                            f"CRITICAL: Fix mandatory requirement: {req.title}"
                        )
                
                # Log to audit trail
                self._audit_trail.append({
                    "type": "compliance_check",
                    "framework": framework.value,
                    "requirement": req.title,
                    "result": "pass" if is_compliant else "fail",
                    "timestamp": datetime.now().isoformat()
                })
                
            except Exception as e:
                failed += 1
                failures.append({
                    "requirement_id": req.requirement_id,
                    "title": req.title,
                    "error": str(e)
                })
        
        return ComplianceCheck(
            compliant=failed == 0,
            framework=framework,
            checks_passed=passed,
            checks_failed=failed,
            failures=failures,
            recommendations=recommendations
        )
    
    def assess_risk_category(
        self,
        system_description: Dict[str, Any]
    ) -> RiskCategory:
        """
        Assess risk category per EU AI Act.
        
        Args:
            system_description: Description of the AI system
            
        Returns:
            RiskCategory classification
        """
        # Unacceptable risk systems (Article 5)
        unacceptable_indicators = [
            "social_scoring",
            "subliminal_manipulation",
            "exploit_vulnerabilities",
            "biometric_categorization"
        ]
        
        for indicator in unacceptable_indicators:
            if indicator in str(system_description).lower():
                return RiskCategory.UNACCEPTABLE
        
        # High-risk systems (Annex III)
        high_risk_indicators = [
            "critical_infrastructure",
            "education",
            "employment",
            "essential_services",
            "law_enforcement",
            "migration",
            "justice",
            "biometric_identification"
        ]
        
        for indicator in high_risk_indicators:
            if indicator in str(system_description).lower():
                return RiskCategory.HIGH_RISK
        
        # Limited risk (transparency obligations)
        limited_risk_indicators = [
            "chatbot",
            "content_generation",
            "deepfake"
        ]
        
        for indicator in limited_risk_indicators:
            if indicator in str(system_description).lower():
                return RiskCategory.LIMITED_RISK
        
        return RiskCategory.MINIMAL_RISK
    
    def generate_compliance_report(
        self,
        framework: RegulatoryFramework
    ) -> Dict[str, Any]:
        """
        Generate a compliance report.
        
        Args:
            framework: Framework to report on
            
        Returns:
            Compliance report dictionary
        """
        requirements = self._requirements.get(framework, [])
        
        # Get recent audit trail for this framework
        recent_checks = [
            entry for entry in self._audit_trail
            if entry.get("framework") == framework.value
            and datetime.fromisoformat(entry["timestamp"]) > 
                datetime.now() - timedelta(days=30)
        ]
        
        passed = sum(1 for c in recent_checks if c["result"] == "pass")
        failed = sum(1 for c in recent_checks if c["result"] == "fail")
        
        return {
            "framework": framework.value,
            "total_requirements": len(requirements),
            "mandatory_requirements": sum(1 for r in requirements if r.mandatory),
            "recent_checks": len(recent_checks),
            "passed": passed,
            "failed": failed,
            "compliance_rate": (passed / len(recent_checks) * 100) if recent_checks else 0,
            "generated_at": datetime.now().isoformat()
        }
    
    def get_audit_trail(
        self,
        framework: Optional[RegulatoryFramework] = None,
        days: int = 30
    ) -> List[Dict[str, Any]]:
        """
        Get audit trail entries.
        
        Args:
            framework: Optional framework filter
            days: Number of days to look back
            
        Returns:
            List of audit trail entries
        """
        cutoff = datetime.now() - timedelta(days=days)
        
        entries = [
            entry for entry in self._audit_trail
            if datetime.fromisoformat(entry["timestamp"]) > cutoff
        ]
        
        if framework:
            entries = [
                entry for entry in entries
                if entry.get("framework") == framework.value
            ]
        
        return entries
    
    def _initialize_default_requirements(self):
        """Initialize default compliance requirements"""
        
        # EU AI Act - High-Risk System Requirements
        def check_human_oversight(context: Dict[str, Any]) -> bool:
            """EU AI Act Article 14 - Human oversight"""
            return context.get("human_oversight_enabled", False)
        
        self.add_requirement(
            framework=RegulatoryFramework.EU_AI_ACT,
            title="Human oversight",
            description="High-risk AI systems must be designed with human oversight",
            validator=check_human_oversight,
            mandatory=True,
            control_id="EU-AI-Act-Art14"
        )
        
        def check_transparency(context: Dict[str, Any]) -> bool:
            """EU AI Act Article 13 - Transparency"""
            return context.get("provides_transparency_info", False)
        
        self.add_requirement(
            framework=RegulatoryFramework.EU_AI_ACT,
            title="Transparency and information",
            description="Users must be informed they are interacting with an AI system",
            validator=check_transparency,
            mandatory=True,
            control_id="EU-AI-Act-Art13"
        )
        
        # SOC 2 - Common Criteria
        def check_access_controls(context: Dict[str, Any]) -> bool:
            """SOC 2 CC6.1 - Logical and physical access controls"""
            return context.get("access_controls_implemented", False)
        
        self.add_requirement(
            framework=RegulatoryFramework.SOC2,
            title="Access controls",
            description="Logical and physical access controls restrict access to authorized users",
            validator=check_access_controls,
            mandatory=True,
            control_id="CC6.1"
        )
        
        def check_monitoring(context: Dict[str, Any]) -> bool:
            """SOC 2 CC7.2 - System monitoring"""
            return context.get("monitoring_enabled", False)
        
        self.add_requirement(
            framework=RegulatoryFramework.SOC2,
            title="System monitoring",
            description="The entity monitors system components and operation of controls",
            validator=check_monitoring,
            mandatory=True,
            control_id="CC7.2"
        )
        
        # GDPR
        def check_data_minimization(context: Dict[str, Any]) -> bool:
            """GDPR Article 5(1)(c) - Data minimization"""
            collected = context.get("data_collected", [])
            necessary = context.get("data_necessary", [])
            return set(collected).issubset(set(necessary))
        
        self.add_requirement(
            framework=RegulatoryFramework.GDPR,
            title="Data minimization",
            description="Personal data must be adequate, relevant and limited to what is necessary",
            validator=check_data_minimization,
            mandatory=True,
            control_id="GDPR-Art5-1-c"
        )


class ConstitutionalAI:
    """
    Constitutional AI implementation for value alignment.
    
    Based on Anthropic's Constitutional AI approach, this provides
    a framework for aligning agent behavior with human values through
    explicit constitutional rules.
    
    Features:
    - Define constitutional principles
    - Evaluate actions against constitution
    - Self-critique and revision
    - Transparency in decision-making
    
    Usage:
        constitution = ConstitutionalAI()
        
        # Add rules
        constitution.add_rule(
            principle=ConstitutionalPrinciple.HARMLESSNESS,
            rule_text="Never assist with illegal activities",
            evaluator=evaluate_harmlessness
        )
        
        # Evaluate
        result = constitution.evaluate("User request text", context)
    """
    
    def __init__(self):
        self._rules: List[ConstitutionalRule] = []
        self._initialize_default_constitution()
    
    def add_rule(
        self,
        principle: ConstitutionalPrinciple,
        rule_text: str,
        evaluator: Callable[[str, Dict[str, Any]], float],
        severity: float = 1.0,
        examples: Optional[List[str]] = None
    ) -> str:
        """
        Add a constitutional rule.
        
        Args:
            principle: Which principle this enforces
            rule_text: Human-readable rule description
            evaluator: Function that evaluates compliance (0.0-1.0)
            severity: How important this rule is
            examples: Example applications of the rule
            
        Returns:
            rule_id
        """
        import uuid
        rule_id = str(uuid.uuid4())
        
        rule = ConstitutionalRule(
            rule_id=rule_id,
            principle=principle,
            rule_text=rule_text,
            evaluator=evaluator,
            severity=severity,
            examples=examples or []
        )
        
        self._rules.append(rule)
        return rule_id
    
    def evaluate(
        self,
        text: str,
        context: Dict[str, Any]
    ) -> Dict[str, Any]:
        """
        Evaluate text against constitutional rules.
        
        Args:
            text: Text to evaluate (prompt, response, etc.)
            context: Additional context
            
        Returns:
            Evaluation results with compliance scores
        """
        results = []
        total_score = 0.0
        total_weight = 0.0
        violations = []
        
        for rule in self._rules:
            try:
                compliance_score = rule.evaluator(text, context)
                
                results.append({
                    "rule_id": rule.rule_id,
                    "principle": rule.principle.value,
                    "rule_text": rule.rule_text,
                    "compliance_score": compliance_score,
                    "severity": rule.severity
                })
                
                total_score += compliance_score * rule.severity
                total_weight += rule.severity
                
                if compliance_score < 0.7:  # Threshold for violation
                    violations.append({
                        "principle": rule.principle.value,
                        "rule_text": rule.rule_text,
                        "compliance_score": compliance_score
                    })
                    
            except Exception as e:
                results.append({
                    "rule_id": rule.rule_id,
                    "error": str(e)
                })
        
        overall_compliance = (total_score / total_weight) if total_weight > 0 else 1.0
        
        return {
            "compliant": overall_compliance >= 0.7,
            "overall_compliance": overall_compliance,
            "rule_results": results,
            "violations": violations,
            "recommendations": self._generate_recommendations(violations)
        }
    
    def self_critique(
        self,
        proposed_response: str,
        context: Dict[str, Any]
    ) -> Dict[str, Any]:
        """
        Perform self-critique on a proposed response.
        
        This is a key Constitutional AI technique where the system
        evaluates its own outputs before presenting them.
        
        Args:
            proposed_response: Response to critique
            context: Context including original prompt
            
        Returns:
            Critique results with suggested revisions
        """
        evaluation = self.evaluate(proposed_response, context)
        
        revisions = []
        if not evaluation["compliant"]:
            for violation in evaluation["violations"]:
                revisions.append(f"Revise to better align with: {violation['rule_text']}")
        
        return {
            "approved": evaluation["compliant"],
            "compliance_score": evaluation["overall_compliance"],
            "violations": evaluation["violations"],
            "suggested_revisions": revisions
        }
    
    def _generate_recommendations(
        self,
        violations: List[Dict[str, Any]]
    ) -> List[str]:
        """Generate recommendations based on violations"""
        if not violations:
            return []
        
        recommendations = ["Review and revise content to address constitutional violations:"]
        
        for violation in violations:
            recommendations.append(
                f"- Align with principle: {violation['principle']} - {violation['rule_text']}"
            )
        
        return recommendations
    
    def _initialize_default_constitution(self):
        """Initialize default constitutional rules"""
        
        def evaluate_harmlessness(text: str, context: Dict[str, Any]) -> float:
            """Evaluate harmlessness principle"""
            harmful_keywords = [
                "violence", "harm", "illegal", "exploit",
                "manipulate", "deceive", "dangerous"
            ]
            text_lower = text.lower()
            
            violations = sum(1 for keyword in harmful_keywords if keyword in text_lower)
            # Need at least 2 violations to fail
            return max(0.0, 1.0 - (violations * 0.5))
        
        self.add_rule(
            principle=ConstitutionalPrinciple.HARMLESSNESS,
            rule_text="Avoid content that could cause harm to individuals or society",
            evaluator=evaluate_harmlessness,
            severity=1.0,
            examples=[
                "Don't provide instructions for illegal activities",
                "Don't generate content promoting violence",
                "Don't help with harmful manipulations"
            ]
        )
        
        def evaluate_honesty(text: str, context: Dict[str, Any]) -> float:
            """Evaluate honesty principle"""
            dishonest_indicators = [
                "guarantee", "100% certain", "definitely will",
                "impossible to", "never wrong"
            ]
            text_lower = text.lower()
            
            violations = sum(1 for indicator in dishonest_indicators if indicator in text_lower)
            return max(0.0, 1.0 - (violations * 0.25))
        
        self.add_rule(
            principle=ConstitutionalPrinciple.HONESTY,
            rule_text="Be honest about capabilities, limitations, and uncertainty",
            evaluator=evaluate_honesty,
            severity=0.9,
            examples=[
                "Acknowledge when uncertain",
                "Don't overstate capabilities",
                "Be truthful about limitations"
            ]
        )
        
        def evaluate_privacy(text: str, context: Dict[str, Any]) -> float:
            """Evaluate privacy principle"""
            # Check for PII exposure
            import re
            pii_patterns = [
                r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b',  # email
                r'\b\d{3}-\d{2}-\d{4}\b',  # SSN
                r'\b\d{3}[-.]?\d{3}[-.]?\d{4}\b',  # phone
            ]
            
            violations = sum(1 for pattern in pii_patterns if re.search(pattern, text))
            return max(0.0, 1.0 - (violations * 0.3))
        
        self.add_rule(
            principle=ConstitutionalPrinciple.PRIVACY,
            rule_text="Protect privacy and don't expose personal information",
            evaluator=evaluate_privacy,
            severity=1.0,
            examples=[
                "Don't include PII in responses",
                "Respect data confidentiality",
                "Follow privacy best practices"
            ]
        )
    
    def get_constitution(self) -> List[Dict[str, Any]]:
        """Get the full constitution as a readable format"""
        return [
            {
                "principle": rule.principle.value,
                "rule_text": rule.rule_text,
                "severity": rule.severity,
                "examples": rule.examples
            }
            for rule in self._rules
        ]


def create_compliance_suite() -> Dict[str, Any]:
    """
    Create a complete compliance suite with multiple frameworks.
    
    Returns:
        Dictionary with compliance engine and constitutional AI
    """
    return {
        "compliance_engine": ComplianceEngine(),
        "constitutional_ai": ConstitutionalAI()
    }
