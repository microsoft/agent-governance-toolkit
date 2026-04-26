# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

"""
Governance Layer - Ethical Alignment and Advanced Safety

The Governance Layer provides enhanced safety mechanisms beyond basic policy
enforcement, including ethical alignment, bias detection, and privacy controls.

Research Foundations:
    - Ethical AI frameworks from "Responsible AI Governance: A Review" 
      (ScienceDirect, 2024)
    - Constitutional AI and value alignment approaches
    - Bias detection and mitigation techniques
    - Privacy-preserving computation from "Privacy in Agentic Systems" 
      (arXiv:2409.1087, 2024)
    - Red-teaming methodologies from "Red-Teaming Agentic AI" (arXiv:2511.21990)

See docs/RESEARCH_FOUNDATION.md for complete references.
"""

from typing import Any, Dict, List, Optional, Callable, Set
from dataclasses import dataclass, field
from enum import Enum
from datetime import datetime
import re


class AlignmentPrinciple(Enum):
    """Core ethical principles for agent alignment"""
    HARM_PREVENTION = "harm_prevention"
    FAIRNESS = "fairness"
    TRANSPARENCY = "transparency"
    PRIVACY = "privacy"
    ACCOUNTABILITY = "accountability"
    HUMAN_OVERSIGHT = "human_oversight"


class BiasType(Enum):
    """Types of bias to detect and mitigate"""
    DEMOGRAPHIC = "demographic"
    CONFIRMATION = "confirmation"
    SELECTION = "selection"
    ANCHORING = "anchoring"
    AVAILABILITY = "availability"


class PrivacyLevel(Enum):
    """Privacy protection levels"""
    PUBLIC = "public"
    INTERNAL = "internal"
    CONFIDENTIAL = "confidential"
    RESTRICTED = "restricted"


@dataclass
class AlignmentRule:
    """
    A rule for ethical alignment.
    
    Attributes:
        rule_id: Unique identifier
        principle: Which ethical principle this enforces
        description: What the rule does
        validator: Function to check compliance
        severity: How critical this rule is (0.0-1.0)
    """
    rule_id: str
    principle: AlignmentPrinciple
    description: str
    validator: Callable[[Dict[str, Any]], bool]
    severity: float = 1.0
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class BiasDetectionResult:
    """Result of bias detection analysis"""
    has_bias: bool
    bias_types: List[BiasType]
    confidence: float
    details: Dict[str, Any]
    recommendations: List[str]


@dataclass
class PrivacyAnalysis:
    """Result of privacy analysis"""
    privacy_level: PrivacyLevel
    contains_pii: bool
    pii_types: List[str]
    risk_score: float
    recommendations: List[str]


class GovernanceLayer:
    """
    Enhanced governance layer for ethical AI operations.
    
    Features:
    - Constitutional AI-inspired value alignment
    - Bias detection and mitigation
    - Privacy-preserving computation hooks
    - Human-in-the-loop intervention points
    - Comprehensive audit trail for compliance
    
    Usage:
        governance = GovernanceLayer()
        
        # Add alignment rules
        governance.add_alignment_rule(
            principle=AlignmentPrinciple.HARM_PREVENTION,
            description="Prevent harmful content generation",
            validator=check_harmful_content
        )
        
        # Check alignment before execution
        result = governance.check_alignment(request_data)
        if not result["aligned"]:
            # Handle misalignment
            pass
        
        # Detect bias
        bias_result = governance.detect_bias(text_content)
        
        # Analyze privacy
        privacy_result = governance.analyze_privacy(data)
    """
    
    def __init__(self):
        self._alignment_rules: Dict[str, AlignmentRule] = {}
        self._bias_patterns: Dict[BiasType, List[str]] = self._load_bias_patterns()
        self._pii_patterns: Dict[str, str] = self._load_pii_patterns()
        self._audit_log: List[Dict[str, Any]] = []
        
    def add_alignment_rule(
        self,
        principle: AlignmentPrinciple,
        description: str,
        validator: Callable[[Dict[str, Any]], bool],
        severity: float = 1.0,
        metadata: Optional[Dict[str, Any]] = None
    ) -> str:
        """
        Add an ethical alignment rule.
        
        Args:
            principle: Which principle this enforces
            description: What the rule does
            validator: Function to check compliance
            severity: How critical (0.0-1.0)
            metadata: Additional metadata
            
        Returns:
            rule_id of the added rule
        """
        import uuid
        rule_id = str(uuid.uuid4())
        
        rule = AlignmentRule(
            rule_id=rule_id,
            principle=principle,
            description=description,
            validator=validator,
            severity=severity,
            metadata=metadata or {}
        )
        
        self._alignment_rules[rule_id] = rule
        return rule_id
    
    def check_alignment(
        self,
        context: Dict[str, Any]
    ) -> Dict[str, Any]:
        """
        Check if a request aligns with ethical principles.
        
        Args:
            context: Request context to evaluate
            
        Returns:
            {
                "aligned": bool,
                "violations": List[Dict],
                "severity": float
            }
        """
        violations = []
        max_severity = 0.0
        
        for rule_id, rule in self._alignment_rules.items():
            try:
                if not rule.validator(context):
                    violations.append({
                        "rule_id": rule_id,
                        "principle": rule.principle.value,
                        "description": rule.description,
                        "severity": rule.severity
                    })
                    max_severity = max(max_severity, rule.severity)
            except Exception as e:
                # Log but don't fail on validator errors
                self._log_audit_event({
                    "event": "validator_error",
                    "rule_id": rule_id,
                    "error": str(e)
                })
        
        return {
            "aligned": len(violations) == 0,
            "violations": violations,
            "severity": max_severity
        }
    
    def detect_bias(
        self,
        text: str,
        context: Optional[Dict[str, Any]] = None
    ) -> BiasDetectionResult:
        """
        Detect potential bias in text content.
        
        This is a simplified implementation. In production, would use
        ML models trained on bias detection datasets.
        
        Args:
            text: Text to analyze
            context: Additional context
            
        Returns:
            BiasDetectionResult with findings
        """
        detected_biases = []
        details = {}
        recommendations = []
        
        # Pattern-based detection (simplified)
        for bias_type, patterns in self._bias_patterns.items():
            matches = []
            for pattern in patterns:
                if re.search(pattern, text, re.IGNORECASE):
                    matches.append(pattern)
            
            if matches:
                detected_biases.append(bias_type)
                details[bias_type.value] = matches
                recommendations.append(
                    f"Review content for {bias_type.value} bias"
                )
        
        return BiasDetectionResult(
            has_bias=len(detected_biases) > 0,
            bias_types=detected_biases,
            confidence=0.7 if detected_biases else 0.0,
            details=details,
            recommendations=recommendations
        )
    
    def analyze_privacy(
        self,
        data: Dict[str, Any]
    ) -> PrivacyAnalysis:
        """
        Analyze data for privacy concerns and PII.
        
        Args:
            data: Data to analyze
            
        Returns:
            PrivacyAnalysis with findings
        """
        pii_found = []
        risk_score = 0.0
        recommendations = []
        
        # Convert data to string for pattern matching
        data_str = str(data)
        
        # Check for PII patterns
        for pii_type, pattern in self._pii_patterns.items():
            if re.search(pattern, data_str, re.IGNORECASE):
                pii_found.append(pii_type)
                risk_score += 0.2
        
        # Determine privacy level
        if len(pii_found) >= 3:
            privacy_level = PrivacyLevel.RESTRICTED
            risk_score = min(risk_score, 1.0)
        elif len(pii_found) >= 1:
            privacy_level = PrivacyLevel.CONFIDENTIAL
        elif "internal" in data_str.lower():
            privacy_level = PrivacyLevel.INTERNAL
        else:
            privacy_level = PrivacyLevel.PUBLIC
        
        if pii_found:
            recommendations.append(
                f"Found PII: {', '.join(pii_found)}. Consider redaction or encryption."
            )
            recommendations.append(
                "Apply differential privacy or secure computation if possible."
            )
        
        return PrivacyAnalysis(
            privacy_level=privacy_level,
            contains_pii=len(pii_found) > 0,
            pii_types=pii_found,
            risk_score=risk_score,
            recommendations=recommendations
        )
    
    def request_human_review(
        self,
        request_id: str,
        reason: str,
        context: Dict[str, Any]
    ) -> Dict[str, Any]:
        """
        Request human review for a decision.
        
        This is a hook for human-in-the-loop patterns.
        In production, would integrate with approval systems.
        
        Args:
            request_id: ID of the request
            reason: Why review is needed
            context: Request context
            
        Returns:
            Review request details
        """
        review_request = {
            "request_id": request_id,
            "reason": reason,
            "context": context,
            "timestamp": datetime.now().isoformat(),
            "status": "pending"
        }
        
        self._log_audit_event({
            "event": "human_review_requested",
            **review_request
        })
        
        return review_request
    
    def get_audit_log(
        self,
        limit: Optional[int] = None
    ) -> List[Dict[str, Any]]:
        """Get governance audit log"""
        if limit:
            return self._audit_log[-limit:]
        return self._audit_log.copy()
    
    def _log_audit_event(self, event: Dict[str, Any]):
        """Internal audit logging"""
        event["timestamp"] = datetime.now().isoformat()
        self._audit_log.append(event)
    
    def _load_bias_patterns(self) -> Dict[BiasType, List[str]]:
        """
        Load bias detection patterns.
        
        In production, would load from comprehensive bias datasets.
        """
        return {
            BiasType.DEMOGRAPHIC: [
                r'\b(all|every) (men|women|people) (are|do)\b',
                r'\btypical (man|woman)\b',
            ],
            BiasType.CONFIRMATION: [
                r'\bproves? (that|what)\b',
                r'\bobviously\b',
                r'\bclearly shows?\b',
            ],
            BiasType.SELECTION: [
                r'\bonly (consider|look at)\b',
                r'\bignore (other|alternative)\b',
            ],
        }
    
    def _load_pii_patterns(self) -> Dict[str, str]:
        """
        Load PII detection patterns.
        
        In production, would use more sophisticated NER models.
        """
        return {
            "email": r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b',
            "ssn": r'\b\d{3}-\d{2}-\d{4}\b',
            "phone": r'\b\d{3}[-.]?\d{3}[-.]?\d{4}\b',
            "credit_card": r'\b\d{4}[- ]?\d{4}[- ]?\d{4}[- ]?\d{4}\b',
            "ip_address": r'\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b',
        }


def create_default_governance() -> GovernanceLayer:
    """
    Create a governance layer with default alignment rules.
    
    Returns:
        GovernanceLayer with standard rules configured
    """
    governance = GovernanceLayer()
    
    # Harm prevention
    def check_no_harmful_content(context: Dict[str, Any]) -> bool:
        """Basic harmful content check"""
        content = str(context.get("content", "")).lower()
        harmful_keywords = ["violence", "harm", "illegal", "exploit"]
        return not any(keyword in content for keyword in harmful_keywords)
    
    governance.add_alignment_rule(
        principle=AlignmentPrinciple.HARM_PREVENTION,
        description="Prevent generation of harmful content",
        validator=check_no_harmful_content,
        severity=1.0
    )
    
    # Privacy protection
    def check_privacy_compliance(context: Dict[str, Any]) -> bool:
        """Check for privacy compliance"""
        analysis = governance.analyze_privacy(context)
        return analysis.privacy_level != PrivacyLevel.RESTRICTED
    
    governance.add_alignment_rule(
        principle=AlignmentPrinciple.PRIVACY,
        description="Ensure privacy protection compliance",
        validator=check_privacy_compliance,
        severity=0.9
    )
    
    return governance
