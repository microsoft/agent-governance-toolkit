# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
# Community Edition — basic YAML policy enforcement
"""
Governance Layer - Pass-through with logging.

Keeps AlignmentPrinciple and BiasType enums.  No actual bias detection
or ethical framework evaluation.
"""

from typing import Any, Dict, List, Optional, Callable
from dataclasses import dataclass, field
from enum import Enum
from datetime import datetime
import logging

logger = logging.getLogger(__name__)


class AlignmentPrinciple(Enum):
    """Core ethical principles for agent alignment."""
    HARM_PREVENTION = "harm_prevention"
    FAIRNESS = "fairness"
    TRANSPARENCY = "transparency"
    PRIVACY = "privacy"
    ACCOUNTABILITY = "accountability"
    HUMAN_OVERSIGHT = "human_oversight"


class BiasType(Enum):
    """Types of bias to detect and mitigate."""
    DEMOGRAPHIC = "demographic"
    CONFIRMATION = "confirmation"
    SELECTION = "selection"
    ANCHORING = "anchoring"
    AVAILABILITY = "availability"


class PrivacyLevel(Enum):
    """Privacy protection levels."""
    PUBLIC = "public"
    INTERNAL = "internal"
    CONFIDENTIAL = "confidential"
    RESTRICTED = "restricted"


@dataclass
class AlignmentRule:
    """A rule for ethical alignment."""
    rule_id: str
    principle: AlignmentPrinciple
    description: str
    validator: Callable[[Dict[str, Any]], bool]
    severity: float = 1.0
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class BiasDetectionResult:
    """Result of bias detection analysis."""
    has_bias: bool
    bias_types: List[BiasType]
    confidence: float
    details: Dict[str, Any]
    recommendations: List[str]


@dataclass
class PrivacyAnalysis:
    """Result of privacy analysis."""
    privacy_level: PrivacyLevel
    contains_pii: bool
    pii_types: List[str]
    risk_score: float
    recommendations: List[str]


class GovernanceLayer:
    """Pass-through governance layer with logging.  No real bias detection."""

    def __init__(self):
        self._alignment_rules: Dict[str, AlignmentRule] = {}
        self._audit_log: List[Dict[str, Any]] = []

    def add_alignment_rule(
        self,
        principle: AlignmentPrinciple,
        description: str,
        validator: Callable[[Dict[str, Any]], bool],
        severity: float = 1.0,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> str:
        import uuid
        rule_id = str(uuid.uuid4())
        self._alignment_rules[rule_id] = AlignmentRule(
            rule_id=rule_id, principle=principle, description=description,
            validator=validator, severity=severity, metadata=metadata or {},
        )
        return rule_id

    def check_alignment(self, context: Dict[str, Any]) -> Dict[str, Any]:
        """Pass-through: logs and returns aligned=True unless a validator fails."""
        violations = []
        max_severity = 0.0
        for rule_id, rule in self._alignment_rules.items():
            try:
                if not rule.validator(context):
                    violations.append({
                        "rule_id": rule_id,
                        "principle": rule.principle.value,
                        "description": rule.description,
                        "severity": rule.severity,
                    })
                    max_severity = max(max_severity, rule.severity)
            except Exception as e:
                logger.warning(f"Governance validator error for {rule_id}: {e}")
        result = {"aligned": len(violations) == 0, "violations": violations, "severity": max_severity}
        self._log_audit_event({"event": "alignment_check", **result})
        return result

    def detect_bias(self, text: str, context: Optional[Dict[str, Any]] = None) -> BiasDetectionResult:
        """No-op bias detection — always returns no bias."""
        logger.debug("Bias detection called (pass-through)")
        return BiasDetectionResult(
            has_bias=False, bias_types=[], confidence=0.0, details={}, recommendations=[],
        )

    def analyze_privacy(self, data: Dict[str, Any]) -> PrivacyAnalysis:
        """No-op privacy analysis — always returns PUBLIC."""
        logger.debug("Privacy analysis called (pass-through)")
        return PrivacyAnalysis(
            privacy_level=PrivacyLevel.PUBLIC, contains_pii=False,
            pii_types=[], risk_score=0.0, recommendations=[],
        )

    def request_human_review(
        self, request_id: str, reason: str, context: Dict[str, Any]
    ) -> Dict[str, Any]:
        review = {
            "request_id": request_id, "reason": reason, "context": context,
            "timestamp": datetime.now().isoformat(), "status": "pending",
        }
        self._log_audit_event({"event": "human_review_requested", **review})
        return review

    def get_audit_log(self, limit: Optional[int] = None) -> List[Dict[str, Any]]:
        if limit:
            return self._audit_log[-limit:]
        return self._audit_log.copy()

    def _log_audit_event(self, event: Dict[str, Any]):
        event["timestamp"] = datetime.now().isoformat()
        self._audit_log.append(event)


def create_default_governance() -> GovernanceLayer:
    """Create a governance layer with basic default rules."""
    governance = GovernanceLayer()

    def check_no_harmful_content(context: Dict[str, Any]) -> bool:
        content = str(context.get("content", "")).lower()
        harmful = ["violence", "harm", "illegal", "exploit"]
        return not any(kw in content for kw in harmful)

    governance.add_alignment_rule(
        principle=AlignmentPrinciple.HARM_PREVENTION,
        description="Prevent generation of harmful content",
        validator=check_no_harmful_content,
        severity=1.0,
    )
    return governance