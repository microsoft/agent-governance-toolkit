# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""Data-layer ABAC policies for AI agent governance.

Extends the policy engine beyond tool-level to data-level enforcement.
Agents are checked not just for which tools they can use, but which
data classifications they can access.

Addresses the market gap where 63% of organizations cannot stop
their AI from accessing unauthorized data (Kiteworks 2026 research).
"""

from __future__ import annotations

import re
from datetime import datetime, timezone
from enum import IntEnum
from typing import Optional

from pydantic import BaseModel, Field


class DataClassification(IntEnum):
    """Sensitivity levels for data classification, ordered by sensitivity."""

    PUBLIC = 0
    INTERNAL = 1
    CONFIDENTIAL = 2
    RESTRICTED = 3
    TOP_SECRET = 4


class DataLabel(BaseModel):
    """Label describing data sensitivity and handling requirements."""

    classification: DataClassification
    categories: list[str] = Field(
        default_factory=list,
        description="Data categories such as PII, PHI, PCI, GDPR, ITAR",
    )
    owner: str = ""
    retention_days: int = 90
    geography: str = ""


class ABACPolicy(BaseModel):
    """Attribute-Based Access Control policy for an agent."""

    agent_id: str
    allowed_classifications: list[DataClassification] = Field(default_factory=list)
    allowed_categories: list[str] = Field(default_factory=list)
    denied_categories: list[str] = Field(default_factory=list)
    required_geography: Optional[str] = None
    max_classification: DataClassification = DataClassification.PUBLIC


class DataAccessDecision(BaseModel):
    """Result of evaluating an agent's data access request."""

    allowed: bool
    reason: str
    agent_id: str
    data_label: DataLabel
    matched_policy: Optional[str] = None
    evaluated_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))


class DataAccessEvaluator:
    """Evaluates agent data-access requests against ABAC policies.

    When multiple policies exist for the same agent, the most restrictive
    result wins (deny takes precedence over allow).
    """

    def __init__(self, policies: list[ABACPolicy]) -> None:
        self._policies = policies

    def evaluate(self, agent_id: str, data_label: DataLabel) -> DataAccessDecision:
        """Check whether *agent_id* may access data described by *data_label*."""
        agent_policies = [p for p in self._policies if p.agent_id == agent_id]
        if not agent_policies:
            return DataAccessDecision(
                allowed=False,
                reason="No ABAC policy registered for agent",
                agent_id=agent_id,
                data_label=data_label,
            )

        # Evaluate each policy; any denial means overall denial (most restrictive wins)
        for policy in agent_policies:
            decision = self._evaluate_single(agent_id, data_label, policy)
            if not decision.allowed:
                return decision

        # All policies passed
        return DataAccessDecision(
            allowed=True,
            reason="Access permitted by all applicable policies",
            agent_id=agent_id,
            data_label=data_label,
            matched_policy=agent_policies[0].agent_id,
        )

    @staticmethod
    def _evaluate_single(
        agent_id: str, data_label: DataLabel, policy: ABACPolicy
    ) -> DataAccessDecision:
        policy_ref = policy.agent_id

        if data_label.classification > policy.max_classification:
            return DataAccessDecision(
                allowed=False,
                reason=(
                    f"Classification {data_label.classification.name} exceeds "
                    f"max {policy.max_classification.name}"
                ),
                agent_id=agent_id,
                data_label=data_label,
                matched_policy=policy_ref,
            )

        if (
            policy.allowed_classifications
            and data_label.classification not in policy.allowed_classifications
        ):
            return DataAccessDecision(
                allowed=False,
                reason=(
                    f"Classification {data_label.classification.name} not in "
                    f"allowed list"
                ),
                agent_id=agent_id,
                data_label=data_label,
                matched_policy=policy_ref,
            )

        for cat in data_label.categories:
            if cat in policy.denied_categories:
                return DataAccessDecision(
                    allowed=False,
                    reason=f"Category '{cat}' is explicitly denied",
                    agent_id=agent_id,
                    data_label=data_label,
                    matched_policy=policy_ref,
                )

        if policy.allowed_categories:
            for cat in data_label.categories:
                if cat not in policy.allowed_categories:
                    return DataAccessDecision(
                        allowed=False,
                        reason=f"Category '{cat}' not in allowed categories",
                        agent_id=agent_id,
                        data_label=data_label,
                        matched_policy=policy_ref,
                    )

        if (
            policy.required_geography
            and data_label.geography
            and data_label.geography != policy.required_geography
        ):
            return DataAccessDecision(
                allowed=False,
                reason=(
                    f"Geography '{data_label.geography}' does not match "
                    f"required '{policy.required_geography}'"
                ),
                agent_id=agent_id,
                data_label=data_label,
                matched_policy=policy_ref,
            )

        return DataAccessDecision(
            allowed=True,
            reason="Policy passed",
            agent_id=agent_id,
            data_label=data_label,
            matched_policy=policy_ref,
        )


# ---------------------------------------------------------------------------
# PII / PHI / PCI detection helpers
# ---------------------------------------------------------------------------

_SSN_RE = re.compile(r"\b\d{3}-\d{2}-\d{4}\b")
_EMAIL_RE = re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b")
_PHONE_RE = re.compile(
    r"\b(?:\+1[-.\s]?)?\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}\b"
)

_MRN_RE = re.compile(r"\bMRN[-:\s]*\d{6,10}\b", re.IGNORECASE)
_ICD_RE = re.compile(r"\b[A-Z]\d{2}(?:\.\d{1,4})?\b")

_CC_RE = re.compile(r"\b(?:\d[ -]*?){13,19}\b")


def detect_pii(text: str) -> list[str]:
    """Detect PII patterns (SSN, email, phone) in *text*."""
    findings: list[str] = []
    if _SSN_RE.search(text):
        findings.append("SSN")
    if _EMAIL_RE.search(text):
        findings.append("email")
    if _PHONE_RE.search(text):
        findings.append("phone")
    return findings


def detect_phi(text: str) -> list[str]:
    """Detect PHI patterns (medical record numbers, diagnosis codes)."""
    findings: list[str] = []
    if _MRN_RE.search(text):
        findings.append("MRN")
    if _ICD_RE.search(text):
        findings.append("ICD-code")
    return findings


def detect_pci(text: str) -> list[str]:
    """Detect PCI patterns (credit card numbers)."""
    findings: list[str] = []
    if _CC_RE.search(text):
        findings.append("credit-card")
    return findings


def classify_text(text: str) -> DataLabel:
    """Auto-classify *text* based on detected sensitive-data patterns."""
    categories: list[str] = []
    classification = DataClassification.PUBLIC

    pii = detect_pii(text)
    if pii:
        categories.append("PII")
        classification = max(classification, DataClassification.CONFIDENTIAL)

    phi = detect_phi(text)
    if phi:
        categories.append("PHI")
        classification = max(classification, DataClassification.RESTRICTED)

    pci = detect_pci(text)
    if pci:
        categories.append("PCI")
        classification = max(classification, DataClassification.CONFIDENTIAL)

    if not categories:
        classification = DataClassification.PUBLIC

    return DataLabel(classification=classification, categories=categories)
