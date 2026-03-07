# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""
Declarative policy language for Agent-OS governance.

Separates policy rules (YAML/JSON data) from evaluation logic,
enabling policies to be authored, versioned, and shared as plain files.
"""

from .async_evaluator import AsyncPolicyEvaluator, ConcurrencyStats
from .bridge import document_to_governance, governance_to_document
from .evaluator import PolicyDecision, PolicyEvaluator
from .schema import (
    PolicyAction,
    PolicyCondition,
    PolicyDefaults,
    PolicyDocument,
    PolicyOperator,
    PolicyRule,
)
from .shared import (
    Condition,
    SharedPolicyDecision,
    SharedPolicyEvaluator,
    SharedPolicyRule,
    SharedPolicySchema,
    policy_document_to_shared,
    shared_to_policy_document,
)

__all__ = [
    "AsyncPolicyEvaluator",
    "ConcurrencyStats",
    "Condition",
    "PolicyAction",
    "PolicyCondition",
    "PolicyDecision",
    "PolicyDefaults",
    "PolicyDocument",
    "PolicyEvaluator",
    "PolicyOperator",
    "PolicyRule",
    "SharedPolicyDecision",
    "SharedPolicyEvaluator",
    "SharedPolicyRule",
    "SharedPolicySchema",
    "document_to_governance",
    "governance_to_document",
    "policy_document_to_shared",
    "shared_to_policy_document",
]
