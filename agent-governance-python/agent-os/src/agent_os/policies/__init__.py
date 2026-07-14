# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""Surviving Agent-OS context and rate-limit primitives."""

from .context_accumulation import (
    ContextDecision,
    ContextOutcome,
    accumulate,
    decide_next,
)
from .context_aggregation import (
    AggregationResult,
    AggregationRule,
    AggregationRuleSet,
    evaluate_aggregation,
)
from .context_audit import ContextEvent, context_event
from .context_delegation import merge_restrictions
from .context_envelope import (
    ContextEnvelope,
    EnvelopeReference,
    apply_restrictions,
    envelope_reference,
    fold,
)
from .data_classification import DataClassification
from .dynamic_context import (
    CostContext,
    DynamicContext,
    QuotaContext,
    SystemContext,
    TimeContext,
)
from .obligations import Obligation, ObligationSet
from .rate_limiting import RateLimitConfig, RateLimitExceeded, TokenBucket

__all__ = [
    "AggregationResult",
    "AggregationRule",
    "AggregationRuleSet",
    "ContextDecision",
    "ContextEnvelope",
    "ContextEvent",
    "ContextOutcome",
    "CostContext",
    "DataClassification",
    "DynamicContext",
    "EnvelopeReference",
    "Obligation",
    "ObligationSet",
    "QuotaContext",
    "RateLimitConfig",
    "RateLimitExceeded",
    "SystemContext",
    "TimeContext",
    "TokenBucket",
    "accumulate",
    "apply_restrictions",
    "context_event",
    "decide_next",
    "envelope_reference",
    "evaluate_aggregation",
    "fold",
    "merge_restrictions",
]
