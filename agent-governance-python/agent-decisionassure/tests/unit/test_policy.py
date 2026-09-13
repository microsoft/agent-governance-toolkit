# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

import pytest
import uuid
from datetime import datetime, timezone, timedelta
from agent_decisionassure.engine import ImpactEngine
from agent_decisionassure.models import Action, DecisionTrace, TraceBatch


def test_policy_evaluation():
    action = Action(
        id=uuid.uuid4(),
        name="refund",
        parameters={"amount": 45000},
        tool="payment-api",
        version="v3",
        transaction_amount=200000  # Increased to push severity to HIGH -> BLOCK
    )
    decision = DecisionTrace(
        action=action,
        agent_id=uuid.uuid4(),
        agent_version="1.0",
        timestamp=datetime.now(timezone.utc),
        policy_version="v4",
        authority_chain=["delegation_123"],
        context={"risk_score": 35, "evidence_age_hours": 0.5},  # risk_score 35 so risk rule fails
        evidence_used=[],
        evidence_age_hours=0.5,
        tool_permissions_at_time=["read"],
        model_version="approved_v1",
        result="ALLOW"
    )
    trace = TraceBatch(
        trace_id=uuid.uuid4(),
        decisions=[decision],
        environment={},
        metadata={}
    )
    engine = ImpactEngine([trace])

    policy_v4 = {
        "version": "v4",
        "rules": [
            {"condition": "context.get('risk_score', 100) < 30", "effect": "ALLOW", "priority": 10},
            {"condition": "action.name == 'refund' and action.parameters.get('amount', 0) <= 50000", "effect": "ALLOW", "priority": 5}
        ],
        "default_effect": "DENY"
    }
    policy_v5 = {
        "version": "v5",
        "rules": [
            {"condition": "context.get('risk_score', 100) < 30", "effect": "ALLOW", "priority": 10},
            {"condition": "action.name == 'refund' and action.parameters.get('amount', 0) <= 40000", "effect": "ALLOW", "priority": 5}
        ],
        "default_effect": "DENY"
    }

    authority = {
        "delegations": [
            {
                "id": "delegation_123",
                "grantor": "admin",
                "grantee": "agent",
                "permissions": ["refund"],
                "valid_from": (datetime.now(timezone.utc) - timedelta(days=1)).isoformat(),
                "valid_until": (datetime.now(timezone.utc) + timedelta(days=1)).isoformat(),
            }
        ],
        "global_tool_capabilities": {"payment-api": ["read", "write"]}
    }

    report = engine.analyze_impact(policy_v4, authority, policy_v5, authority)
    assert report.transitions.admissible_to_inadmissible == 1
    assert report.recommendation == "BLOCK"
