import pytest
import uuid
from datetime import datetime, timezone, timedelta
from agent_decisionassure.engine import ImpactEngine
from agent_decisionassure.models import Action, DecisionTrace, TraceBatch


def test_authority_expiry():
    decision_time = datetime.now(timezone.utc)
    action = Action(
        id=uuid.uuid4(),
        name="refund",
        parameters={"amount": 1000},
        tool="payment-api",
        version="v3",
        transaction_amount=1000
    )
    decision = DecisionTrace(
        action=action,
        agent_id=uuid.uuid4(),
        agent_version="1.0",
        timestamp=decision_time,
        policy_version="v4",
        authority_chain=["delegation_123"],
        context={"risk_score": 25, "evidence_age_hours": 0.5},
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

    policy = {"version": "v4", "rules": [], "default_effect": "ALLOW"}

    authority_valid = {
        "delegations": [
            {
                "id": "delegation_123",
                "grantor": "admin",
                "grantee": "agent",
                "permissions": ["refund"],
                "valid_from": (decision_time - timedelta(days=1)).isoformat(),
                "valid_until": (decision_time + timedelta(days=1)).isoformat(),
            }
        ],
        "global_tool_capabilities": {"payment-api": ["read"]}   # allow "read"
    }

    authority_expired = {
        "delegations": [
            {
                "id": "delegation_123",
                "grantor": "admin",
                "grantee": "agent",
                "permissions": ["refund"],
                "valid_from": (decision_time - timedelta(days=2)).isoformat(),
                "valid_until": (decision_time - timedelta(days=1)).isoformat(),
            }
        ],
        "global_tool_capabilities": {"payment-api": ["read"]}
    }

    # Test evaluate_decision directly
    ctx = {"risk_score": 25, "evidence_age_hours": 0.5}
    state_valid = engine.evaluate_decision(decision, policy, authority_valid, ctx)
    assert state_valid.is_admissible is True

    state_expired = engine.evaluate_decision(decision, policy, authority_expired, ctx)
    assert state_expired.is_admissible is False
    assert state_expired.reason == "Authority chain invalid or expired"
