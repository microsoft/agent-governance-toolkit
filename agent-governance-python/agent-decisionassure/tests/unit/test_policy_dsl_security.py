# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

import pytest
from agent_decisionassure.policy import PolicyError, evaluate_condition, build_env
import uuid
from datetime import datetime, timezone
from agent_decisionassure.models import Action, DecisionTrace


def _decision():
    return DecisionTrace(
        action=Action(id=uuid.uuid4(), name="refund", parameters={"amount": 100},
                      tool="payment-api", version="v3", transaction_amount=100),
        agent_id=uuid.uuid4(), agent_version="1.0",
        timestamp=datetime.now(timezone.utc),
        policy_version="v4", authority_chain=[], context={"risk_score": 10},
        evidence_used=[], evidence_age_hours=0.1,
        tool_permissions_at_time=["read"], model_version="approved_v1", result="ALLOW",
    )


def test_dsl_rejects_unknown_operator():
    with pytest.raises(PolicyError):
        evaluate_condition({"__import__": ["os"]}, build_env(_decision()))


def test_dsl_rejects_attribute_chain():
    # Attempt to walk dunders via field path — must not resolve
    cond = {"eq": [{"field": "action.__class__.__mro__"}, 0]}
    result = evaluate_condition(cond, build_env(_decision()))
    assert result is False  # None != 0, so no escalation


def test_dsl_rejects_call():
    with pytest.raises(PolicyError):
        evaluate_condition({"call": ["os.system", "echo hi"]}, build_env(_decision()))


def test_dsl_never_evals_strings():
    # A malicious string literal is just a string, never executed
    cond = {"eq": [{"field": "action.name"}, "__import__('os').system('id')"]}
    assert evaluate_condition(cond, build_env(_decision())) is False


def test_dsl_allows_legit_conditions():
    cond = {"all": [
        {"eq": [{"field": "action.name"}, "refund"]},
        {"lte": [{"field": "action.parameters.amount"}, 50000]},
    ]}
    assert evaluate_condition(cond, build_env(_decision())) is True
