from decisionassure_impact.models import Action, Decision, Policy
from decisionassure_impact.policy import evaluate_policy
from datetime import datetime, timezone

def test_policy_dsl_is_deterministic():
    policy = Policy.model_validate({"version":"1", "rules":[{"id":"limit", "when":{"all":[{"field":"action.parameters.amount","operator":"lte","value":10}]},"effect":"ADMISSIBLE"}]})
    decision = Decision(decision_id="d", action=Action(action_id="a",name="refund",tool="x",parameters={"amount":10}), agent_id="agent", timestamp=datetime.now(timezone.utc))
    assert evaluate_policy(policy, decision, {})[0] == "ADMISSIBLE"

def test_malicious_expression_is_data_not_code():
    policy = Policy.model_validate({"version":"1", "rules":[{"id":"bad", "when":{"field":"__import__('os').system('nope')","operator":"exists"},"effect":"ADMISSIBLE"}]})
    decision = Decision(decision_id="d", action=Action(action_id="a",name="refund",tool="x"), agent_id="agent", timestamp=datetime.now(timezone.utc))
    assert evaluate_policy(policy, decision, {})[0] == "INADMISSIBLE"
