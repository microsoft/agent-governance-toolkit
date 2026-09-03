from datetime import datetime, timedelta, timezone
from decisionassure_impact.engine import CounterfactualReplayer
from decisionassure_impact.models import Action, Authority, Decision, Delegation, Evidence, EvidenceRequirements, GovernanceSnapshot, Policy

def _decision(evidence=None): return Decision(decision_id="d", action=Action(action_id="a", name="refund", tool="p"), agent_id="agent", timestamp=datetime(2026, 2, 1, tzinfo=timezone.utc), authority_chain=["del"], evidence=evidence or [])
def _snapshot(until="2026-12-31T00:00:00Z", requirements=None):
    return GovernanceSnapshot(policy=Policy(version="v", default_effect="ADMISSIBLE"), authority=Authority(delegations=[Delegation(id="del", grantor="admin", grantee="agent", permissions=["refund"], valid_from="2026-01-01T00:00:00Z", valid_until=until)]), evidence_requirements=requirements or EvidenceRequirements())
def test_authority_is_checked_at_historical_timestamp(): assert CounterfactualReplayer().evaluate(_decision(), _snapshot(), {}).state == "ADMISSIBLE"
def test_stale_evidence_is_inadmissible():
    evidence = Evidence(evidence_id="e", source="s", fetched_at=datetime(2026, 1, 31, tzinfo=timezone.utc))
    assert CounterfactualReplayer().evaluate(_decision([evidence]), _snapshot(requirements=EvidenceRequirements(max_age_hours=1)), {}).reason_codes[0] == "EVIDENCE_STALE"
