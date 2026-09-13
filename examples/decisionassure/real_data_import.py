"""Example explicit adapter: map an organization's audit record into the versioned schema."""
from decisionassure_impact.models import Trace

def map_audit_record(record: dict) -> Trace:
    """Callers must validate their source fields before mapping; never guess missing values."""
    return Trace.model_validate({"trace_id": record["audit_id"], "timestamp": record["occurred_at"], "decisions": [{"decision_id": record["decision_id"], "action": {"action_id": record["action_id"], "name": record["action_name"], "tool": record["tool"], "parameters": record.get("parameters", {})}, "agent_id": record["agent_id"], "timestamp": record["occurred_at"], "policy_version": record["policy_version"], "authority_chain": record["delegations"], "context": record.get("context", {}), "evidence": record.get("evidence", [])}]})
