import json
import uuid
import random
from datetime import datetime, timezone

def generate_trace(agent_id, num_decisions=5):
    trace_id = str(uuid.uuid4())
    decisions = []
    for _ in range(num_decisions):
        amount = random.randint(30000, 60000)
        risk_score = random.randint(20, 50)
        action = {
            "id": str(uuid.uuid4()),
            "name": "refund",
            "parameters": {"amount": amount},
            "tool": "payment-api",
            "version": "v3",
            "transaction_amount": amount
        }
        decision = {
            "action": action,
            "agent_id": agent_id,
            "agent_version": "1.2",
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "policy_version": "v4",
            "authority_chain": ["delegation_123"],
            "context": {
                "risk_score": risk_score,
                "evidence_age_hours": random.choice([0.5, 1.0, 2.0]),
                "model_version": "approved_v1"
            },
            "evidence_used": [str(uuid.uuid4())],
            "result": "ALLOW" if random.random() > 0.3 else "DENY",
            "tool_permissions_at_time": ["read"],
            "model_version": "approved_v1"
        }
        decisions.append(decision)
    return {
        "trace_id": trace_id,
        "decisions": decisions,
        "environment": {"model_version": "approved_v1"},
        "metadata": {}
    }

if __name__ == "__main__":
    traces = [generate_trace(str(uuid.uuid4()), random.randint(1, 5)) for _ in range(100)]
    with open("examples/decisionassure/sample_traces.jsonl", "w") as f:
        for trace in traces:
            f.write(json.dumps(trace) + "\n")
    print("Generated 100 traces.")
