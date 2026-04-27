"""Demo data generator for the governance dashboard."""
import random
import uuid
from datetime import datetime, timedelta, timezone

def _ts(days_ago=0, hours_ago=0):
    return datetime.now(timezone.utc) - timedelta(days=days_ago, hours=hours_ago)

AGENT_TYPES = ["langchain", "crewai", "autogen", "openai-agents", "semantic-kernel",
    "mcp-server", "llamaindex", "pydantic-ai", "google-adk", "agt"]

NAMES = ["Code Review Bot", "PR Summarizer", "Security Scanner", "Support Triage",
    "Data Pipeline Agent", "Incident Response", "Doc Generator", "Test Generator",
    "Dep Updater", "Cost Optimizer", "Translation Agent", "Meeting Notes Bot",
    "Migration Agent", "API Monitor", "Compliance Checker", "Onboarding Agent",
    "Forecast Agent", "Inventory Manager", "Log Analyzer", "Perf Profiler",
    "Vuln Scanner", "Release Manager", "Feature Flag Agent", "A/B Analyzer", "Chaos Agent"]

OWNERS = ["alice@company.com", "bob@company.com", "charlie@company.com",
    "platform-team@company.com", "security-team@company.com", "ml-ops@company.com", ""]

STATES = ["active"]*5 + ["provisioned", "suspended", "orphaned", "decommissioned", "pending_approval"]
ACTIONS = ["web_search", "read_file", "write_file", "execute_code", "send_email",
    "delete_file", "api_call", "database_query", "deploy", "ssh_connect"]
DECISIONS = ["allow"]*4 + ["deny"]*2 + ["escalate"]

def generate_fleet(count=25):
    agents = []
    for i in range(count):
        has_id = random.random() > 0.3
        owner = random.choice(OWNERS)
        state = random.choice(STATES)
        atype = random.choice(AGENT_TYPES)
        risk = 0.0
        if not has_id: risk += 30
        if not owner: risk += 20
        if state in ("orphaned", "suspended"): risk += 20
        if atype in ("autogen", "crewai", "langchain"): risk += 15
        risk = min(100, max(0, risk + random.uniform(-5, 10)))
        level = "critical" if risk >= 75 else "high" if risk >= 50 else "medium" if risk >= 25 else "low" if risk >= 10 else "info"
        agents.append({
            "id": f"agent:{uuid.uuid4().hex[:8]}", "name": NAMES[i % len(NAMES)],
            "type": atype, "state": state, "owner": owner or "unassigned",
            "has_identity": has_id, "did": f"did:agent:{uuid.uuid4().hex[:12]}" if has_id else None,
            "trust_score": random.randint(300, 1000) if has_id else 0,
            "confidence": round(random.uniform(0.5, 1.0), 2),
            "risk_score": round(risk, 1), "risk_level": level,
            "created_at": _ts(days_ago=random.uniform(1, 180)).isoformat(),
            "last_heartbeat": _ts(hours_ago=random.uniform(0, 72)).isoformat() if state == "active" else None,
            "credential_expires": _ts(hours_ago=-random.uniform(1, 24)).isoformat() if state == "active" and has_id else None,
            "heartbeat_count": random.randint(0, 10000) if state == "active" else 0,
            "evidence_count": random.randint(1, 5),
        })
    return agents

def generate_policy_events(count=200):
    events = []
    for _ in range(count):
        action = random.choice(ACTIONS)
        decision = random.choice(["deny", "deny", "escalate", "allow"]) if action in ("delete_file", "ssh_connect", "deploy") else random.choice(DECISIONS)
        events.append({"timestamp": _ts(hours_ago=random.uniform(0, 168)).isoformat(),
            "agent_id": f"agent:{uuid.uuid4().hex[:8]}", "action": action, "decision": decision,
            "latency_ms": round(random.uniform(0.01, 0.5), 3), "policy_rule": f"rule:{random.randint(1, 50):03d}"})
    return sorted(events, key=lambda e: e["timestamp"], reverse=True)

def generate_trust_matrix(agents):
    identified = [a for a in agents if a["has_identity"]][:10]
    return [{"from_agent": a["name"], "to_agent": b["name"], "trust_score": random.randint(200, 1000)}
        for i, a in enumerate(identified) for j, b in enumerate(identified) if i != j]

def generate_lifecycle_events(agents, count=100):
    types = ["requested", "approved", "activated", "credential_rotated", "heartbeat",
        "suspended", "resumed", "orphan_detected", "decommissioned", "owner_changed"]
    events = [{"timestamp": _ts(hours_ago=random.uniform(0, 720)).isoformat(),
        "agent_id": random.choice(agents)["id"], "agent_name": random.choice(agents)["name"],
        "event_type": random.choice(types), "actor": random.choice(OWNERS) or "system"} for _ in range(count)]
    return sorted(events, key=lambda e: e["timestamp"], reverse=True)
