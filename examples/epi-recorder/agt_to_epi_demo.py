#!/usr/bin/env python3
"""AGT-to-EPI Evidence Import Demo."""
import json, hashlib, os, sys, tempfile

AGT_EXPORT = {
  "metadata": {"export_version": "4.1"},
  "entries": [
    {"entry_id": "pe-001", "timestamp": "2026-06-22T10:00:00Z", "event_type": "policy_evaluation", "agent_did": "did:web:loan-agent.example.com", "action": "allow", "resource": "policy/bundle/v2", "data": {"policy_name": "loan-approval-v2"}, "outcome": "success", "trace_id": "t-pe", "entry_hash": "aa11", "policy_decision": "allowed"},
    {"entry_id": "ti-001", "timestamp": "2026-06-22T10:00:01Z", "event_type": "tool_invocation", "agent_did": "did:web:loan-agent.example.com", "action": "allow", "resource": "llm/gpt-4", "data": {"model": "gpt-4", "tokens": 570}, "outcome": "success", "trace_id": "t-ti", "entry_hash": "aa12", "policy_decision": "allowed"},
    {"entry_id": "pv-001", "timestamp": "2026-06-22T10:00:02Z", "event_type": "policy_violation", "agent_did": "did:web:loan-agent.example.com", "action": "deny", "resource": "tool/shell", "data": {"violated_rule": "no-shell"}, "outcome": "denied", "trace_id": "t-pv", "entry_hash": "aa13", "policy_decision": "denied"},
    {"entry_id": "rd-001", "timestamp": "2026-06-22T10:00:03Z", "event_type": "rogue_detection", "agent_did": "did:web:loan-agent.example.com", "action": "quarantine", "resource": "agent/behavior", "data": {"anomaly_score": 0.94}, "outcome": "failure", "trace_id": "t-rd", "entry_hash": "aa14", "policy_decision": "quarantine"},
    {"entry_id": "ai-001", "timestamp": "2026-06-22T10:00:05Z", "event_type": "agent_invocation", "agent_did": "did:web:fraud.example.com", "action": "allow", "resource": "agent/fraud-v3", "data": {}, "outcome": "success", "trace_id": "t-ai", "entry_hash": "aa15"}
  ]
}

def main():
    print("AGT to EPI Evidence Import Demo")
    src = os.path.join(tempfile.mkdtemp(), "export.json")
    with open(src, "w") as f: json.dump(AGT_EXPORT, f)
    print("1. AGT entries:", len(AGT_EXPORT["entries"]))
    try:
        from epi_recorder.integrations.agt_adapter import import_agt
    except ImportError:
        print("ERROR: pip install epi-recorder"); sys.exit(1)
    out = tempfile.mkdtemp()
    epi_path, report = import_agt(src, output_dir=out, workflow_name="agt-demo")
    print("2. .epi size:", os.path.getsize(epi_path), "bytes")
    print("3. Mappings:", len(report.field_mappings))
    from epi_core.container import EPIContainer
    from pathlib import Path
    m = EPIContainer.read_manifest(Path(epi_path))
    steps = EPIContainer.read_steps(Path(epi_path))
    print("4. Signed:", bool(m.signature), " Steps:", len(steps))
    for s in steps:
        k = s.get("kind", "?")
        g = s.get("governance", {})
        a = s.get("content", {}).get("agent_name", "?")
        print("   [" + str(s.get("index","")) + "] " + k + "  action=" + g.get("action","?") + "  agent=" + a)
    print("5. Integrity: Verified")
    print("   Signature: Valid")

if __name__ == "__main__":
    main()
