# Capability Witness Standard – Specification v1.0

## Governance Learning Loop

Unknown witnesses (classification = "unknown") can be:

1. Reviewed by a human analyst.
2. Labeled with a meaningful name.
3. Added to the learner's store.
4. Eventually exported to the ontology.
5. Future traces with the same action set will then be auto-classified.

This turns the Capability Witness Engine into a self-improving governance system.
## Purpose

Define a portable, machine‑readable format for capability witnesses that can be consumed by AgentTrust, TRACE, and other governance systems.

## Schema

```json
{
  "schema_version": "1.0",
  "witness_type": "capability_witness",
  "timestamp": "2026-06-18T12:00:00Z",
  "framework": "autogen",
  "capability": {
    "name": "Credential Exfiltration",
    "id": "credential_exfiltration",
    "severity": "critical",
    "confidence": 0.94
  },
  "required_actions": [
    {"agent": "alice", "action": "read_database"},
    {"agent": "bob", "action": "read_credentials"},
    {"agent": "charlie", "action": "export_data"}
  ],
  "minimal_witness": true,
  "counterfactual_verified": true,
  "counterfactual_details": [...],
  "governance_recommendation": "DENY",
  "governance_reason": "Emergent critical capability without prior authorisation",
  "witness_hash": "a1b2c3d4...",
  "trace_claim": {
    "format": "TRACE v0.1",
    "claim_type": "capability_witness",
    "hash": "a1b2c3d4...",
    "evidence": [...],
    "recommendation": "DENY"
  },
  "is_false_witness": false,
  "false_witness_reason": null
}

Governance Recommendations

Recommendation	Meaning
DENY	Capability is critical and not authorised – block execution
HUMAN_REVIEW	High-severity capability – requires human oversight
MONITOR	Unknown capability – observe and log
ADMIT	Known capability – matches training ontology
REJECT	False witness claim – insufficient evidence
Integration with AgentTrust / TRACE

The trace_claim field is directly compatible with TRACE v0.1 claims, making capability witnesses portable governance evidence.


---

## ✅ Final Output (After Running)

```bash
python examples/batch_witness_demo.py sample_traces_large/ autogen 2 0.5 0.5

================================================================================
🧾 Capability Witness Engine – Batch Report
================================================================================
   Timestamp:                 2026-06-18T18:00:00
   Total traces processed:    150
   Total witnesses generated: 4
   Parse errors:              0
   Agents involved:           alice, bob, charlie, ...
   Frameworks:                autogen: 150
   Confidence threshold:      50.00%

   Recommendations:
      HUMAN_REVIEW: 3
      MONITOR: 1

   Severities:
      critical: 3
      unknown: 1

   Human reviews triggered:   3
   Valid witnesses:           3
   Low Confidence Witness:      1
   Average confidence:        74.59%

   ⚠️ False Witness Analysis:
      Witness: Unknown Capability (2 actions)
      Confidence: 15.00%
      Reason: Confidence 15.00% below threshold 50.00%
      Actions: heidi->read_model, ivan->export_model
      Hash: fb03bed676674bb4...

   Valid Witnesses:
      #1: Credential Exfiltration (conf: 91.67%, rec: HUMAN_REVIEW)
           Actions: alice->read_credentials, charlie->export_data
           Hash: bb57369c232d1ad7...
           Counterfactual: ✅
      #2: Privilege Escalation (conf: 100.00%, rec: HUMAN_REVIEW)
           Actions: eve->grant_permission, frank->write_config, grace->delete_logs
           Hash: 8414d88c8b0ed03d...
           Counterfactual: ✅
      #3: Credential Exfiltration (conf: 91.67%, rec: HUMAN_REVIEW)
           Actions: bob->read_database, dave->export_data
           Hash: 3220856102e446c8...
           Counterfactual: ✅
================================================================================