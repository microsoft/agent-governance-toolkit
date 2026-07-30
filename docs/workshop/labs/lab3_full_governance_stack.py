# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""
Lab 3 — Full Governance Stack
==============================
Introduction to AI Agent Governance Workshop

Goal: Combine policy enforcement, cryptographic agent identity, and tamper-proof
audit logging into a single pipeline that processes agent tool calls end-to-end.

Instructions:
1. Read through this file completely before making changes.
2. Fill in each section marked with TODO.
3. Run the script:   python lab3_full_governance_stack.py
4. Compare your output to the expected output in lab-guide.md.

Prerequisites:
    pip install agent-os-kernel agentmesh-platform
"""

from agent_os.policies import PolicyEvaluator
from agentmesh import AgentIdentity, RiskScorer
from agentmesh.governance.audit import AuditLog

# ---------------------------------------------------------------------------
# Policy that governs what the production agent may do.
# ---------------------------------------------------------------------------
POLICY_YAML = """
version: "1.0"
name: lab3-production-policy
description: Workshop Lab 3 — production governance policy

rules:
  - name: block-code-execution
    condition:
      field: tool_name
      operator: eq
      value: execute_code
    action: deny
    priority: 110
    message: "Code execution is not permitted for this agent"

  - name: block-destructive-operations
    condition:
      field: tool_name
      operator: in
      value: [delete_all_records, drop_table, wipe_storage]
    action: deny
    priority: 110
    message: "Destructive operations are blocked"

  - name: token-budget
    condition:
      field: token_count
      operator: gt
      value: 2000
    action: deny
    priority: 100
    message: "Token budget exceeded (max 2000)"

  - name: audit-large-reads
    condition:
      field: token_count
      operator: gt
      value: 500
    action: audit
    priority: 90
    message: "Large read — logged for review"

defaults:
  action: allow
  max_tokens: 2000
  max_tool_calls: 20
"""

# ---------------------------------------------------------------------------
# Scenarios to run through the governance pipeline.
# Each entry: (tool_name, token_count, expected_allowed: bool)
# ---------------------------------------------------------------------------
SCENARIOS = [
    ("read_customer_data", 200, True),
    ("execute_code", 50, False),
    ("read_reports", 800, True),    # allowed but audited (>500 tokens)
    ("delete_all_records", 10, False),
    ("read_inventory", 300, True),
]


# ---------------------------------------------------------------------------
# Step 1 — Build the governance pipeline
# ---------------------------------------------------------------------------

def create_governance_pipeline() -> tuple:
    """
    TODO: Create and return (evaluator, agent, scorer, audit_log).

    - evaluator: PolicyEvaluator loaded with POLICY_YAML
    - agent: AgentIdentity named "ProductionAgent", sponsored by
             "ops-team@example.com", capabilities ["read:data", "read:reports"]
    - scorer: RiskScorer()
    - audit:  AuditLog()
    """
    # TODO: uncomment and complete the lines below
    # evaluator = PolicyEvaluator()
    # evaluator.load_policy_yaml(POLICY_YAML)

    # agent = AgentIdentity.create(
    #     name="ProductionAgent",
    #     sponsor="ops-team@example.com",
    #     capabilities=["read:data", "read:reports"],
    #     organization="Acme",
    # )

    # scorer = RiskScorer()
    # audit = AuditLog()

    # return evaluator, agent, scorer, audit

    # Remove these stubs once you've completed the TODO above:
    return None, None, None, None


# ---------------------------------------------------------------------------
# Step 2 — Process a single tool call through the pipeline
# ---------------------------------------------------------------------------

def process_tool_call(
    tool_name: str,
    token_count: int,
    evaluator: PolicyEvaluator,
    agent: AgentIdentity,
    scorer: RiskScorer,
    audit: AuditLog,
) -> tuple:
    """
    TODO: Implement the three-layer governance pipeline:

    Layer 1 — Policy check:
        Evaluate {"tool_name": tool_name, "token_count": token_count}.
        If denied → log a "policy_violation" audit entry and return (False, reason).

    Layer 2 — Trust check:
        Get the agent's trust score.
        If score < 400 → return (False, "Trust score too low: <score>").

    Layer 3 — Execute and log:
        Log a "tool_invocation" audit entry with outcome "success".
        Record a "policy_compliant_action" event on the scorer.
        Return (True, "OK").

    Return (allowed: bool, message: str).
    """
    # TODO: implement the three layers described above.
    return False, "not implemented yet"


# ---------------------------------------------------------------------------
# Step 3 — Inspect the audit trail
# ---------------------------------------------------------------------------

def print_audit_trail(audit: AuditLog) -> None:
    """Print a formatted summary of all audit entries."""
    print("\nAudit Trail:")
    print("-" * 70)
    for entry in audit.entries:
        ts = str(entry.timestamp)[:19]
        print(
            f"  {ts}  {entry.event_type:<22} {entry.resource:<25} {entry.outcome}"
        )


# ---------------------------------------------------------------------------
# Step 4 — Simulate tampering and verify detection
# ---------------------------------------------------------------------------

def simulate_tampering(audit: AuditLog) -> None:
    """
    TODO: Mutate one audit entry to simulate log tampering, then call
    audit.verify_integrity() and print whether the tamper was detected.
    """
    if not audit.entries:
        print("[WARN]  No audit entries to tamper with.")
        return

    print("\n--- Simulating log tampering ---")
    # TODO: Mutate audit.entries[0].outcome to a different value, then verify.
    # Example:
    # audit.entries[0].outcome = "success"   # tamper: change "blocked" → "success"
    # valid, error = audit.verify_integrity()
    # print(f"Audit intact after tampering: {valid}")
    # if error:
    #     print(f"  Detection message: {error}")


# ---------------------------------------------------------------------------
# Main flow
# ---------------------------------------------------------------------------

def run_lab() -> None:
    print("=" * 60)
    print("Lab 3 — Full Governance Stack")
    print("=" * 60)

    evaluator, agent, scorer, audit = create_governance_pipeline()
    if evaluator is None:
        print("[ERROR] create_governance_pipeline() returned None — complete Step 1.")
        return

    print(f"[INFO]  Agent DID: {agent.did}")
    print()

    # --- Run scenarios through the pipeline ---
    print("--- Processing tool calls ---")
    results: list[tuple] = []
    for tool_name, token_count, expected_allowed in SCENARIOS:
        ok, msg = process_tool_call(tool_name, token_count, evaluator, agent, scorer, audit)
        icon = "✅" if ok else "❌"
        print(f"{icon}  {tool_name:<25} {msg}")
        results.append((tool_name, ok, expected_allowed))

    # --- Verify all results match expected outcomes ---
    print()
    all_correct = all(ok == expected for _, ok, expected in results)
    if all_correct:
        print("All decisions matched expected outcomes. ✅")
    else:
        print("Some decisions did not match expected — review your policy rules.")

    # --- Verify audit integrity ---
    valid, error = audit.verify_integrity()
    print(f"\nAudit chain intact: {valid}")
    if error:
        print(f"  Error: {error}")
    print(f"Entries recorded: {len(audit.entries)}")

    # --- Print audit trail ---
    print_audit_trail(audit)

    # --- Simulate tampering ---
    simulate_tampering(audit)

    print("\nLab 3 complete.")


if __name__ == "__main__":
    run_lab()
