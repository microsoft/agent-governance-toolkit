# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""
Lab 1 — Your First Policy
=========================
Introduction to AI Agent Governance Workshop

Goal: Write a declarative YAML governance policy and evaluate it against
simulated agent tool calls.

Instructions:
1. Read through this file completely before making changes.
2. Fill in each section marked with TODO.
3. Run the script:   python lab1_first_policy.py
4. Compare your output to the expected output in lab-guide.md.

Prerequisites:
    pip install agent-os-kernel
"""

from agent_os.policies import PolicyEvaluator

# ---------------------------------------------------------------------------
# TODO (Step 2): Replace the empty string below with a YAML policy that
# blocks `execute_code` tool calls.
#
# Hint — every policy file needs:
#   version, name, description, rules (list of rule objects), defaults
#
# Each rule needs:
#   name, condition (field + operator + value), action, priority, message
# ---------------------------------------------------------------------------
POLICY_YAML = """
version: "1.0"
name: lab1-policy
description: Workshop Lab 1 — starter policy

rules: []   # <-- replace this with your rules

defaults:
  action: allow
"""

# ---------------------------------------------------------------------------
# Scenarios: each entry is (tool_name, token_count, expected_decision)
# "allow" means the call should proceed; "deny" means it should be blocked.
# ---------------------------------------------------------------------------
SCENARIOS = [
    ("read_customer_data", 100, "allow"),
    ("execute_code", 50, "deny"),
    ("write_database", 200, "deny"),
    ("read_reports", 3000, "deny"),   # Step 4: blocked by token-budget rule
    ("read_inventory", 150, "allow"),
]


def run_lab() -> None:
    """Evaluate each scenario and print a pass/fail summary."""
    evaluator = PolicyEvaluator()

    # TODO (Step 2): Load your policy from the POLICY_YAML string above.
    # Hint: PolicyEvaluator has a load_policy_yaml() method.
    # evaluator.load_policy_yaml(POLICY_YAML)

    print("=" * 60)
    print("Lab 1 — Policy Evaluation Results")
    print("=" * 60)

    all_passed = True
    for tool_name, token_count, expected in SCENARIOS:
        context = {"tool_name": tool_name, "token_count": token_count}

        # TODO (Step 2): Evaluate the context against your policy.
        # Hint: evaluator.evaluate(context) returns a Decision object
        # with .allowed (bool) and .reason (str).
        decision_allowed = True   # replace with: evaluator.evaluate(context).allowed
        decision_reason = "(not evaluated yet)"  # replace with: decision.reason

        actual = "allow" if decision_allowed else "deny"
        match = actual == expected
        all_passed = all_passed and match

        status = "✅ PASS" if match else "❌ FAIL"
        action_str = "allow" if decision_allowed else "deny"
        print(
            f"{status}  [{action_str:<5}]  {tool_name:<25}  tokens={token_count:<5}"
            f"  (expected={expected})"
        )
        if not decision_allowed:
            print(f"         reason: {decision_reason}")

    print()
    print("All scenarios matched expected output." if all_passed else
          "Some scenarios did not match — re-read the policy rules.")

    # ---------------------------------------------------------------------------
    # TODO (Stretch goal): assert that each scenario matches its expected output
    # ---------------------------------------------------------------------------
    # for tool_name, token_count, expected in SCENARIOS:
    #     context = {"tool_name": tool_name, "token_count": token_count}
    #     decision = evaluator.evaluate(context)
    #     actual = "allow" if decision.allowed else "deny"
    #     assert actual == expected, f"{tool_name}: expected {expected}, got {actual}"
    # print("All assertions passed.")


if __name__ == "__main__":
    run_lab()
