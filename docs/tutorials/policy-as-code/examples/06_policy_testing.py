# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""
Chapter 6: Policy Testing — Automated Validation and Test Scenarios

Shows how to validate policy structure, run declarative test scenarios,
build a role-by-tool test matrix, and catch regressions automatically.

Run from the repo root:
    pip install agent-os-kernel[full]
    python docs/tutorials/policy-as-code/examples/06_policy_testing.py
"""

from __future__ import annotations

import copy
import sys
from pathlib import Path

import yaml

# Allow running from the repo root without installing the packages.
_REPO_ROOT = Path(__file__).resolve().parent.parent.parent.parent.parent
sys.path.insert(0, str(_REPO_ROOT / "packages" / "agent-os" / "src"))

from pydantic import ValidationError

from agent_os.policies import PolicyEvaluator
from agent_os.policies.schema import PolicyDocument

EXAMPLES_DIR = Path(__file__).parent

ESCALATION_KEYWORD = "requires human approval"


def classify(decision):
    """Classify a PolicyDecision into allow / escalate / deny."""
    if decision.allowed:
        return ("allow", "\u2705 allow   ")
    if decision.reason and ESCALATION_KEYWORD in decision.reason.lower():
        return ("escalate", "\u23f3 escalate")
    return ("deny", "\U0001f6ab deny    ")


# ── Part 1: Validate the structure ────────────────────────────────────

print("=" * 60)
print("  Chapter 6: Policy Testing")
print("=" * 60)

print("\n--- Part 1: Validate the structure ---\n")

# 1a — Load a valid policy
policy = PolicyDocument.from_yaml(EXAMPLES_DIR / "06_test_policy.yaml")
print(f"  \u2705 '{policy.name}' loaded successfully")
print(f"     {len(policy.rules)} rules, default action: {policy.defaults.action.value}")

# 1b — Try to validate a broken policy
print()
broken_data = {
    "version": "1.0",
    "name": "broken-policy",
    "rules": [
        {
            "name": "bad-rule",
            "condition": {
                "field": "tool_name",
                "operator": "equals",  # wrong — should be "eq"
                "value": "send_email",
            },
            "action": "deny",
        }
    ],
}

try:
    PolicyDocument.model_validate(broken_data)
    print("  Unexpected: broken policy passed validation")
except ValidationError as exc:
    # Show only the first error for readability
    first_error = exc.errors()[0]
    print(f"  \U0001f6ab Validation failed (as expected):")
    print(f"     Field:   {' -> '.join(str(p) for p in first_error['loc'])}")
    print(f"     Problem: {first_error['msg']}")

print()
print("  PolicyDocument.from_yaml() catches structural errors")
print("  before any rule is evaluated. A typo like 'equals'")
print("  instead of 'eq' is caught immediately.")

# ── Part 2: Run test scenarios ────────────────────────────────────────

print("\n--- Part 2: Run test scenarios ---\n")

# Load the scenarios file
scenarios_path = EXAMPLES_DIR / "06_test_scenarios.yaml"
with open(scenarios_path) as f:
    scenarios_data = yaml.safe_load(f)

scenarios = scenarios_data["scenarios"]
evaluator = PolicyEvaluator(policies=[policy])

passed = 0
failed = 0

print(f"  {'Scenario':<32s} {'Expected':<10s} {'Actual':<10s} Result")
print(f"  {'-' * 68}")

for scenario in scenarios:
    name = scenario["name"]
    context = scenario.get("context", {})
    expected_action = scenario.get("expected_action")
    expected_allowed = scenario.get("expected_allowed")

    decision = evaluator.evaluate(context)
    actual_action = decision.action
    actual_allowed = decision.allowed

    ok = True
    if expected_action is not None and actual_action != expected_action:
        ok = False
    if expected_allowed is not None and actual_allowed != expected_allowed:
        ok = False

    # For display, show whichever field the scenario tested
    expected_display = expected_action if expected_action is not None else str(expected_allowed).lower()
    actual_display = actual_action if expected_action is not None else str(actual_allowed).lower()

    status = "\u2705 pass" if ok else "\u274c FAIL"
    print(f"  {name:<32s} {expected_display:<10s} {actual_display:<10s} {status}")

    if ok:
        passed += 1
    else:
        failed += 1

total = passed + failed
print()
if failed == 0:
    print(f"  \u2705 {passed}/{total} scenarios passed")
else:
    print(f"  \u274c {passed}/{total} scenarios passed, {failed} failed")

print()
print("  Each scenario is one line in a YAML file. The test runner")
print("  evaluates the policy and compares the actual result to the")
print("  expected result. No manual checking required.")

# ── Part 3: The test matrix ──────────────────────────────────────────

print("\n--- Part 3: The test matrix ---\n")

print("  Loading policies from chapters 2 and 4...")

# Role policies from Chapter 2
reader_policy = PolicyDocument.from_yaml(EXAMPLES_DIR / "02_reader_policy.yaml")
admin_policy = PolicyDocument.from_yaml(EXAMPLES_DIR / "02_admin_policy.yaml")

# Environment policy from Chapter 4
env_policy = PolicyDocument.from_yaml(EXAMPLES_DIR / "04_env_policy.yaml")

# Combine: each role gets its own policy + the shared environment policy.
# The evaluator merges all rules and sorts by priority — the first
# matching rule wins.  This is where surprising interactions happen.
role_policies = {
    "reader": [reader_policy, env_policy],
    "admin":  [admin_policy, env_policy],
}

environments = ["development", "production"]
tools = [
    "search_documents",
    "write_file",
    "send_email",
    "delete_database",
    "transfer_funds",
]

# What the team intends — the "answer key":
#   Reader:   cannot write_file, send_email, delete_database (from ch2)
#   Admin:    cannot delete_database (from ch2)
#   Production: everything blocked (from ch4)
#   Development: role-based rules apply
intended = {
    ("reader", "development", "search_documents"): True,
    ("reader", "development", "write_file"):       False,  # ch2 blocks it
    ("reader", "development", "send_email"):       False,
    ("reader", "development", "delete_database"):  False,
    ("reader", "development", "transfer_funds"):   True,
    ("reader", "production",  "search_documents"): False,
    ("reader", "production",  "write_file"):       False,
    ("reader", "production",  "send_email"):       False,
    ("reader", "production",  "delete_database"):  False,
    ("reader", "production",  "transfer_funds"):   False,
    ("admin",  "development", "search_documents"): True,
    ("admin",  "development", "write_file"):       True,
    ("admin",  "development", "send_email"):       True,
    ("admin",  "development", "delete_database"):  False,
    ("admin",  "development", "transfer_funds"):   True,
    ("admin",  "production",  "search_documents"): False,
    ("admin",  "production",  "write_file"):       False,
    ("admin",  "production",  "send_email"):       False,
    ("admin",  "production",  "delete_database"):  False,
    ("admin",  "production",  "transfer_funds"):   False,
}

# Print the matrix header
print()
print(f"  {'Tool':<22s}", end="")
for role in role_policies:
    for env in environments:
        short_env = "dev" if env == "development" else "prod"
        label = f"{role}/{short_env}"
        print(f" {label:<13s}", end="")
print()
print(f"  {'-' * 74}")

matrix_pass = 0
matrix_total = 0
surprises = []

for tool in tools:
    print(f"  {tool:<22s}", end="")
    for role, policies in role_policies.items():
        for env in environments:
            evaluator = PolicyEvaluator(policies=list(policies))
            decision = evaluator.evaluate({"tool_name": tool, "environment": env})
            icon = "\u2705 allow " if decision.allowed else "\U0001f6ab deny  "

            exp = intended.get((role, env, tool))
            matrix_total += 1
            if exp is not None and decision.allowed == exp:
                matrix_pass += 1
                print(f" {icon}     ", end="")
            else:
                surprises.append((role, env, tool, exp, decision))
                print(f" {icon} \u26a0\ufe0f ", end="")
    print()

print()
if surprises:
    print(f"  {matrix_pass}/{matrix_total} cells match expectations.  "
          f"{len(surprises)} surprise(s):\n")
    for role, env, tool, exp, decision in surprises:
        exp_label = "deny" if not exp else "allow"
        act_label = "allow" if decision.allowed else "deny"
        print(f"  \u26a0\ufe0f  {role} + {env} + {tool}")
        print(f"     Expected: {exp_label}")
        print(f"     Actual:   {act_label} (from rule: {decision.matched_rule or 'default'})")
        print(f"     Reason:   {decision.reason}")
        print()
    print("  The reader policy blocks write_file at priority 80.")
    print("  But the environment policy allows development at priority 90.")
    print("  Priority 90 beats 80 \u2014 the environment rule fires first.")
    print("  Without the test matrix, this interaction is invisible.")
else:
    print(f"  \u2705 {matrix_pass}/{matrix_total} cells match expectations")

# ── Part 4: Catch a regression ────────────────────────────────────────

print("\n--- Part 4: Catch a regression ---\n")

print("  Scenario: someone edits the policy and removes the phrase")
print('  "requires human approval" from the transfer_funds rule.')
print("  The tool silently flips from escalate to hard deny.")
print()

# Deep-copy the policy and modify the message
modified_policy = copy.deepcopy(policy)
for rule in modified_policy.rules:
    if rule.name == "escalate-transfer-funds":
        rule.message = "Sensitive action: transfer_funds is blocked"
        break

# Evaluate transfer_funds with the original and modified policies
original_eval = PolicyEvaluator(policies=[policy])
modified_eval = PolicyEvaluator(policies=[modified_policy])

orig_decision = original_eval.evaluate({"tool_name": "transfer_funds"})
mod_decision = modified_eval.evaluate({"tool_name": "transfer_funds"})

orig_tier, orig_icon = classify(orig_decision)
mod_tier, mod_icon = classify(mod_decision)

print(f"  Original policy:  transfer_funds \u2192 {orig_icon} ({orig_tier})")
print(f"  Modified policy:  transfer_funds \u2192 {mod_icon} ({mod_tier})")
print()

if orig_tier != mod_tier:
    print(f"  \u274c Regression detected!")
    print(f"     transfer_funds changed from '{orig_tier}' to '{mod_tier}'.")
    print(f"     The edit removed the escalation keyword, so the action")
    print(f"     that used to pause for human review now silently blocks.")
else:
    print("  No regression (tiers match).")

print()
print("  A human scanning the YAML diff might miss this. But a test")
print("  scenario that checks for the escalation keyword catches it")
print("  instantly. That is the value of automated policy testing:")
print("  changes that look harmless cannot silently break behavior.")

print("\n" + "=" * 60)
print("  Policies are code. Test them like code.")
print("  Validate the structure, write expected outcomes,")
print("  run them automatically, and catch regressions")
print("  before they reach production.")
print("=" * 60)
