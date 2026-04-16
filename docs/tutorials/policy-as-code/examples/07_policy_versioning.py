# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""
Chapter 7: Policy Versioning — Compare, Test, and Catch Regressions

Shows how to diff two policy versions, test both with the same contexts,
and detect regressions before deploying the new version.

Run from the repo root:
    pip install agent-os-kernel[full]
    python docs/tutorials/policy-as-code/examples/07_policy_versioning.py
"""

from __future__ import annotations

import sys
from pathlib import Path


# ── Windows UTF-8 console fix ──────────────────────────────────────────
if sys.platform == "win32":
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    sys.stderr.reconfigure(encoding="utf-8", errors="replace")

# Allow running from the repo root without installing the packages.
_REPO_ROOT = Path(__file__).resolve().parent.parent.parent.parent.parent
sys.path.insert(0, str(_REPO_ROOT / "packages" / "agent-os" / "src"))

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


def diff_rules(v1_doc, v2_doc):
    """Compare two PolicyDocuments rule-by-rule. Return a list of change strings."""
    diffs = []

    # Top-level fields
    if v1_doc.version != v2_doc.version:
        diffs.append(f"version: {v1_doc.version} \u2192 {v2_doc.version}")

    # Index rules by name
    v1_rules = {r.name: r for r in v1_doc.rules}
    v2_rules = {r.name: r for r in v2_doc.rules}

    for name in v2_rules:
        if name not in v1_rules:
            diffs.append(f"rule added: {name}")

    for name in v1_rules:
        if name not in v2_rules:
            diffs.append(f"rule removed: {name}")

    for name in v1_rules:
        if name not in v2_rules:
            continue
        r1 = v1_rules[name]
        r2 = v2_rules[name]
        if r1.priority != r2.priority:
            diffs.append(f"rule {name}: priority {r1.priority} \u2192 {r2.priority}")
        if r1.message != r2.message:
            diffs.append(f"rule {name}: message changed")
            diffs.append(f"  was: \"{r1.message}\"")
            diffs.append(f"  now: \"{r2.message}\"")
        if r1.action != r2.action:
            diffs.append(f"rule {name}: action {r1.action.value} \u2192 {r2.action.value}")

    # Defaults
    if v1_doc.defaults.action != v2_doc.defaults.action:
        diffs.append(f"defaults: action {v1_doc.defaults.action.value} \u2192 {v2_doc.defaults.action.value}")
    if v1_doc.defaults.max_tool_calls != v2_doc.defaults.max_tool_calls:
        diffs.append(f"defaults: max_tool_calls {v1_doc.defaults.max_tool_calls} \u2192 {v2_doc.defaults.max_tool_calls}")

    return diffs


# ── Part 1: Load both versions ────────────────────────────────────────

print("=" * 60)
print("  Chapter 7: Policy Versioning")
print("=" * 60)

print("\n--- Part 1: Load both versions ---\n")

v1 = PolicyDocument.from_yaml(EXAMPLES_DIR / "07_policy_v1.yaml")
v2 = PolicyDocument.from_yaml(EXAMPLES_DIR / "07_policy_v2.yaml")

print(f"  v1: '{v1.name}' version {v1.version}  ({len(v1.rules)} rules)")
print(f"  v2: '{v2.name}' version {v2.version}  ({len(v2.rules)} rules)")

# ── Part 2: Diff ──────────────────────────────────────────────────────

print("\n--- Part 2: Diff the two versions ---\n")

changes = diff_rules(v1, v2)

if not changes:
    print("  No differences found.")
else:
    for change in changes:
        print(f"  {change}")

print()
print("  The diff lists every structural change. But a diff cannot")
print("  tell you whether a change is safe. You need to test both")
print("  versions and compare the results.")

# ── Part 3: Test both versions ────────────────────────────────────────

print("\n--- Part 3: Test both versions ---\n")

eval_v1 = PolicyEvaluator(policies=[v1])
eval_v2 = PolicyEvaluator(policies=[v2])

tools = [
    "search_documents",
    "write_file",
    "send_email",
    "delete_database",
    "transfer_funds",
]

print(f"  {'Tool':<22s} {'v1':<14s} {'v2':<14s} Changed?")
print(f"  {'-' * 58}")

results = []

for tool in tools:
    context = {"tool_name": tool}

    d1 = eval_v1.evaluate(context)
    d2 = eval_v2.evaluate(context)

    tier1, icon1 = classify(d1)
    tier2, icon2 = classify(d2)

    changed = tier1 != tier2
    flag = "\u26a0\ufe0f  yes" if changed else ""

    print(f"  {tool:<22s} {icon1:<14s} {icon2:<14s} {flag}")
    results.append((tool, tier1, tier2, changed))

changed_count = sum(1 for _, _, _, c in results if c)
print()
if changed_count == 0:
    print("  \u2705 No behavioral changes between v1 and v2.")
else:
    print(f"  {changed_count} tool(s) changed behavior between versions.")

# ── Part 4: Detect regressions ────────────────────────────────────────

print("\n--- Part 4: Detect regressions ---\n")

# The team planned two changes in v2:
#   - block-write-file priority raised (structural, no behavioral change here)
#   - send_email converted from escalation to hard deny (legal decision)
# Anything else that changed is a regression.
expected_changes = {"send_email"}

regressions = []

for tool, tier1, tier2, changed in results:
    if not changed:
        continue
    if tool in expected_changes:
        print(f"  \u2705 {tool}: {tier1} \u2192 {tier2} (expected \u2014 legal decision)")
    else:
        print(f"  \u274c {tool}: {tier1} \u2192 {tier2} (REGRESSION)")
        regressions.append((tool, tier1, tier2))

if not regressions:
    print()
    print("  \u2705 All changes are expected. Safe to deploy v2.")
else:
    print()
    for tool, old, new in regressions:
        print(f"  \u274c Regression: {tool}")
        print(f"     Was '{old}' in v1, now '{new}' in v2.")
        print(f"     The v2 edit removed the escalation keyword from the")
        print(f"     message, so the action that used to pause for human")
        print(f"     review now silently blocks.")
    print()
    print("  Fix the regression in v2, then re-run this comparison.")
    print("  Do not deploy until all changes are expected.")

print("\n" + "=" * 60)
print("  Policy versioning closes the loop.")
print("  Tag a version, diff it, test both, catch regressions.")
print("  No policy update ships without passing this check.")
print("=" * 60)
