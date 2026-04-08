# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""
Chapter 4: Conditional Policies — Environment-Aware Rules and Conflict Resolution

Shows how policies can change based on environment (dev vs prod), then
what happens when policies from different teams disagree, and how
PolicyConflictResolver picks a winner.

Run from the repo root:
    pip install agent-os-kernel[full]
    python docs/tutorials/policy-as-code/examples/04_conditional_policies.py
"""

from __future__ import annotations

import sys
from pathlib import Path

# Allow running from the repo root without installing the packages.
_REPO_ROOT = Path(__file__).resolve().parent.parent.parent.parent.parent
sys.path.insert(0, str(_REPO_ROOT / "packages" / "agent-os" / "src"))

from agent_os.policies import (
    CandidateDecision,
    ConflictResolutionStrategy,
    PolicyConflictResolver,
    PolicyEvaluator,
    PolicyScope,
)
from agent_os.policies.schema import PolicyDocument

EXAMPLES_DIR = Path(__file__).parent

# ── Part 1: Environment-aware rules ─────────────────────────────────

print("=" * 60)
print("  Chapter 4: Conditional Policies")
print("=" * 60)

print("\n--- Part 1: Environment-aware rules ---\n")

env_policy = PolicyDocument.from_yaml(EXAMPLES_DIR / "04_env_policy.yaml")
env_eval = PolicyEvaluator(policies=[env_policy])

environments = ["development", "staging", "production"]
print(f"  {'Environment':<16s} {'Decision':<12s} Reason")
print(f"  {'-' * 55}")
for env in environments:
    decision = env_eval.evaluate({"environment": env})
    icon = "\u2705 allow" if decision.allowed else "\U0001f6ab deny "
    print(f"  {env:<16s} {icon:<12s} {decision.reason}")

print()
print("  Same agent, same tool — different answer depending on")
print("  where it runs. Dev is open, production is locked down.")
print()
print("  This works when one team writes all the rules. But what")
print("  happens when the security team and a product team each")
print("  write their own policy — and they disagree?")

# ── Part 2: The conflict ──────────────────────────────────────────────

print("\n--- Part 2: Two policies, one agent ---\n")

global_policy = PolicyDocument.from_yaml(EXAMPLES_DIR / "04_global_policy.yaml")
team_policy = PolicyDocument.from_yaml(EXAMPLES_DIR / "04_support_team_policy.yaml")

# Evaluate each policy separately to see their individual answers.
global_eval = PolicyEvaluator(policies=[global_policy])
team_eval = PolicyEvaluator(policies=[team_policy])

tools = ["send_email", "write_file", "delete_database", "search_documents"]

print(f"  {'Tool':<22s} {'Global policy':<18s} {'Team policy'}")
print(f"  {'-' * 58}")
for tool in tools:
    g = global_eval.evaluate({"tool_name": tool})
    t = team_eval.evaluate({"tool_name": tool})
    g_icon = "\u2705 allow" if g.allowed else "\U0001f6ab deny "
    t_icon = "\u2705 allow" if t.allowed else "\U0001f6ab deny "
    conflict = "  \u26a0\ufe0f CONFLICT" if g.allowed != t.allowed else ""
    print(f"  {tool:<22s} {g_icon:<18s} {t_icon}{conflict}")

print()
print("  The security team says: deny send_email.")
print("  The support team says: allow send_email.")
print("  Both policies apply to the same agent. Who wins?")

# ── Part 3: Introduce the conflict resolver ───────────────────────────

print("\n--- Part 3: Resolving the send_email conflict ---\n")

# Build candidate decisions for the conflicting tool: send_email.
# The global policy is company-wide, so its scope is GLOBAL.
# The team policy is specific to one team, so its scope is TENANT.
global_candidate = CandidateDecision(
    action="deny",
    priority=90,
    scope=PolicyScope.GLOBAL,
    policy_name="global-security-policy",
    rule_name="block-send-email",
    reason="Company policy: agents may not send emails without controls",
)

team_candidate = CandidateDecision(
    action="allow",
    priority=90,
    scope=PolicyScope.TENANT,
    policy_name="support-team-policy",
    rule_name="allow-send-email",
    reason="Support team: our agent needs to email customers",
)

print(f"  Security team says: {global_candidate.action:6s} send_email  (scope={global_candidate.scope.value})")
print(f"  Support team says:  {team_candidate.action:6s} send_email  (scope={team_candidate.scope.value})")

# ── Part 4: All four strategies ───────────────────────────────────────

print("\n--- Part 4: Four strategies, four outcomes ---\n")

candidates = [global_candidate, team_candidate]

strategies = [
    ("DENY_OVERRIDES", ConflictResolutionStrategy.DENY_OVERRIDES,
     "If anyone says deny, the answer is deny. Safety first."),
    ("ALLOW_OVERRIDES", ConflictResolutionStrategy.ALLOW_OVERRIDES,
     "If anyone says allow, the answer is allow. Exceptions win."),
    ("PRIORITY_FIRST_MATCH", ConflictResolutionStrategy.PRIORITY_FIRST_MATCH,
     "Highest priority number wins. Both are 90 — tie goes to whichever candidate was listed first."),
    ("MOST_SPECIFIC_WINS", ConflictResolutionStrategy.MOST_SPECIFIC_WINS,
     "The more specific scope wins. TENANT beats GLOBAL."),
]

for name, strategy, explanation in strategies:
    resolver = PolicyConflictResolver(strategy)
    result = resolver.resolve(candidates)
    winner = result.winning_decision
    icon = "\u2705 allow" if winner.is_allow else "\U0001f6ab deny "
    print(f"  {name}")
    print(f"    Result: {icon}  (from {winner.policy_name})")
    print(f"    Why:    {explanation}")
    print()

# ── Part 5: Scopes — organizational hierarchy ────────────────────────

print("--- Part 5: The scope hierarchy ---\n")

print("  Scopes rank from broadest to most specific:\n")
print("    GLOBAL (0)  →  TENANT (1)  →  ORGANIZATION (2)  →  AGENT (3)")
print()
print("  With MOST_SPECIFIC_WINS, a closer scope always beats a broader one.")
print()

# Show what happens when the support team upgrades to AGENT scope.
team_as_agent = team_candidate.model_copy(update={"scope": PolicyScope.AGENT})

resolver = PolicyConflictResolver(ConflictResolutionStrategy.MOST_SPECIFIC_WINS)

print("  Scenario A: security=GLOBAL vs support=TENANT")
result_a = resolver.resolve([global_candidate, team_candidate])
icon_a = "\u2705 allow" if result_a.winning_decision.is_allow else "\U0001f6ab deny"
print(f"    Winner: {result_a.winning_decision.policy_name} ({icon_a})")
print(f"    TENANT (specificity {team_candidate.specificity}) beats GLOBAL (specificity {global_candidate.specificity})")

print()
print("  Scenario B: security=GLOBAL vs support=AGENT")
result_b = resolver.resolve([global_candidate, team_as_agent])
icon_b = "\u2705 allow" if result_b.winning_decision.is_allow else "\U0001f6ab deny"
print(f"    Winner: {result_b.winning_decision.policy_name} ({icon_b})")
print(f"    AGENT (specificity {team_as_agent.specificity}) beats GLOBAL (specificity {global_candidate.specificity})")

# Now show what happens if security upgrades to AGENT too.
print()
print("  Scenario C: both at AGENT scope (tie on scope — priority breaks it)")
global_as_agent = global_candidate.model_copy(
    update={"scope": PolicyScope.AGENT, "priority": 95},
)
result_c = resolver.resolve([global_as_agent, team_as_agent])
icon_c = "\u2705 allow" if result_c.winning_decision.is_allow else "\U0001f6ab deny"
print(f"    Security priority: {global_as_agent.priority}, Support priority: {team_as_agent.priority}")
print(f"    Winner: {result_c.winning_decision.policy_name} ({icon_c})")
print(f"    Same scope, so higher priority wins.")

print("\n" + "=" * 60)
print("  Conflict resolution lets you layer policies from different")
print("  parts of the organization without them breaking each other.")
print("=" * 60)
