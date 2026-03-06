#!/usr/bin/env python3
# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""
Agent OS + LangChain -- Governance in 5 Minutes (Runnable Demo)

No API keys needed. Run with:
    python demo.py

This demo:
  1. Creates a mock LangChain-like agent
  2. Shows it running WITHOUT governance (anything goes)
  3. Wraps it with Agent OS governance
  4. Shows policy enforcement (dangerous queries get blocked)
  5. Shows audit logging
"""

import sys
import os

# Add project root to path so we can import agent_os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "..", "src"))

from agent_os.integrations import LangChainKernel, GovernancePolicy
from agent_os.integrations.base import GovernanceEventType
from agent_os.integrations.langchain_adapter import PolicyViolationError


# ── ANSI colors ──────────────────────────────────────────────────
GREEN = "\033[92m"
RED = "\033[91m"
YELLOW = "\033[93m"
CYAN = "\033[96m"
BOLD = "\033[1m"
DIM = "\033[2m"
RESET = "\033[0m"


def header(text):
    print(f"\n{BOLD}{CYAN}{'=' * 60}")
    print(f"  {text}")
    print(f"{'=' * 60}{RESET}\n")


def step(num, text):
    print(f"{BOLD}{YELLOW}  Step {num}: {text}{RESET}")


def ok(text):
    print(f"  {GREEN}+ {text}{RESET}")


def blocked(text):
    print(f"  {RED}x {text}{RESET}")


def info(text):
    print(f"  {DIM}{text}{RESET}")


# ── Mock LangChain Agent ─────────────────────────────────────────
# Simulates a LangChain Runnable -- no API keys needed.

class MockLangChainAgent:
    """A mock LangChain agent that echoes queries as if it were an LLM."""

    name = "mock-sql-agent"

    def invoke(self, input_data, **kwargs):
        if isinstance(input_data, dict):
            query = input_data.get("input", str(input_data))
        else:
            query = str(input_data)
        return f"Agent response to: {query}"

    def run(self, *args, **kwargs):
        return self.invoke(args[0] if args else kwargs)


# ── The Demo ─────────────────────────────────────────────────────

def main():
    header("Agent OS + LangChain -- Governance in 5 Minutes")

    # ── Part 1: Without governance (anything goes) ───────────────
    step(1, "LangChain agent WITHOUT governance")
    info("The agent processes everything -- no guardrails.")
    print()

    agent = MockLangChainAgent()

    test_queries = [
        "What are our top customers?",                # Safe
        "Run: DROP TABLE users;",                     # Dangerous!
        "Show me the password for admin",             # Data leak!
        "Execute rm -rf / on the server",             # Catastrophic!
    ]

    for query in test_queries:
        result = agent.invoke({"input": query})
        ok(f"{query}")
        info(f"  -> {result}")
    print()
    info("!!  Everything passed -- including dangerous queries!")

    # ── Part 2: Add Agent OS governance (2 lines!) ───────────────
    print()
    step(2, "Same agent WITH Agent OS governance")
    info("Just 2 lines to add governance:\n")
    print(f"  {CYAN}from agent_os.integrations import LangChainKernel, GovernancePolicy{RESET}")
    print(f"  {CYAN}governed = LangChainKernel(policy=policy).wrap(agent){RESET}")
    print()

    # Define policy
    policy = GovernancePolicy(
        name="tutorial-policy",
        max_tokens=4096,
        max_tool_calls=10,
        blocked_patterns=["DROP TABLE", "DELETE FROM", "password", "secret", "api_key", "rm -rf"],
        log_all_calls=True,
    )

    # Wrap the agent -- this is all it takes!
    kernel = LangChainKernel(policy=policy)
    governed = kernel.wrap(agent)

    # Collect audit log
    audit_log = []

    def on_policy_check(event):
        audit_log.append({"type": "check", "time": event["timestamp"], **event})

    def on_violation(event):
        audit_log.append({"type": "violation", "time": event["timestamp"], **event})

    def on_blocked(event):
        audit_log.append({"type": "blocked", "time": event["timestamp"], **event})

    kernel.on(GovernanceEventType.POLICY_CHECK, on_policy_check)
    kernel.on(GovernanceEventType.POLICY_VIOLATION, on_violation)
    kernel.on(GovernanceEventType.TOOL_CALL_BLOCKED, on_blocked)

    # Test same queries -- now with governance
    for query in test_queries:
        try:
            result = governed.invoke({"input": query})
            ok(f"ALLOWED: {query}")
            info(f"  -> {result}")
        except PolicyViolationError as e:
            blocked(f"BLOCKED: {query}")
            info(f"  -> Policy: {e}")

    # ── Part 3: Audit Log ────────────────────────────────────────
    print()
    step(3, "Audit log -- every action is recorded")
    print()

    if audit_log:
        for entry in audit_log:
            marker = f"{GREEN}CHECK{RESET}" if entry["type"] == "check" else f"{RED}BLOCK{RESET}"
            agent_id = entry.get("agent_id", "unknown")
            reason = entry.get("reason", "")
            ts = entry.get("time", "")
            line = f"  [{marker}] agent={agent_id} time={ts}"
            if reason:
                line += f" reason={reason}"
            print(line)
    else:
        info("(audit log is empty -- events fire internally)")

    # ── Part 4: Policy from YAML ─────────────────────────────────
    print()
    step(4, "Load policy from YAML")
    print()

    yaml_path = os.path.join(os.path.dirname(__file__), "policies.yaml")
    if os.path.exists(yaml_path):
        loaded_policy = GovernancePolicy.load(yaml_path)
        ok(f"Loaded policy from {os.path.basename(yaml_path)}")
        info(f"  max_tokens={loaded_policy.max_tokens}, "
             f"max_tool_calls={loaded_policy.max_tool_calls}, "
             f"blocked_patterns={loaded_policy.blocked_patterns}")
    else:
        info(f"(policies.yaml not found at {yaml_path})")

    # ── Summary ──────────────────────────────────────────────────
    header("Summary")
    print(f"  {GREEN}+{RESET} Created a LangChain agent")
    print(f"  {GREEN}+{RESET} Added Agent OS governance in 2 lines")
    print(f"  {GREEN}+{RESET} Dangerous queries blocked by policy")
    print(f"  {GREEN}+{RESET} Every action recorded in audit log")
    print(f"  {GREEN}+{RESET} Policy loaded from YAML file")
    print()
    print(f"  {BOLD}Next steps:{RESET}")
    print(f"  * Edit policies.yaml to customize rules")
    print(f"  * Replace MockLangChainAgent with your real agent")
    print(f"  * See docs: https://github.com/microsoft/agent-governance-toolkit")
    print()


if __name__ == "__main__":
    main()
