"""Govern your AI agent in 60 seconds.

This is the simplest possible AGT integration — 3 lines to add
governance to any agent. No trust mesh, no execution rings, no SRE.
Just deterministic policy enforcement.

Usage:
    pip install agent-os-kernel
    python examples/quickstart/govern_in_60_seconds.py
"""

from agent_os.policies import PolicyEvaluator

# 1. Create a policy evaluator with inline rules
evaluator = PolicyEvaluator()
evaluator.add_rules([
    {"action": "web_search", "effect": "allow"},
    {"action": "read_file", "effect": "allow"},
    {"action": "execute_code", "effect": "deny"},
    {"action": "delete_file", "effect": "deny"},
    {"action": "send_email", "effect": "deny"},
])

# 2. Check every agent action before execution
def govern(action: str, **context) -> bool:
    """Returns True if the action is allowed."""
    decision = evaluator.evaluate({"action": action, **context})
    print(f"  {'✅' if decision.allowed else '🚫'} {action}: {'allowed' if decision.allowed else 'BLOCKED'}")
    return decision.allowed

# 3. That's it! Use it in your agent loop
print("\n🛡️  Agent Governance in 60 Seconds\n")
print("Testing actions against policy:")
govern("web_search")        # ✅ allowed
govern("read_file")         # ✅ allowed
govern("execute_code")      # 🚫 blocked
govern("delete_file")       # 🚫 blocked
govern("send_email")        # 🚫 blocked

print("\n✨ Done! You just governed an agent in 3 lines of code.")
print("\nNext steps:")
print("  📚 Add YAML policies:     docs/tutorials/01-policy-engine.md")
print("  🔐 Add agent identity:    docs/tutorials/02-trust-and-identity.md")
print("  🔍 Discover shadow agents: docs/tutorials/29-agent-discovery.md")
print("  📊 View dashboard:         demo/governance-dashboard/")
