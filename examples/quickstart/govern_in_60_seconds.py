"""Govern your AI agent in 60 seconds.

This is the simplest possible AGT integration — 3 lines to add
governance to any agent. No trust mesh, no execution rings, no SRE.
Just deterministic policy enforcement.

Usage:
    pip install agent-os-kernel
    python examples/quickstart/govern_in_60_seconds.py
"""

from agent_os.lite import govern

# 1. Create a governance gate — one line
check = govern(
    allow=["web_search", "read_file"],
    deny=["execute_code", "delete_file", "send_email"],
)

# 2. Check every agent action — one line
def safe_action(action: str) -> bool:
    """Returns True if the action is allowed."""
    allowed = check.is_allowed(action)
    print(f"  {'✅' if allowed else '🚫'} {action}: {'allowed' if allowed else 'BLOCKED'}")
    return allowed

# 3. That's it! Use it in your agent loop
print("\n🛡️  Agent Governance in 60 Seconds\n")
print("Testing actions against policy:")
safe_action("web_search")        # ✅ allowed
safe_action("read_file")         # ✅ allowed
safe_action("execute_code")      # 🚫 blocked
safe_action("delete_file")       # 🚫 blocked
safe_action("send_email")        # 🚫 blocked

# Show stats
stats = check.stats
print(f"\n📊 Stats: {stats['total']} decisions, {stats['denied']} blocked, "
      f"{stats['violation_rate']} violation rate, {stats['avg_latency_ms']}ms avg")

print("\n✨ Done! You just governed an agent in 3 lines of code.")
print("\nNext steps:")
print("  📚 Add YAML policies:      docs/tutorials/01-policy-engine.md")
print("  🔐 Add agent identity:     docs/tutorials/02-trust-and-identity.md")
print("  🔍 Discover shadow agents: docs/tutorials/29-agent-discovery.md")
print("  📈 Progressive complexity: docs/tutorials/progressive-governance.md")
