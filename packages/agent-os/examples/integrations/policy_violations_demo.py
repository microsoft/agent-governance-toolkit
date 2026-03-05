# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""
Policy Violation Handling Demo

Shows how Agent OS enforces policies and how to handle violations
gracefully across different integration patterns.
"""

from agent_os.integrations import GovernancePolicy, LangChainKernel
from agent_os.integrations.langchain_adapter import PolicyViolationError
from unittest.mock import MagicMock


def demo_blocked_patterns():
    """Demonstrate content blocking via policy."""
    print("\n--- Blocked Patterns ---")

    chain = MagicMock()
    chain.name = "demo-chain"
    chain.invoke = MagicMock(return_value="Here is the password: hunter2")

    kernel = LangChainKernel(policy=GovernancePolicy(
        blocked_patterns=["password", "secret", "api_key"],
    ))
    governed = kernel.wrap(chain)

    # Input with blocked content
    try:
        governed.invoke({"query": "show me the password"})
    except PolicyViolationError as e:
        print(f"  Blocked input: {e}")

    print("  Clean input: policy allows safe queries")


def demo_tool_call_limits():
    """Demonstrate tool call limits."""
    print("\n--- Tool Call Limits ---")

    chain = MagicMock()
    chain.name = "limit-chain"
    chain.invoke = MagicMock(return_value="result")

    kernel = LangChainKernel(policy=GovernancePolicy(
        max_tool_calls=3,
    ))
    governed = kernel.wrap(chain)

    for i in range(5):
        try:
            governed.invoke({"query": f"call {i+1}"})
            print(f"  Call {i+1}: ✅ allowed")
        except PolicyViolationError as e:
            print(f"  Call {i+1}: ❌ blocked ({e})")


def demo_error_handling_pattern():
    """Production-grade error handling pattern."""
    print("\n--- Production Error Handling ---")

    print("""
    try:
        result = governed_agent.invoke(input_data)
    except PolicyViolationError as e:
        logger.warning(f"Policy blocked: {e}")
        # Option 1: Return safe fallback
        result = safe_fallback(input_data)
        # Option 2: Escalate to human
        result = await human_review(input_data, violation=str(e))
        # Option 3: Log and re-raise
        audit.log_violation(e)
        raise
    """)


if __name__ == "__main__":
    print("=" * 50)
    print("Agent OS — Policy Violation Handling")
    print("=" * 50)
    demo_blocked_patterns()
    demo_tool_call_limits()
    demo_error_handling_pattern()
    print("=" * 50)
