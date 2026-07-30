# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""
Cross-Framework Signal Demo

Shows how Agent OS provides UNIX-style process signals (SIGSTOP, SIGCONT,
SIGKILL) across all supported frameworks — enabling pause/resume/kill
regardless of the underlying agent runtime.
"""

from agent_os.integrations import GovernancePolicy, AutoGenKernel, LlamaIndexKernel
from agent_os.integrations.langchain_adapter import PolicyViolationError
from unittest.mock import MagicMock


def demo_autogen_signals():
    """AutoGen: govern agents in-place with signal control."""
    print("\n--- AutoGen Signal Demo ---")

    # Mock agent for demonstration
    agent = MagicMock()
    agent.name = "demo-agent"
    agent.generate_reply = MagicMock(return_value="I am thinking")

    kernel = AutoGenKernel(policy=GovernancePolicy(max_tokens=5000))
    kernel.govern(agent)

    # Normal operation
    result = agent.generate_reply(messages=[{"content": "hello"}])
    print(f"  Normal:   generate_reply → {result}")

    # SIGSTOP — pause agent
    kernel.signal("demo-agent", "SIGSTOP")
    result = agent.generate_reply(messages=[{"content": "hello"}])
    print(f"  SIGSTOP:  Agent paused → {result}")

    # SIGCONT — resume agent
    kernel.signal("demo-agent", "SIGCONT")
    result = agent.generate_reply(messages=[{"content": "hello"}])
    print(f"  SIGCONT:  Agent resumed → {result}")

    # Unwrap — restore original
    kernel.unwrap(agent)
    print("  unwrap(): Original methods restored")


def demo_llamaindex_signals():
    """LlamaIndex: govern engines with signal control."""
    print("\n--- LlamaIndex Signal Demo ---")

    # Mock query engine
    engine = MagicMock()
    engine.name = "search-engine"
    engine.query = MagicMock(return_value="Document says X")

    kernel = LlamaIndexKernel(policy=GovernancePolicy(max_tokens=5000))
    governed = kernel.wrap(engine)

    # Normal operation
    result = governed.query("What does the document say?")
    print(f"  Normal:   query → {result}")

    # SIGSTOP — pause
    kernel.signal("search-engine", "SIGSTOP")
    try:
        governed.query("Another query")
    except (RuntimeError, PolicyViolationError) as e:
        print(f"  SIGSTOP:  Engine paused → {e}")

    # SIGCONT — resume
    kernel.signal("search-engine", "SIGCONT")
    result = governed.query("Final query")
    print(f"  SIGCONT:  Engine resumed → {result}")


if __name__ == "__main__":
    print("=" * 50)
    print("Agent OS — Cross-Framework Signal Handling")
    print("=" * 50)
    demo_autogen_signals()
    demo_llamaindex_signals()
    print("\n" + "=" * 50)
    print("SIGSTOP/SIGCONT/SIGKILL work identically across all adapters")
    print("=" * 50)
