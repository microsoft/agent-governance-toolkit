# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""
LangChain SRE Callbacks — auto-record Agent-SRE SLIs from LangChain execution.

Usage:
    from agent_sre.integrations.langchain import AgentSRECallback

    callback = AgentSRECallback()
    chain.invoke("query", config={"callbacks": [callback]})

    # After execution:
    callback.task_success_rate  # 0.95
    callback.avg_cost_usd      # 0.42
    callback.avg_latency_ms    # 230
"""

from agent_sre.integrations.langchain.callback import AgentSRECallback

__all__ = ["AgentSRECallback"]
