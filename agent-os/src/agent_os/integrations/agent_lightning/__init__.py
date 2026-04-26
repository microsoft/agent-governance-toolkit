# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""
Agent-Lightning Integration — backward-compatibility shim.

The integration has moved to the **agent-lightning** package
(``agent_lightning_gov``). All symbols are re-exported here so
existing ``from agent_os.integrations.agent_lightning …`` imports
continue to work.

.. deprecated::
    Import directly from ``agent_lightning_gov`` instead.
"""

# ruff: noqa: F401
from agent_lightning_gov import (  # noqa: F401 – re-export
    FlightRecorderEmitter,
    GovernedEnvironment,
    GovernedRunner,
    PolicyReward,
    policy_penalty,
)

__all__ = [
    "GovernedRunner",
    "PolicyReward",
    "policy_penalty",
    "FlightRecorderEmitter",
    "GovernedEnvironment",
]
