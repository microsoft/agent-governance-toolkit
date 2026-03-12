# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""Shadow Mode — backward-compatibility shim.

The canonical implementation has moved to ``agent_sre.delivery.rollout``.
This module re-exports the shadow-mode symbols used by agentmesh governance.

.. deprecated::
    Import from ``agent_sre.delivery.rollout`` instead.
"""
from agent_sre.delivery.rollout import *  # noqa: F401,F403
