# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""Shadow Mode — backward-compatibility shim.

Attempts to import the canonical implementation from
``agent_sre.delivery.rollout``.  When ``agent_sre`` is not installed the
standalone fallback in ``agentmesh.governance._shadow_impl`` is
re-exported so that ``agentmesh`` continues to work without requiring
the optional SRE package.

.. deprecated::
    Import from ``agent_sre.delivery.rollout`` instead.
"""

from __future__ import annotations

try:
    from agent_sre.delivery.rollout import *  # noqa: F401,F403
except ImportError:
    from agentmesh.governance._shadow_impl import *  # noqa: F401,F403
