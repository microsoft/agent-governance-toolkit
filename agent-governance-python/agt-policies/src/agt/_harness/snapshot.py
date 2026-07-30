# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""Back-compat shim. The snapshot helpers moved to ``agt.policies.snapshot``.

Existing scenario tests under ``tests/scenarios/`` import the module-level
helpers (``input_snapshot``, ``pre_tool_call_snapshot``, ...) from this
path; the canonical home is now :mod:`agt.policies.snapshot`. New code
SHOULD import from there (or from :mod:`agt.policies`).
"""

from __future__ import annotations

from agt.policies.snapshot import (
    SnapshotBuilder,
    agent_shutdown_snapshot,
    agent_startup_snapshot,
    input_snapshot,
    output_snapshot,
    post_model_call_snapshot,
    post_tool_call_snapshot,
    pre_model_call_snapshot,
    pre_tool_call_snapshot,
)

__all__ = [
    "SnapshotBuilder",
    "agent_shutdown_snapshot",
    "agent_startup_snapshot",
    "input_snapshot",
    "output_snapshot",
    "post_model_call_snapshot",
    "post_tool_call_snapshot",
    "pre_model_call_snapshot",
    "pre_tool_call_snapshot",
]
