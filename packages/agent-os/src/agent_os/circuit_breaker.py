# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""Circuit Breaker — backward-compatibility shim.

The canonical implementation has moved to ``agent_sre.cascade.circuit_breaker``.

.. deprecated::
    Import from ``agent_sre.cascade.circuit_breaker`` instead.
"""
from agent_sre.cascade.circuit_breaker import *  # noqa: F401,F403
