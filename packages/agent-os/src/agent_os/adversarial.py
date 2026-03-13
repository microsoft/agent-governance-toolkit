# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""Adversarial Evaluation — backward-compatibility shim.

Attempts to import the canonical implementation from
``agent_sre.chaos.adversarial_policy``.  When ``agent_sre`` is not
installed the standalone fallback in ``agent_os._adversarial_impl`` is
re-exported so that ``agent_os`` continues to work without requiring the
optional SRE package.

.. deprecated::
    Import from ``agent_sre.chaos.adversarial_policy`` instead.
"""

from __future__ import annotations

try:
    from agent_sre.chaos.adversarial_policy import *  # noqa: F401,F403
except ImportError:
    from agent_os._adversarial_impl import *  # noqa: F401,F403
