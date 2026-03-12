# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""Adversarial Evaluation — backward-compatibility shim.

The canonical implementation has moved to ``agent_sre.chaos``.
This module re-exports all public symbols.

.. deprecated::
    Import from ``agent_sre.chaos.adversarial_policy`` instead.
"""
from agent_sre.chaos.adversarial_policy import *  # noqa: F401,F403