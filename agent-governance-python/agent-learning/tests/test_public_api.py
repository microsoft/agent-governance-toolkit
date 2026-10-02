# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""Smoke tests for the public package surface."""

from __future__ import annotations

import agent_learning_gov


def test_all_public_exports_resolve() -> None:
    assert agent_learning_gov.__all__
    assert all(hasattr(agent_learning_gov, name) for name in agent_learning_gov.__all__)
