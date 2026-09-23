# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""Regression tests for supervisor hierarchy registration and validation."""

from __future__ import annotations

from typing import Any, cast

import pytest

from agent_os.supervisor import SupervisorHierarchy
from agent_os.trust_root import TrustRoot


def _hierarchy() -> SupervisorHierarchy:
    # validate_hierarchy() does not consult the trust root; a typed placeholder
    # keeps this test focused on registration metadata only.
    return SupervisorHierarchy(cast(TrustRoot, object()))


@pytest.mark.parametrize("level", ["1", 1.0, None, True, False])
def test_register_supervisor_rejects_non_integer_levels(level: Any) -> None:
    hierarchy = _hierarchy()

    with pytest.raises(TypeError, match="level must be an integer"):
        hierarchy.register_supervisor("invalid", level=level, is_agent=True)

    assert hierarchy.get_authority_chain({}) == []


def test_register_supervisor_rejects_agent_root() -> None:
    hierarchy = _hierarchy()

    with pytest.raises(ValueError, match="must be deterministic"):
        hierarchy.register_supervisor("agent-root", level=0, is_agent=True)

    assert hierarchy.get_authority_chain({}) == []


def test_valid_integer_hierarchy_contract_is_unchanged() -> None:
    hierarchy = _hierarchy()
    hierarchy.register_supervisor("trust-root", level=0, is_agent=False)
    hierarchy.register_supervisor("worker", level=1, is_agent=True)

    assert hierarchy.validate_hierarchy() == []
