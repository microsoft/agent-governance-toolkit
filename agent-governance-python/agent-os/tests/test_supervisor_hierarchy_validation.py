# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""Regression tests for supervisor hierarchy validation."""

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
def test_validate_hierarchy_reports_non_integer_level_without_crashing(level: Any) -> None:
    hierarchy = _hierarchy()
    hierarchy.register_supervisor("trust-root", level=0, is_agent=False)
    hierarchy.register_supervisor("invalid", level=level, is_agent=True)

    violations = hierarchy.validate_hierarchy()

    assert any("invalid" in violation and "non-integer level" in violation for violation in violations)


def test_invalid_false_level_does_not_satisfy_root_requirement() -> None:
    hierarchy = _hierarchy()
    hierarchy.register_supervisor("boolean-root", level=False, is_agent=False)

    violations = hierarchy.validate_hierarchy()

    assert any("non-integer level" in violation for violation in violations)
    assert "Level 0 (root) has no registered supervisor" in violations


def test_valid_integer_hierarchy_contract_is_unchanged() -> None:
    hierarchy = _hierarchy()
    hierarchy.register_supervisor("trust-root", level=0, is_agent=False)
    hierarchy.register_supervisor("worker", level=1, is_agent=True)

    assert hierarchy.validate_hierarchy() == []
