# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""Regression tests for supervisor hierarchy registration and validation."""

from __future__ import annotations

from typing import Any, cast

import pytest

from agent_os.supervisor import SupervisorHierarchy, _Supervisor
from agent_os.trust_root import TrustRoot


def _hierarchy() -> SupervisorHierarchy:
    # validate_hierarchy() does not consult the trust root; a typed placeholder
    # keeps this test focused on registration metadata only.
    return SupervisorHierarchy(cast(TrustRoot, object()))


@pytest.mark.parametrize("level", ["1", 1.0, None, True, False])
def test_register_supervisor_rejects_non_integer_levels(level: Any) -> None:
    hierarchy = _hierarchy()

    with pytest.raises(TypeError) as exc_info:
        hierarchy.register_supervisor("invalid", level=level, is_agent=True)

    assert str(exc_info.value) == f"Supervisor level must be an int, got {level!r}"
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


def test_validate_hierarchy_reports_missing_root_and_level_gap() -> None:
    hierarchy = _hierarchy()
    hierarchy.register_supervisor("worker", level=2, is_agent=True)

    assert hierarchy.validate_hierarchy() == [
        "Level 0 (root) has no registered supervisor",
        "Level 1 has no registered supervisor",
    ]


def test_validate_hierarchy_defensively_reports_invalid_internal_state() -> None:
    hierarchy = _hierarchy()
    hierarchy.register_supervisor("trust-root", level=0, is_agent=False)
    hierarchy._supervisors.extend(
        [
            _Supervisor("non-integer", cast(Any, "1")),
            _Supervisor("above-root", -1),
            _Supervisor("agent-root", 0),
        ]
    )

    violations = hierarchy.validate_hierarchy()

    assert any(
        "non-integer" in violation and "non-integer level" in violation for violation in violations
    )
    assert any(
        "above-root" in violation and "negative level" in violation for violation in violations
    )
    assert any(
        "agent-root" in violation and "must be deterministic" in violation
        for violation in violations
    )
