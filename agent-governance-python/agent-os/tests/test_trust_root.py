# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""Tests for the native-runtime trust authority and supervisor hierarchy."""
from __future__ import annotations

import pytest
from agent_control_specification import Decision, InterventionPointResult, Verdict

from agent_os.supervisor import MAX_SUPERVISOR_LEVEL, SupervisorHierarchy
from agent_os.trust_root import TrustRoot


class _Runtime:
    manifest = None

    async def evaluate_intervention_point(self, intervention_point, snapshot, mode=None):
        denied = 'delete_file' in str(snapshot) or 'DROP TABLE' in str(snapshot)
        return InterventionPointResult(verdict=Verdict(decision=Decision('deny') if denied else Decision('allow'), reason='restricted_action' if denied else '', message='Action denied by trust authority' if denied else ''))

def _root() -> TrustRoot:
    return TrustRoot(_Runtime())

def test_trust_root_delegates_actions_to_native_runtime() -> None:
    root = _root()
    assert root.validate_action({'tool': 'read_file', 'arguments': {}}).allowed is True
    denied = root.validate_action({'tool': 'delete_file', 'arguments': {}})
    assert denied.allowed is False
    assert denied.authority == 'native-runtime'
    assert denied.deterministic is True

def test_trust_root_passes_nested_arguments_to_runtime() -> None:
    denied = _root().validate_action({'tool': 'sql_query', 'arguments': {'query': 'DROP TABLE users'}})
    assert denied.allowed is False

def test_supervisor_validation_preserves_deterministic_root_rule() -> None:
    root = _root()
    assert root.validate_supervisor({'name': 'root', 'level': 0, 'is_agent': False})
    assert not root.validate_supervisor({'name': 'model', 'level': 0, 'is_agent': True})
    assert root.validate_supervisor({'name': 'model', 'level': 1, 'is_agent': True})

def test_supervisor_hierarchy_escalates_to_native_trust_root() -> None:
    hierarchy = SupervisorHierarchy(trust_root=_root())
    hierarchy.register_supervisor('trust-root', level=0, is_agent=False)
    hierarchy.register_supervisor('worker', level=1, is_agent=True)
    assert hierarchy.validate_hierarchy() == []
    assert hierarchy.escalate({'tool': 'read_file', 'arguments': {}}, from_level=1).allowed
    assert not hierarchy.escalate({'tool': 'delete_file', 'arguments': {}}, from_level=1).allowed

@pytest.mark.parametrize('level', [-1, -2, -100])
@pytest.mark.parametrize('is_agent', [True, False])
def test_negative_supervisor_level_is_rejected(level: int, is_agent: bool) -> None:
    """Level 0 is the root, so a negative level sits *above* it.

    The rule was a single exact comparison, ``if level == 0 and is_agent``, which
    every negative level passes -- placing a supervisor ahead of the
    deterministic authority, which is the one position the rule exists to
    protect. Rejected regardless of ``is_agent``: being deterministic does not
    make the position valid, because there is nothing above the root to
    supervise.
    """
    assert _root().validate_supervisor({'name': 'above-root', 'level': level, 'is_agent': is_agent}) is False

@pytest.mark.parametrize('level', ['0', '1', 0.0, 1.5, [0], True, False])
def test_non_integer_supervisor_level_is_rejected(level: object) -> None:
    """A level that is not a real ``int`` skipped the determinism check.

    ``"0" == 0`` is False in Python, so a string level -- exactly what a config
    loader that skips coercion produces -- was never compared against the root
    at all rather than failing the comparison. ``bool`` is covered here too: it
    is an ``int`` subclass whose ``False == 0``, so a bool level would otherwise
    be read as the root level.
    """
    assert _root().validate_supervisor({'name': 'sup', 'level': level, 'is_agent': True}) is False

@pytest.mark.parametrize(('level', 'is_agent', 'expected'), [(0, False, True), (0, True, False), (1, True, True), (9, True, True)])
def test_accepted_supervisor_levels_are_unchanged(level: int, is_agent: bool, expected: bool) -> None:
    assert _root().validate_supervisor({'name': 'sup', 'level': level, 'is_agent': is_agent}) is expected

def _hierarchy_with(name: str, level: int, is_agent: bool) -> SupervisorHierarchy:
    hierarchy = SupervisorHierarchy(trust_root=_root())
    hierarchy.register_supervisor('trust-root', level=0, is_agent=False)
    hierarchy.register_supervisor('safety-agent', level=1, is_agent=True)
    hierarchy.register_supervisor(name, level=level, is_agent=is_agent)
    return hierarchy

def test_agent_registered_above_the_root_is_reported() -> None:
    """``validate_hierarchy`` had no check that could see a negative level.

    The determinism rule only inspects supervisors whose level is exactly 0, and
    the gap scan only walks ``range(1, max_level + 1)``. An LLM agent at level -1
    therefore produced an empty violation list -- the documented "valid" signal.
    """
    violations = _hierarchy_with('above-root', -1, True).validate_hierarchy()
    assert violations != []
    assert any('above-root' in v and '-1' in v for v in violations)

def test_deterministic_supervisor_above_the_root_is_also_reported() -> None:
    assert _hierarchy_with('above-root', -1, False).validate_hierarchy() != []

def test_negative_level_outranks_the_root_in_the_authority_chain() -> None:
    """Why a violation is the right response rather than a warning.

    The chain is ordered by level, so a negative level lands last -- the
    position the docstring reserves for the trust root as final authority.
    """
    assert _hierarchy_with('above-root', -1, True).get_authority_chain({})[-1] == 'above-root'

@pytest.mark.parametrize('level', [-1, -7])
def test_negative_level_is_reported_even_without_a_level_0(level: int) -> None:
    # The gap scan walks range(1, max_level + 1), which is empty when the highest
    # level is negative, so nothing else would fire here either.
    hierarchy = SupervisorHierarchy(trust_root=_root())
    hierarchy.register_supervisor('only', level=level, is_agent=True)
    assert any('negative level' in v for v in hierarchy.validate_hierarchy())


# =====================================================================
# Level-bound enforcement  (#3788)
#
# ``validate_hierarchy`` previously iterated ``range(1, max_level + 1)`` to
# find gaps. Python ints are unbounded, so a supervisor at level ``10**100``
# made that loop hang — a denial-of-service vector whenever levels come from
# attacker-influenced configuration.
#
# Fix: (1) ``register_supervisor`` rejects levels above
# ``MAX_SUPERVISOR_LEVEL`` at registration time, so the pathological value
# never enters the hierarchy; (2) the gap scan now walks the *sorted set of
# registered levels* (O(n log n) in supervisors) instead of the numeric range;
# (3) ``TrustRoot.validate_supervisor`` mirrors the bound.
#
# Tests below:
#   - 4 on register_supervisor (ValueError on over-limit levels)
#   - 4 on validate_hierarchy (gap scan correctness with the new algorithm)
#   - 2 on TrustRoot.validate_supervisor (bound mirrored)
# =====================================================================

class TestRegisterSupervisorRejectsOverLimitLevel:
    """``register_supervisor`` must reject levels above ``MAX_SUPERVISOR_LEVEL``.

    Call chain: ``SupervisorHierarchy.register_supervisor``
    → compares *level* against ``MAX_SUPERVISOR_LEVEL``
    → raises ``ValueError`` before appending to ``self._supervisors``.

    The bound is checked at registration, not at validation, so the
    pathological value never enters the data structure.
    """

    def test_level_just_above_the_limit_is_rejected(self) -> None:
        hierarchy = SupervisorHierarchy(trust_root=_root())
        with pytest.raises(ValueError, match="exceeds the maximum"):
            hierarchy.register_supervisor('bad', level=MAX_SUPERVISOR_LEVEL + 1)

    def test_astronomically_large_level_is_rejected(self) -> None:
        """The original DoS vector: ``level=10**100`` hung ``validate_hierarchy``
        because the gap scan iterated ``range(1, 10**100 + 1)``.  With the
        bound, registration fails instantly."""
        hierarchy = SupervisorHierarchy(trust_root=_root())
        with pytest.raises(ValueError, match="exceeds the maximum"):
            hierarchy.register_supervisor('dos', level=10**100)

    def test_level_at_the_limit_is_accepted(self) -> None:
        hierarchy = SupervisorHierarchy(trust_root=_root())
        hierarchy.register_supervisor('edge', level=MAX_SUPERVISOR_LEVEL)
        assert 'edge' in hierarchy.get_authority_chain({})

    def test_rejected_level_does_not_enter_the_hierarchy(self) -> None:
        hierarchy = SupervisorHierarchy(trust_root=_root())
        with pytest.raises(ValueError):
            hierarchy.register_supervisor('ghost', level=MAX_SUPERVISOR_LEVEL + 1)
        assert 'ghost' not in hierarchy.get_authority_chain({})


class TestGapScanWithSortedSet:
    """The gap scan must find missing levels without iterating the numeric range.

    Call chain: ``SupervisorHierarchy.validate_hierarchy``
    → builds ``occupied = sorted({s.level for s in self._supervisors if s.level >= 0})``
    → walks adjacent pairs ``(occupied[i-1], occupied[i])``
    → reports every integer in the gap as a missing level.

    The old implementation was ``for lvl in range(1, max_level + 1)``, which is
    O(max_level). The new one is O(n log n) in the number of supervisors.
    """

    def test_contiguous_levels_produce_no_gap_violations(self) -> None:
        hierarchy = SupervisorHierarchy(trust_root=_root())
        hierarchy.register_supervisor('root', level=0, is_agent=False)
        hierarchy.register_supervisor('mid', level=1, is_agent=True)
        hierarchy.register_supervisor('leaf', level=2, is_agent=True)
        violations = hierarchy.validate_hierarchy()
        assert not any('has no registered supervisor' in v for v in violations)

    def test_single_gap_is_reported(self) -> None:
        """Levels 0 and 2 present, level 1 missing."""
        hierarchy = SupervisorHierarchy(trust_root=_root())
        hierarchy.register_supervisor('root', level=0, is_agent=False)
        hierarchy.register_supervisor('leaf', level=2, is_agent=True)
        violations = hierarchy.validate_hierarchy()
        gap_violations = [v for v in violations if 'has no registered supervisor' in v]
        assert len(gap_violations) == 1
        assert 'Level 1' in gap_violations[0]

    def test_multiple_gaps_across_sparse_levels(self) -> None:
        """Levels 0, 3, 7 present → gaps at 1, 2, 4, 5, 6."""
        hierarchy = SupervisorHierarchy(trust_root=_root())
        hierarchy.register_supervisor('root', level=0, is_agent=False)
        hierarchy.register_supervisor('mid', level=3, is_agent=True)
        hierarchy.register_supervisor('far', level=7, is_agent=True)
        violations = hierarchy.validate_hierarchy()
        gap_violations = [v for v in violations if 'has no registered supervisor' in v]
        assert len(gap_violations) == 5
        missing = {int(v.split('Level ')[1].split(' ')[0]) for v in gap_violations}
        assert missing == {1, 2, 4, 5, 6}

    def test_gaps_below_minimum_occupied_level_are_reported(self) -> None:
        """Counterexample from review: levels=[0,3] must report levels 1 and 2
        missing.  Without anchoring at 0 the sorted-set walk starts at the
        minimum occupied level and silently drops gaps below it."""
        hierarchy = SupervisorHierarchy(trust_root=_root())
        hierarchy.register_supervisor('root', level=0, is_agent=False)
        hierarchy.register_supervisor('far', level=3, is_agent=True)
        violations = hierarchy.validate_hierarchy()
        gap_violations = [v for v in violations if 'has no registered supervisor' in v]
        missing = {int(v.split('Level ')[1].split(' ')[0]) for v in gap_violations}
        assert missing == {1, 2}

    def test_gap_scan_ignores_negative_levels(self) -> None:
        """Negative levels are reported by the separate check, not the gap scan.

        The sorted set filters ``s.level >= 0``, so a negative level never
        anchors a gap range — without the filter, ``sorted({-1, 0, 2})`` would
        try to enumerate the gap between -1 and 0 (there is none) but would
        mask the gap between 0 and 2 if the code expected a contiguous sequence
        starting from the minimum.
        """
        hierarchy = SupervisorHierarchy(trust_root=_root())
        hierarchy.register_supervisor('neg', level=-1, is_agent=True)
        hierarchy.register_supervisor('root', level=0, is_agent=False)
        hierarchy.register_supervisor('leaf', level=2, is_agent=True)
        violations = hierarchy.validate_hierarchy()
        gap_violations = [v for v in violations if 'has no registered supervisor' in v]
        assert len(gap_violations) == 1
        assert 'Level 1' in gap_violations[0]


class TestTrustRootRejectsOverLimitLevel:
    """``TrustRoot.validate_supervisor`` mirrors the level bound.

    Call chain: ``TrustRoot.validate_supervisor``
    → type-checks *level* (bool, non-int)
    → rejects negatives
    → rejects levels above ``_MAX_SUPERVISOR_LEVEL``
    → checks root determinism.

    The bound is mirrored from ``supervisor.MAX_SUPERVISOR_LEVEL`` (not
    imported, to avoid a circular dependency) so callers that validate a
    supervisor config through the trust root before registering it get the same
    protection.
    """

    def test_over_limit_level_is_rejected(self) -> None:
        assert _root().validate_supervisor(
            {'name': 'bad', 'level': MAX_SUPERVISOR_LEVEL + 1, 'is_agent': True}
        ) is False

    def test_level_at_the_limit_is_accepted(self) -> None:
        assert _root().validate_supervisor(
            {'name': 'ok', 'level': MAX_SUPERVISOR_LEVEL, 'is_agent': True}
        ) is True
