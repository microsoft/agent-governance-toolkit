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

def _hierarchy() -> SupervisorHierarchy:
    hierarchy = SupervisorHierarchy(trust_root=_root())
    hierarchy.register_supervisor('trust-root', level=0, is_agent=False)
    hierarchy.register_supervisor('safety-agent', level=1, is_agent=True)
    return hierarchy

@pytest.mark.parametrize('level', [-1, -7])
@pytest.mark.parametrize('is_agent', [True, False])
def test_hierarchy_rejects_negative_levels_before_they_reach_the_authority_chain(
    level: int, is_agent: bool
) -> None:
    hierarchy = _hierarchy()

    with pytest.raises(ValueError, match='must be non-negative'):
        hierarchy.register_supervisor('above-root', level=level, is_agent=is_agent)

    assert hierarchy.get_authority_chain({}) == ['safety-agent', 'trust-root']


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
    """The gap scan must report every missing level between occupied levels.

    Call chain: ``SupervisorHierarchy.validate_hierarchy``
    → builds ``occupied = sorted({s.level for s in self._supervisors if s.level >= 0})``
    → walks adjacent pairs ``(occupied[i-1], occupied[i])``
    → reports every integer in the gap as a missing level.

    The old implementation was ``for lvl in range(1, max_level + 1)``, which is
    O(max_level * n). The new scan costs O(n log n + g), where g counts missing levels.
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
        """Counterexample from review: levels=[3] must report levels 1 and 2
        missing.  Without anchoring at 0 the sorted-set walk starts at the
        minimum occupied level and silently drops gaps below it."""
        hierarchy = SupervisorHierarchy(trust_root=_root())
        hierarchy.register_supervisor('far', level=3, is_agent=True)
        violations = hierarchy.validate_hierarchy()
        gap_violations = [v for v in violations if 'has no registered supervisor' in v]
        missing = {int(v.split('Level ')[1].split(' ')[0]) for v in gap_violations}
        assert missing == {0, 1, 2}



class TestTrustRootRejectsOverLimitLevel:
    """``TrustRoot.validate_supervisor`` mirrors the level bound.

    Call chain: ``TrustRoot.validate_supervisor``
    → type-checks *level* (bool, non-int)
    → rejects negatives
    → rejects levels above ``MAX_SUPERVISOR_LEVEL``
    → checks root determinism.

    Both modules import the same bound from ``_supervisor_constants`` so callers that validate a
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
