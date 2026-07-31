# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""Tests for the native-runtime trust authority and supervisor hierarchy."""
from __future__ import annotations
import pytest
from agent_control_specification import Decision, InterventionPointResult, Verdict
from agent_os.supervisor import SupervisorHierarchy
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

@pytest.mark.parametrize('level', [0.0, 1.0, 2.5])
def test_a_float_level_is_reported_when_it_is_the_maximum(level: float) -> None:
    """A lone float level used to raise ``TypeError`` out of the gap scan.

    ``validate_supervisor`` accepted a float, and ``range(1, max_level + 1)``
    does not, so a config that got a float past the declaration check crashed at
    the next step. It is now a violation, which is the same answer the rest of
    this method gives for a level it will not govern.
    """
    hierarchy = SupervisorHierarchy(trust_root=_root())
    hierarchy.register_supervisor('root', level=level, is_agent=False)
    assert any('non-integer level' in v for v in hierarchy.validate_hierarchy())


@pytest.mark.parametrize(
    ('level', 'top'),
    [(0.0, 1), (1.0, 2), (0.5, 1), (1.5, 2), (-1.0, 1)],
)
def test_a_float_level_under_an_integer_maximum_is_reported(
    level: float, top: int
) -> None:
    """The case a float-is-always-fatal reading misses, and the reason for the check.

    ``range(1, max_level + 1)`` only raises when the float *is* the maximum. Put
    any higher integer level in the hierarchy and the gap scan never sees the
    float, so none of the other rules apply to it either: ``level == 0`` is False
    for ``0.0``'s neighbours, ``level < 0`` is False for ``0.5``, and the level is
    absent from ``range``. Before the check these returned ``violations == []`` --
    a supervisor at 0.5 sitting between the root and level 1, governed by
    neither, reported as a valid hierarchy. ``-1.0`` is included because the
    negative-level rule did fire for it, but on a value the hierarchy cannot
    order; naming the type is the more accurate violation.
    """
    hierarchy = SupervisorHierarchy(trust_root=_root())
    hierarchy.register_supervisor('root', level=0, is_agent=False)
    hierarchy.register_supervisor('drifted', level=level, is_agent=True)
    hierarchy.register_supervisor('top', level=top, is_agent=True)

    violations = hierarchy.validate_hierarchy()

    assert any('non-integer level' in v and 'drifted' in v for v in violations)


def test_a_string_level_is_reported_instead_of_raising() -> None:
    # '0' == 0 is False, so a string level skipped the determinism rule and then
    # raised out of the `level < 0` comparison. Same class of gap as the float.
    hierarchy = SupervisorHierarchy(trust_root=_root())
    hierarchy.register_supervisor('root', level='0', is_agent=False)  # type: ignore[arg-type]
    hierarchy.register_supervisor('top', level=1, is_agent=True)

    assert any('non-integer level' in v for v in hierarchy.validate_hierarchy())


def test_a_bool_level_is_reported_rather_than_read_as_a_level() -> None:
    # bool subclasses int and False == 0, so `True` would otherwise be governed
    # as level 1 and `False` as the deterministic root.
    hierarchy = SupervisorHierarchy(trust_root=_root())
    hierarchy.register_supervisor('root', level=False, is_agent=False)  # type: ignore[arg-type]

    assert any('non-integer level' in v for v in hierarchy.validate_hierarchy())


def test_an_all_integer_hierarchy_is_unaffected() -> None:
    # The check must not add a violation to a hierarchy that already validated.
    hierarchy = SupervisorHierarchy(trust_root=_root())
    hierarchy.register_supervisor('root', level=0, is_agent=False)
    hierarchy.register_supervisor('mid', level=1, is_agent=True)
    hierarchy.register_supervisor('leaf', level=2, is_agent=True)

    assert hierarchy.validate_hierarchy() == []
