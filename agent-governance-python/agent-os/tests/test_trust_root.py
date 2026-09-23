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
