# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""Tests for the native-runtime trust authority and supervisor hierarchy."""
from __future__ import annotations
from typing import Any
from agt.policies import PolicyEvaluation
from agent_os.supervisor import SupervisorHierarchy
from agent_os.trust_root import TrustRoot

class _Runtime:
    manifest = None

    def evaluate(self, intervention_point: str, snapshot: dict[str, Any]) -> PolicyEvaluation:
        denied = 'delete_file' in str(snapshot) or 'DROP TABLE' in str(snapshot)
        return PolicyEvaluation(verdict='deny' if denied else 'allow', reason_code='restricted_action' if denied else '', message='Action denied by trust authority' if denied else '', intervention_point=intervention_point)

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
