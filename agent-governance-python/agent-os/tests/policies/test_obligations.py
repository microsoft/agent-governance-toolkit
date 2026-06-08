# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""Behavioral tests for constrain-as-obligations and the fail-closed mapping."""

from agent_os.policies.context_accumulation import (
    ContextDecision,
    ContextOutcome,
    to_policy_action,
)
from agent_os.policies.data_classification import DataClassification as DC
from agent_os.policies.obligations import Obligation, ObligationSet
from agent_os.policies.schema import PolicyAction


def _constrain(obligations: ObligationSet) -> ContextDecision:
    return ContextDecision(ContextOutcome.CONSTRAIN, obligations, DC.RESTRICTED, "restricted")


def test_constrain_is_allow_plus_obligations():
    obs = ObligationSet(
        obligations=(Obligation("no_external_export", False),),
        result_labels=frozenset({"pii", "financial"}),
    )
    decision = _constrain(obs)
    # WITH an obligation channel the host carries the obligations -> effective ALLOW
    assert to_policy_action(decision, has_obligation_channel=True) == PolicyAction.ALLOW
    assert len(decision.obligations.obligations) >= 1


def test_python_path_constrain_fails_closed():
    obs = ObligationSet(obligations=(Obligation("no_external_export", False),))
    decision = _constrain(obs)
    # NO obligation channel + unsatisfied obligation -> fail closed to DENY (never ALLOW)
    assert to_policy_action(decision, has_obligation_channel=False) == PolicyAction.DENY


def test_satisfiable_obligation_allows():
    obs = ObligationSet(obligations=(Obligation("no_external_export", True),))
    decision = _constrain(obs)
    # NO channel but every obligation already satisfied -> ALLOW
    assert to_policy_action(decision, has_obligation_channel=False) == PolicyAction.ALLOW


def test_empty_obligation_constrain_fails_closed():
    # A constrain carrying NO obligations must not fail open via vacuous
    # all_satisfied: no channel + no obligations -> DENY.
    decision = _constrain(ObligationSet())
    assert to_policy_action(decision, has_obligation_channel=False) == PolicyAction.DENY
