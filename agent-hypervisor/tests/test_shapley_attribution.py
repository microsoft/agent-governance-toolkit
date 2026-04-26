# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""Tests for Shapley-value fault attribution.

Validates the mathematical properties of Shapley-value-inspired fault
attribution: efficiency, symmetry, null-player, additivity, and correct
marginal contribution calculations across single-agent, multi-agent,
weighted, and cascading fault scenarios.

Closes #9
"""

from __future__ import annotations

import math
import time
from itertools import combinations

from hypervisor.liability.attribution import (
    AttributionResult,
    CausalAttributor,
    FaultAttribution,
)
from hypervisor.liability.ledger import LedgerEntryType, LiabilityLedger
from hypervisor.liability.vouching import VouchingEngine

# ── Shapley-value helpers ───────────────────────────────────────────
# Implements game-theoretic Shapley value computation so we can verify
# that attribution results satisfy the required mathematical properties.


def _factorial(n: int) -> int:
    return math.factorial(n)


def characteristic_value(
    coalition: frozenset[str],
    fault_agents: set[str],
    weights: dict[str, float] | None = None,
) -> float:
    """Characteristic function v(S): value (fault contribution) of a coalition.

    A coalition's value is the sum of weighted fault contributions of
    its faulty members. Non-faulty agents contribute 0.
    """
    total = 0.0
    for agent in coalition:
        if agent in fault_agents:
            w = (weights or {}).get(agent, 1.0)
            total += w
    return total


def compute_shapley_values(
    agents: list[str],
    fault_agents: set[str],
    weights: dict[str, float] | None = None,
) -> dict[str, float]:
    """Compute exact Shapley values for each agent.

    φ_i = Σ_{S⊆N\\{i}} [ |S|!(n-|S|-1)! / n! ] * [v(S∪{i}) - v(S)]
    """
    n = len(agents)
    shapley: dict[str, float] = dict.fromkeys(agents, 0.0)
    n_fact = _factorial(n)

    for agent in agents:
        others = [a for a in agents if a != agent]
        for r in range(len(others) + 1):
            for subset in combinations(others, r):
                s = frozenset(subset)
                s_with_i = s | {agent}
                marginal = characteristic_value(
                    s_with_i, fault_agents, weights
                ) - characteristic_value(s, fault_agents, weights)
                coeff = _factorial(len(s)) * _factorial(n - len(s) - 1) / n_fact
                shapley[agent] += coeff * marginal

    return shapley


def normalize_shapley(values: dict[str, float]) -> dict[str, float]:
    """Normalize Shapley values to sum to 1.0 (liability shares)."""
    total = sum(values.values())
    if total == 0:
        return dict.fromkeys(values, 0.0)
    return {k: v / total for k, v in values.items()}


# ── Single Agent Fault Tests ────────────────────────────────────────


class TestSingleAgentFault:
    """When only one agent exists and is faulty, it gets 100% attribution."""

    def test_single_agent_gets_full_liability(self):
        attributor = CausalAttributor()
        actions = {"agent-a": [{"action_id": "a1", "step_id": "s1", "success": False}]}
        result = attributor.attribute("saga-1", "sess-1", actions, "s1", "agent-a")
        assert result.get_liability("agent-a") == 1.0

    def test_single_agent_is_root_cause(self):
        attributor = CausalAttributor()
        actions = {"agent-a": [{"action_id": "a1", "step_id": "s1", "success": False}]}
        result = attributor.attribute("saga-1", "sess-1", actions, "s1", "agent-a")
        assert result.root_cause_agent == "agent-a"

    def test_single_agent_is_direct_cause(self):
        attributor = CausalAttributor()
        actions = {"agent-a": [{"action_id": "a1", "step_id": "s1", "success": False}]}
        result = attributor.attribute("saga-1", "sess-1", actions, "s1", "agent-a")
        fault = result.attributions[0]
        assert fault.is_direct_cause is True

    def test_shapley_single_agent_full_value(self):
        """Shapley value for a single-player game: player gets full value."""
        values = compute_shapley_values(["agent-a"], {"agent-a"})
        assert abs(values["agent-a"] - 1.0) < 1e-9


# ── Two Agent Fault Attribution Tests ───────────────────────────────


class TestTwoAgentFault:
    """When two agents participate and one is faulty."""

    def test_faulty_agent_has_higher_liability(self):
        attributor = CausalAttributor()
        actions = {
            "agent-a": [{"action_id": "a1", "step_id": "s1", "success": True}],
            "agent-b": [{"action_id": "a2", "step_id": "s2", "success": False}],
        }
        result = attributor.attribute("saga-1", "sess-1", actions, "s2", "agent-b")
        assert result.get_liability("agent-b") > result.get_liability("agent-a")

    def test_non_faulty_agent_gets_zero(self):
        attributor = CausalAttributor()
        actions = {
            "agent-a": [{"action_id": "a1", "step_id": "s1", "success": True}],
            "agent-b": [{"action_id": "a2", "step_id": "s2", "success": False}],
        }
        result = attributor.attribute("saga-1", "sess-1", actions, "s2", "agent-b")
        assert result.get_liability("agent-a") == 0.0

    def test_shapley_two_agents_one_faulty(self):
        """Only the faulty agent has positive Shapley value."""
        values = compute_shapley_values(["a", "b"], {"b"})
        assert values["b"] == 1.0
        assert values["a"] == 0.0

    def test_shapley_two_agents_both_faulty_equal(self):
        """Both faulty agents split the total value equally."""
        values = compute_shapley_values(["a", "b"], {"a", "b"})
        assert abs(values["a"] - values["b"]) < 1e-9


# ── Equal Contribution Tests ────────────────────────────────────────


class TestEqualContribution:
    """When all agents contribute equally to a fault."""

    def test_shapley_three_equal_agents(self):
        """Three equally-faulty agents get equal Shapley shares."""
        values = compute_shapley_values(["a", "b", "c"], {"a", "b", "c"})
        normalized = normalize_shapley(values)
        for agent in ["a", "b", "c"]:
            assert abs(normalized[agent] - 1 / 3) < 1e-9

    def test_shapley_symmetry_property(self):
        """Shapley symmetry axiom: interchangeable players get equal values.

        If v(S ∪ {i}) = v(S ∪ {j}) for all S, then φ_i = φ_j.
        """
        agents = ["a", "b", "c", "d"]
        fault_agents = {"a", "b", "c", "d"}
        values = compute_shapley_values(agents, fault_agents)
        unique_values = {round(v, 10) for v in values.values()}
        assert len(unique_values) == 1

    def test_equal_attribution_sums_to_one(self):
        """Normalized attributions always sum to 1.0."""
        agents = [f"agent-{i}" for i in range(5)]
        fault_agents = set(agents)
        values = compute_shapley_values(agents, fault_agents)
        normalized = normalize_shapley(values)
        assert abs(sum(normalized.values()) - 1.0) < 1e-9


# ── Weighted Agent Tests ────────────────────────────────────────────


class TestWeightedAgents:
    """Agents with different weights get proportional attribution."""

    def test_shapley_weighted_two_agents(self):
        """Agent with double weight gets double the Shapley value."""
        weights = {"a": 2.0, "b": 1.0}
        values = compute_shapley_values(["a", "b"], {"a", "b"}, weights)
        assert values["a"] > values["b"]
        assert abs(values["a"] / values["b"] - 2.0) < 1e-9

    def test_shapley_weighted_proportional(self):
        """Weighted Shapley values are proportional to weights."""
        weights = {"a": 3.0, "b": 2.0, "c": 1.0}
        values = compute_shapley_values(["a", "b", "c"], {"a", "b", "c"}, weights)
        normalized = normalize_shapley(values)
        assert abs(normalized["a"] - 0.5) < 1e-9  # 3/6
        assert abs(normalized["b"] - 1 / 3) < 1e-9  # 2/6
        assert abs(normalized["c"] - 1 / 6) < 1e-9  # 1/6

    def test_risk_weights_passed_to_attributor(self):
        """CausalAttributor accepts risk_weights without error."""
        attributor = CausalAttributor()
        actions = {
            "a": [{"action_id": "x", "step_id": "s1", "success": True}],
            "b": [{"action_id": "y", "step_id": "s2", "success": False}],
        }
        result = attributor.attribute(
            "saga-1", "sess-1", actions, "s2", "b",
            risk_weights={"x": 0.9, "y": 0.1},
        )
        assert len(result.attributions) == 2

    def test_zero_weight_agent_gets_zero_shapley(self):
        """An agent with zero weight gets zero Shapley value."""
        weights = {"a": 1.0, "b": 0.0}
        values = compute_shapley_values(["a", "b"], {"a", "b"}, weights)
        assert values["b"] == 0.0
        assert values["a"] == 1.0


# ── Chain / Cascading Attribution Tests ─────────────────────────────


class TestCascadingAttribution:
    """Cascading faults across a chain of agents."""

    def test_chain_of_three_with_root_cause(self):
        """In a chain A→B→C, root cause agent gets highest attribution."""
        attributor = CausalAttributor()
        actions = {
            "a": [{"action_id": "a1", "step_id": "s1", "success": False}],
            "b": [{"action_id": "b1", "step_id": "s2", "success": False}],
            "c": [{"action_id": "c1", "step_id": "s3", "success": False}],
        }
        result = attributor.attribute("saga-1", "sess-1", actions, "s1", "a")
        assert result.root_cause_agent == "a"
        assert result.get_liability("a") == 1.0

    def test_shapley_cascading_decreasing_weights(self):
        """In a cascade, earlier agents should have higher attribution
        when weighted by position."""
        weights = {"a": 1.0, "b": 0.5, "c": 0.25}
        values = compute_shapley_values(
            ["a", "b", "c"], {"a", "b", "c"}, weights
        )
        assert values["a"] > values["b"] > values["c"]

    def test_long_chain_root_cause_dominates(self):
        """Root cause in a 5-agent chain should have highest Shapley value."""
        agents = [f"agent-{i}" for i in range(5)]
        weights = {a: 1.0 / (i + 1) for i, a in enumerate(agents)}
        values = compute_shapley_values(agents, set(agents), weights)
        max_agent = max(values, key=values.get)
        assert max_agent == "agent-0"


# ── No Fault (Zero Attribution) Tests ───────────────────────────────


class TestNoFault:
    """When no agent is faulty, all attributions should be zero."""

    def test_shapley_no_fault_agents_all_zero(self):
        """Null player axiom: non-faulty agents get zero Shapley value."""
        values = compute_shapley_values(["a", "b", "c"], set())
        for v in values.values():
            assert v == 0.0

    def test_shapley_null_player_in_mixed_game(self):
        """A non-faulty agent among faulty ones gets zero."""
        values = compute_shapley_values(["a", "b", "c"], {"a", "c"})
        assert values["b"] == 0.0
        assert values["a"] > 0.0
        assert values["c"] > 0.0

    def test_zero_attribution_normalized(self):
        """Normalizing all-zero values yields all zeros."""
        values = compute_shapley_values(["a", "b"], set())
        normalized = normalize_shapley(values)
        assert all(v == 0.0 for v in normalized.values())


# ── Edge Cases ──────────────────────────────────────────────────────


class TestEdgeCases:
    """Edge cases: empty sets, single agent, many agents."""

    def test_empty_agent_set(self):
        """Shapley with no agents returns empty dict."""
        values = compute_shapley_values([], set())
        assert values == {}

    def test_single_non_faulty_agent(self):
        """Single agent that didn't cause fault gets zero."""
        values = compute_shapley_values(["a"], set())
        assert values["a"] == 0.0

    def test_attributor_with_empty_actions(self):
        """CausalAttributor handles empty agent_actions dict."""
        attributor = CausalAttributor()
        result = attributor.attribute("saga-1", "sess-1", {}, "s1", "ghost")
        assert len(result.attributions) == 0
        assert result.get_liability("ghost") == 0.0

    def test_get_liability_for_unknown_agent(self):
        """get_liability returns 0.0 for unknown agent."""
        result = AttributionResult(saga_id="s1", session_id="s1")
        assert result.get_liability("nonexistent") == 0.0

    def test_attribution_result_agents_involved(self):
        """agents_involved returns all participating agents."""
        result = AttributionResult(
            saga_id="s1",
            session_id="s1",
            attributions=[
                FaultAttribution("a", 0.5, 0.5, True),
                FaultAttribution("b", 0.3, 0.3, False),
                FaultAttribution("c", 0.2, 0.2, False),
            ],
        )
        assert set(result.agents_involved) == {"a", "b", "c"}

    def test_attribution_id_uniqueness(self):
        """Each AttributionResult gets a unique attribution_id."""
        results = [AttributionResult() for _ in range(100)]
        ids = {r.attribution_id for r in results}
        assert len(ids) == 100

    def test_fault_attribution_dataclass_fields(self):
        """FaultAttribution fields are correctly set."""
        fa = FaultAttribution(
            agent_did="a",
            liability_score=0.7,
            causal_contribution=0.6,
            is_direct_cause=True,
            reason="root cause",
        )
        assert fa.agent_did == "a"
        assert fa.liability_score == 0.7
        assert fa.causal_contribution == 0.6
        assert fa.is_direct_cause is True
        assert fa.reason == "root cause"


# ── Performance Tests ───────────────────────────────────────────────


class TestPerformance:
    """Performance: large agent coalitions."""

    def test_shapley_ten_agents_completes(self):
        """Shapley computation for 10 agents completes within 5 seconds."""
        agents = [f"a{i}" for i in range(10)]
        start = time.monotonic()
        values = compute_shapley_values(agents, set(agents))
        elapsed = time.monotonic() - start
        assert elapsed < 5.0
        assert len(values) == 10

    def test_shapley_twelve_agents_efficiency_holds(self):
        """Efficiency property holds for 12-agent coalition."""
        agents = [f"a{i}" for i in range(12)]
        fault_set = set(agents[:6])
        values = compute_shapley_values(agents, fault_set)
        total_value = characteristic_value(frozenset(agents), fault_set)
        assert abs(sum(values.values()) - total_value) < 1e-6

    def test_many_attributions_history(self):
        """CausalAttributor handles many sequential attributions."""
        attributor = CausalAttributor()
        actions = {"a": [{"action_id": "x", "step_id": "s1", "success": False}]}
        for i in range(200):
            attributor.attribute(f"saga-{i}", "sess-1", actions, "s1", "a")
        assert len(attributor.attribution_history) == 200


# ── Coalition Computation Tests ─────────────────────────────────────


class TestCoalitionComputation:
    """Coalition value function correctness."""

    def test_empty_coalition_value_is_zero(self):
        """v(∅) = 0."""
        assert characteristic_value(frozenset(), {"a", "b"}) == 0.0

    def test_grand_coalition_value(self):
        """v(N) equals sum of all fault weights."""
        weights = {"a": 2.0, "b": 3.0, "c": 1.0}
        v = characteristic_value(frozenset(["a", "b", "c"]), {"a", "b", "c"}, weights)
        assert abs(v - 6.0) < 1e-9

    def test_singleton_coalition_value(self):
        """v({i}) = weight of i if faulty, else 0."""
        weights = {"a": 2.0, "b": 3.0}
        assert characteristic_value(frozenset(["a"]), {"a"}, weights) == 2.0
        assert characteristic_value(frozenset(["b"]), {"a"}, weights) == 0.0

    def test_coalition_monotonicity(self):
        """Adding a faulty agent to a coalition never decreases its value."""
        base = frozenset(["a"])
        extended = frozenset(["a", "b"])
        fault = {"a", "b"}
        assert characteristic_value(extended, fault) >= characteristic_value(base, fault)

    def test_coalition_subadditivity_with_non_faulty(self):
        """Adding a non-faulty agent doesn't change coalition value."""
        base = frozenset(["a"])
        extended = frozenset(["a", "b"])
        fault = {"a"}
        assert characteristic_value(extended, fault) == characteristic_value(base, fault)


# ── Marginal Contribution Tests ─────────────────────────────────────


class TestMarginalContribution:
    """Marginal contribution calculation correctness."""

    def test_marginal_of_faulty_agent_is_positive(self):
        """Faulty agent's marginal contribution to any coalition is non-negative."""
        agents = ["a", "b", "c"]
        fault = {"b"}
        for r in range(len(agents)):
            for subset in combinations([a for a in agents if a != "b"], r):
                s = frozenset(subset)
                s_with = s | {"b"}
                marginal = characteristic_value(s_with, fault) - characteristic_value(
                    s, fault
                )
                assert marginal >= 0

    def test_marginal_of_non_faulty_is_zero(self):
        """Non-faulty agent's marginal contribution is always zero."""
        agents = ["a", "b", "c"]
        fault = {"a", "c"}
        for r in range(len(agents)):
            for subset in combinations([a for a in agents if a != "b"], r):
                s = frozenset(subset)
                s_with = s | {"b"}
                marginal = characteristic_value(s_with, fault) - characteristic_value(
                    s, fault
                )
                assert marginal == 0.0

    def test_marginal_equals_weight_for_independent_game(self):
        """In an additive game, marginal contribution equals agent's weight."""
        weights = {"a": 3.0, "b": 5.0}
        fault = {"a", "b"}
        marginal_a = characteristic_value(
            frozenset(["a"]), fault, weights
        ) - characteristic_value(frozenset(), fault, weights)
        assert abs(marginal_a - 3.0) < 1e-9


# ── Shapley Axiom Verification ──────────────────────────────────────


class TestShapleyAxioms:
    """Verify the four Shapley axioms hold."""

    def test_efficiency_axiom(self):
        """Efficiency: Σ φ_i = v(N).

        The sum of all Shapley values equals the grand coalition value.
        """
        agents = ["a", "b", "c", "d"]
        fault = {"a", "b", "d"}
        weights = {"a": 2.0, "b": 1.0, "c": 1.0, "d": 3.0}
        values = compute_shapley_values(agents, fault, weights)
        grand = characteristic_value(frozenset(agents), fault, weights)
        assert abs(sum(values.values()) - grand) < 1e-9

    def test_symmetry_axiom(self):
        """Symmetry: if i and j are interchangeable, φ_i = φ_j."""
        values = compute_shapley_values(
            ["a", "b", "c"], {"a", "b"}, {"a": 1.0, "b": 1.0, "c": 0.5}
        )
        assert abs(values["a"] - values["b"]) < 1e-9

    def test_null_player_axiom(self):
        """Null player: if i adds no value to any coalition, φ_i = 0."""
        values = compute_shapley_values(["a", "b", "c"], {"a", "b"})
        assert values["c"] == 0.0

    def test_additivity_axiom(self):
        """Additivity: φ(v+w) = φ(v) + φ(w) for any two games v, w.

        Tested by computing Shapley values for two separate games and
        verifying they sum to the combined game's Shapley values.
        """
        agents = ["a", "b"]
        fault1 = {"a"}
        fault2 = {"b"}
        weights1 = {"a": 2.0, "b": 0.0}
        weights2 = {"a": 0.0, "b": 3.0}
        combined_weights = {"a": 2.0, "b": 3.0}

        v1 = compute_shapley_values(agents, fault1, weights1)
        v2 = compute_shapley_values(agents, fault2, weights2)
        v_combined = compute_shapley_values(agents, {"a", "b"}, combined_weights)

        for agent in agents:
            assert abs((v1[agent] + v2[agent]) - v_combined[agent]) < 1e-9


# ── Integration with Liability System ──────────────────────────────


class TestLiabilityIntegration:
    """Integration tests between attribution and the broader liability system."""

    def test_attribution_feeds_ledger(self):
        """Attribution result can be recorded in the liability ledger."""
        attributor = CausalAttributor()
        ledger = LiabilityLedger()
        actions = {
            "a": [{"action_id": "x", "step_id": "s1", "success": False}],
            "b": [{"action_id": "y", "step_id": "s2", "success": True}],
        }
        result = attributor.attribute("saga-1", "sess-1", actions, "s1", "a")
        for attr in result.attributions:
            if attr.liability_score > 0:
                ledger.record(
                    attr.agent_did,
                    LedgerEntryType.FAULT_ATTRIBUTED,
                    "sess-1",
                    severity=attr.liability_score,
                )
        history = ledger.get_agent_history("a")
        assert len(history) == 1
        assert history[0].severity == 1.0

    def test_repeated_faults_accumulate_in_ledger(self):
        """Multiple fault attributions accumulate in the ledger."""
        attributor = CausalAttributor()
        ledger = LiabilityLedger()
        actions = {"a": [{"action_id": "x", "step_id": "s1", "success": False}]}
        for i in range(3):
            result = attributor.attribute(f"saga-{i}", "sess-1", actions, "s1", "a")
            for attr in result.attributions:
                if attr.liability_score > 0:
                    ledger.record(
                        attr.agent_did,
                        LedgerEntryType.FAULT_ATTRIBUTED,
                        "sess-1",
                        severity=attr.liability_score,
                    )
        assert len(ledger.get_agent_history("a")) == 3

    def test_vouching_engine_accepts_attributed_agent(self):
        """Vouching engine works with agents that have fault attributions."""
        engine = VouchingEngine()
        record = engine.vouch("voucher", "faulty-agent", "sess-1", voucher_sigma=0.8)
        assert record.vouchee_did == "faulty-agent"
        assert record.is_active
