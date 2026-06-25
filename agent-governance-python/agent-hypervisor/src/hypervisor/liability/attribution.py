# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
# Public Preview — basic implementation
"""
Fault attribution.

Distributes saga-failure liability across the agents whose failed actions
precede the declared failure step, plus a bonus for the direct cause. This is a
deterministic heuristic (failed-action accounting), NOT a game-theoretic Shapley
value: ``agent_actions`` carries no causal-graph edges or timestamps, so actions
are ordered by ``step_id`` (treated as execution order) to decide which failures
are upstream of the failure vs downstream cascade. An optional caller
``risk_weights`` map overrides the heuristic only when it covers every
participating agent.
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from datetime import UTC, datetime


@dataclass
class FaultAttribution:
    """Fault attribution for an agent."""

    agent_did: str
    liability_score: float
    causal_contribution: float
    is_direct_cause: bool = False
    reason: str = ""


@dataclass
class AttributionResult:
    """Attribution result for a saga failure."""

    attribution_id: str = field(default_factory=lambda: f"attr:{uuid.uuid4().hex[:8]}")
    saga_id: str = ""
    session_id: str = ""
    timestamp: datetime = field(default_factory=lambda: datetime.now(UTC))
    attributions: list[FaultAttribution] = field(default_factory=list)
    causal_chain_length: int = 0
    root_cause_agent: str | None = None

    @property
    def agents_involved(self) -> list[str]:
        return [a.agent_did for a in self.attributions]

    def get_liability(self, agent_did: str) -> float:
        for a in self.attributions:
            if a.agent_did == agent_did:
                return a.liability_score
        return 0.0


class CausalAttributor:
    """Distributes fault liability across the causal chain of a saga failure."""

    DIRECT_CAUSE_BONUS = 1.0

    def __init__(self) -> None:
        self._history: list[AttributionResult] = []

    def attribute(
        self,
        saga_id: str,
        session_id: str,
        agent_actions: dict[str, list[dict]],
        failure_step_id: str,
        failure_agent_did: str,
        risk_weights: dict[str, float] | None = None,
    ) -> AttributionResult:
        """Attribute liability for a saga failure.

        Orders ``agent_actions`` by ``step_id`` and truncates at the failure
        action (``failure_agent_did`` at ``failure_step_id``); each FAILED action
        on that prefix earns weight, plus a ``DIRECT_CAUSE_BONUS`` for the direct
        cause, normalized to sum 1.0. Downstream (post-failure-step) actions are
        excluded as cascade. ``risk_weights`` override the heuristic ONLY when the
        map covers every participating agent (so a partial map cannot silently
        exonerate a failed agent); otherwise it is ignored and the causal split is
        used. The result is independent of ``agent_actions`` key/insertion order.
        """
        agents = list(agent_actions.keys())

        if not agents:
            result = AttributionResult(
                saga_id=saga_id,
                session_id=session_id,
                attributions=[],
                causal_chain_length=0,
                root_cause_agent=failure_agent_did,
            )
            self._history.append(result)
            return result

        chain = self._causal_chain(agent_actions, failure_step_id, failure_agent_did)

        # Causal contribution: failed actions on the chain, plus direct-cause bonus.
        # When the direct cause participates, the bonus guarantees it positive
        # weight, so "full liability to the direct cause" emerges naturally when no
        # other agent failed — there is no separate fallback branch.
        causal_raw: dict[str, float] = dict.fromkeys(agents, 0.0)
        failed_on_chain = 0
        for agent_did, action in chain:
            if not action.get("success", True):
                causal_raw[agent_did] += 1.0
                failed_on_chain += 1
        if failure_agent_did in causal_raw:
            causal_raw[failure_agent_did] += self.DIRECT_CAUSE_BONUS
        causal_total = sum(causal_raw.values())
        causal_contribution = {
            a: (causal_raw[a] / causal_total if causal_total else 0.0) for a in agents
        }

        # risk_weights override only if they cover EVERY participating agent and
        # carry positive mass; a partial map falls through to the causal split.
        weight_total = 0.0
        full_coverage = risk_weights is not None and all(a in risk_weights for a in agents)
        if full_coverage:
            weight_raw = {a: max(0.0, risk_weights[a]) for a in agents}
            weight_total = sum(weight_raw.values())

        if full_coverage and weight_total > 0:
            liability = {a: weight_raw[a] / weight_total for a in agents}
            mode = "risk-weighted"
        elif causal_total > 0:
            liability = dict(causal_contribution)
            mode = "causal-chain"
        else:
            # No participating agent is identifiable as a cause (direct cause
            # absent and nothing failed on the chain): attribute nothing.
            liability = dict.fromkeys(agents, 0.0)
            mode = "no-attribution"

        attributions = []
        for agent_did in agents:
            is_direct = agent_did == failure_agent_did
            score = liability[agent_did]
            if is_direct:
                reason = f"Direct cause ({mode})"
            elif score > 0:
                reason = f"Causal contributor ({mode})"
            else:
                reason = "No causal contribution"
            attributions.append(
                FaultAttribution(
                    agent_did=agent_did,
                    liability_score=score,
                    causal_contribution=causal_contribution[agent_did],
                    is_direct_cause=is_direct,
                    reason=reason,
                )
            )

        result = AttributionResult(
            saga_id=saga_id,
            session_id=session_id,
            attributions=attributions,
            causal_chain_length=failed_on_chain,
            root_cause_agent=failure_agent_did,
        )
        self._history.append(result)
        return result

    @staticmethod
    def _causal_chain(
        agent_actions: dict[str, list[dict]],
        failure_step_id: str,
        failure_agent_did: str,
    ) -> list[tuple[str, dict]]:
        """Order actions by ``step_id`` and truncate at the failure action.

        ``agent_actions`` has no timestamps, so ``step_id`` is the only available
        ordering signal and is treated as execution order. Flattened actions are
        sorted by ``(step_id, original_index)`` — a STABLE, insertion-order
        INDEPENDENT order — then truncated at the failure action (exact
        ``failure_agent_did`` + ``failure_step_id`` match preferred, else the first
        action carrying ``failure_step_id``). Actions sorting after the failure are
        downstream cascade and excluded. If the failure step is not found, the
        whole ordered list is the chain.

        NOTE: this assumes ``step_id`` values sort into execution order. Callers
        whose step ids do not encode order should pass risk_weights instead.
        """
        flat: list[tuple[str, dict]] = [
            (agent_did, action)
            for agent_did, actions in agent_actions.items()
            for action in actions
        ]
        ordered = sorted(
            enumerate(flat), key=lambda item: (str(item[1][1].get("step_id", "")), item[0])
        )
        ordered_flat = [pair for _, pair in ordered]

        fail_idx = None
        for idx, (agent_did, action) in enumerate(ordered_flat):
            if agent_did == failure_agent_did and action.get("step_id") == failure_step_id:
                fail_idx = idx
                break
        if fail_idx is None:
            for idx, (_, action) in enumerate(ordered_flat):
                if action.get("step_id") == failure_step_id:
                    fail_idx = idx
                    break

        if fail_idx is None:
            return ordered_flat
        return ordered_flat[: fail_idx + 1]

    @property
    def attribution_history(self) -> list[AttributionResult]:
        return list(self._history)
