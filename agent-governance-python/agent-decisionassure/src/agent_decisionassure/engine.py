# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

import logging
import uuid
from typing import List, Dict, Any
from datetime import datetime, timezone

from .models.trace import TraceBatch, DecisionTrace
from .models.admissibility import GovernanceState
from .models.impact import ImpactReport, TransitionCounts, BlastRadius
from .policy import PolicyError, evaluate_condition, build_env

logger = logging.getLogger(__name__)

# Default evidence-freshness threshold (hours). NOT read from the trace.
DEFAULT_MAX_EVIDENCE_AGE_HOURS = 1.0


class ImpactEngine:
    def __init__(self, traces: List[TraceBatch], max_evidence_age_hours: float = DEFAULT_MAX_EVIDENCE_AGE_HOURS):
        self.traces = traces
        self.max_evidence_age_hours = max_evidence_age_hours

    def evaluate_decision(
        self,
        decision: DecisionTrace,
        policy: Dict[str, Any],
        authority: Dict[str, Any],
        context: Dict[str, Any],
    ) -> GovernanceState:
        model_version = decision.context.get("model_version", "") or decision.model_version or ""

        # Fail closed: missing model data is NOT approved
        model_approved = bool(model_version) and (
            model_version.startswith("approved_") or model_version in ("v1", "v2")
        )

        # Evidence freshness uses the engine-level threshold, not the trace
        evidence_fresh = decision.evidence_age_hours <= self.max_evidence_age_hours

        state = GovernanceState(
            policy_version=policy.get("version", "unknown"),
            policy_valid=True,
            authority_valid=True,
            authority_chain=decision.authority_chain,
            evidence_fresh=evidence_fresh,
            evidence_age_hours=decision.evidence_age_hours,
            capability_authorized=True,
            tool_permissions=decision.tool_permissions_at_time,
            model_approved=model_approved,
            model_version=model_version,
            context_valid=True,
            is_admissible=True,
        )

        if not evidence_fresh:
            state.mark_inadmissible(
                f"Evidence is stale ({decision.evidence_age_hours:.2f}h > {self.max_evidence_age_hours:.2f}h threshold)"
            )

        try:
            if not self._evaluate_policy(policy, decision, context):
                state.mark_inadmissible(f"Policy {state.policy_version} denies this action")
        except PolicyError as exc:
            # Fail closed on malformed policy
            state.mark_inadmissible(f"Policy evaluation error: {exc}")

        if not self._check_authority(authority, decision.authority_chain, decision.action.name, decision.timestamp):
            state.mark_inadmissible("Authority chain invalid or expired")

        if not self._check_capability(authority, decision.action.tool, decision.tool_permissions_at_time):
            state.mark_inadmissible(f"Tool {decision.action.tool} permissions exceed authorized capabilities")

        if not model_approved:
            state.mark_inadmissible(f"Model version '{model_version}' not approved or missing")

        return state

    def _evaluate_policy(self, policy: Dict[str, Any], decision: DecisionTrace, context: Dict[str, Any]) -> bool:
        rules = policy.get("rules", [])
        default_effect = policy.get("default_effect", "DENY")
        env = build_env(decision, context)

        for rule in sorted(rules, key=lambda r: r.get("priority", 0), reverse=True):
            condition = rule.get("condition")
            if condition is None:
                continue
            if evaluate_condition(condition, env):
                return rule.get("effect", "DENY") == "ALLOW"

        return default_effect == "ALLOW"

    def _check_authority(self, authority: Dict[str, Any], chain: List[str], action_name: str, timestamp: datetime) -> bool:
        delegations = authority.get("delegations", [])
        now = timestamp
        for del_id in chain:
            for d in delegations:
                if d.get("id", "") == del_id and action_name in d.get("permissions", []):
                    valid_from = d.get("valid_from", now)
                    valid_until = d.get("valid_until", now)
                    if isinstance(valid_from, str):
                        valid_from = datetime.fromisoformat(valid_from.replace('Z', '+00:00'))
                    if isinstance(valid_until, str):
                        valid_until = datetime.fromisoformat(valid_until.replace('Z', '+00:00'))
                    if valid_from <= now <= valid_until:
                        return True
        return False

    def _check_capability(self, authority: Dict[str, Any], tool_name: str, perms: List[str]) -> bool:
        global_caps = authority.get("global_tool_capabilities", {})
        allowed = global_caps.get(tool_name, [])
        return all(p in allowed for p in perms)

    def analyze_impact(self, baseline_policy, baseline_authority, proposed_policy, proposed_authority) -> ImpactReport:
        baseline_results, proposed_results, decisions_by_action = {}, {}, {}
        for trace in self.traces:
            env = trace.environment
            for decision in trace.decisions:
                aid = str(decision.action.id)
                ctx = {**decision.context, **env}
                baseline_results[aid] = self.evaluate_decision(decision, baseline_policy, baseline_authority, ctx)
                proposed_results[aid] = self.evaluate_decision(decision, proposed_policy, proposed_authority, ctx)
                decisions_by_action[aid] = decision

        total_decisions = len(baseline_results)
        transitions = TransitionCounts()
        blast = BlastRadius()
        explanations: Dict[str, str] = {}
        agents, tools, policies, types = set(), set(), set(), set()
        total_exposure = 0.0

        for aid, base in baseline_results.items():
            prop = proposed_results.get(aid)
            if prop is None:
                continue
            decision = decisions_by_action.get(aid)
            if base.is_admissible == prop.is_admissible:
                transitions.unchanged += 1
            else:
                if base.is_admissible and not prop.is_admissible:
                    transitions.admissible_to_inadmissible += 1
                    explanations[aid] = f"ADMISSIBLE → INADMISSIBLE: {prop.reason}"
                elif not base.is_admissible and prop.is_admissible:
                    transitions.inadmissible_to_admissible += 1
                    explanations[aid] = "INADMISSIBLE → ADMISSIBLE: Previously blocked, now allowed"
                else:
                    transitions.invalidated += 1
                    explanations[aid] = f"Admissibility changed: {base.reason} → {prop.reason}"

                if decision:
                    agents.add(str(decision.agent_id))
                    tools.add(decision.action.tool)
                    policies.add(decision.policy_version)
                    types.add(decision.action.name)
                    total_exposure += getattr(decision.action, "transaction_amount", 0.0) or 0.0

        blast.agents_affected = list(agents)
        blast.tools_affected = list(tools)
        blast.policy_versions_affected = list(policies)
        blast.decision_types_affected = list(types)

        affected_count = transitions.admissible_to_inadmissible + transitions.inadmissible_to_admissible
        impact_rate = (affected_count / total_decisions * 100) if total_decisions else 0.0
        severity = self._calculate_severity(transitions, total_exposure, impact_rate)
        recommendation = self._calculate_recommendation(transitions, severity)
        primary_regression = self._build_regression_message(transitions, proposed_policy)

        return ImpactReport(
            change_description=f"Policy {baseline_policy.get('version', 'v4')} → {proposed_policy.get('version', 'v5')}",
            baseline_policy_version=baseline_policy.get("version", "v4"),
            proposed_policy_version=proposed_policy.get("version", "v5"),
            total_traces_analyzed=len(self.traces),
            total_decisions_evaluated=total_decisions,
            transitions=transitions,
            blast_radius=blast,
            estimated_exposure=total_exposure,
            impact_rate=impact_rate,
            severity=severity,
            recommendation=recommendation,
            primary_regression=primary_regression,
            per_decision_explanations=explanations,
            report_id=str(uuid.uuid4()),
        )

    def _calculate_severity(self, transitions, exposure, impact_rate) -> str:
        affected = transitions.admissible_to_inadmissible + transitions.inadmissible_to_admissible
        if affected == 0:
            return "LOW"
        score = 0
        if exposure > 10_000_000: score += 3
        elif exposure > 1_000_000: score += 2
        elif exposure > 100_000: score += 1
        if impact_rate > 10: score += 2
        elif impact_rate > 5: score += 1
        if transitions.inadmissible_to_admissible > 0: score += 2
        if transitions.admissible_to_inadmissible > 0: score += 1
        if score >= 6: return "CRITICAL"
        elif score >= 4: return "HIGH"
        elif score >= 2: return "MEDIUM"
        return "LOW"

    def _calculate_recommendation(self, transitions, severity) -> str:
        affected = transitions.admissible_to_inadmissible + transitions.inadmissible_to_admissible
        if affected == 0: return "ALLOW"
        if severity in ("CRITICAL", "HIGH"): return "BLOCK"
        if severity == "MEDIUM": return "REVIEW"
        return "ALLOW"

    def _build_regression_message(self, transitions, proposed_policy) -> str:
        a2i = transitions.admissible_to_inadmissible
        i2a = transitions.inadmissible_to_admissible
        if a2i > 0 and i2a == 0:
            return f"Previously admissible decisions become inadmissible under {proposed_policy.get('version', 'new policy')}."
        if i2a > 0 and a2i == 0:
            return f"Previously inadmissible decisions become executable under {proposed_policy.get('version', 'new policy')}."
        if a2i == 0 and i2a == 0:
            return "No decision-level governance impact detected."
        return "Policy change introduces both new allowances and restrictions."
