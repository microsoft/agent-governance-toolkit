"""Counterfactual impact engine."""
import logging
import uuid
from typing import List, Dict, Any, Optional
from datetime import datetime, timezone

from .models.trace import TraceBatch, DecisionTrace
from .models.admissibility import GovernanceState
from .models.impact import ImpactReport, TransitionCounts, BlastRadius

logger = logging.getLogger(__name__)


class ImpactEngine:
    """Replays historical traces against proposed governance changes."""

    def __init__(self, traces: List[TraceBatch]):
        self.traces = traces

    def evaluate_decision(
        self,
        decision: DecisionTrace,
        policy: Dict[str, Any],
        authority: Dict[str, Any],
        context: Dict[str, Any],
    ) -> GovernanceState:
        """Evaluate a single decision against a governance state."""
        # Extract model_version from context or decision field
        model_version = decision.context.get("model_version", "") or decision.model_version or ""
        if not model_version:
            logger.warning(f"Decision {decision.action.id} has empty model_version; treating as approved.")

        state = GovernanceState(
            policy_version=policy.get("version", "unknown"),
            policy_valid=True,
            authority_valid=True,
            authority_chain=decision.authority_chain,
            evidence_fresh=decision.evidence_age_hours <= context.get("max_evidence_age_hours", 24),
            evidence_age_hours=decision.evidence_age_hours,
            capability_authorized=True,
            tool_permissions=decision.tool_permissions_at_time,
            model_approved=(
                model_version.startswith("approved_")
                or model_version in ("v1", "v2")
                or not model_version
            ),
            model_version=model_version,
            context_valid=True,
            is_admissible=True,
        )

        # 1. Policy check
        if not self._evaluate_policy(policy, decision):
            state.mark_inadmissible(f"Policy {state.policy_version} denies this action")

        # 2. Authority check
        if not self._check_authority(authority, decision.authority_chain, decision.action.name):
            state.mark_inadmissible("Authority chain invalid or expired")

        # 3. Capability check
        if not self._check_capability(authority, decision.action.tool, decision.tool_permissions_at_time):
            state.mark_inadmissible(
                f"Tool {decision.action.tool} permissions exceed authorized capabilities"
            )

        # 4. Model approval
        if not state.model_approved:
            state.mark_inadmissible(f"Model version {model_version} not approved")

        logger.debug(
            f"Decision {decision.action.id}: model_version='{model_version}', "
            f"approved={state.model_approved}, admissible={state.is_admissible}, reason={state.reason}"
        )
        return state

    def _evaluate_policy(self, policy: Dict[str, Any], decision: DecisionTrace) -> bool:
        rules = policy.get("rules", [])
        default_effect = policy.get("default_effect", "DENY")

        if not hasattr(self, "_policy_logged"):
            logger.info(f"Policy rules: {rules}")
            logger.info(f"Default effect: {default_effect}")
            self._policy_logged = True

        for rule in sorted(rules, key=lambda r: r.get("priority", 0), reverse=True):
            condition = rule.get("condition", "")
            effect = rule.get("effect", "DENY")
            if self._evaluate_condition(condition, decision):
                logger.debug(f"Rule matched: {condition} -> {effect}")
                return effect == "ALLOW"

        logger.debug(f"No rule matched, default: {default_effect}")
        return default_effect == "ALLOW"

    def _evaluate_condition(self, condition: str, decision: DecisionTrace) -> bool:
        if not condition:
            return True
        try:
            namespace = {
                "action": decision.action,
                "context": decision.context,
                "agent_id": str(decision.agent_id),
                "timestamp": decision.timestamp,
            }
            builtins = {"True": True, "False": False, "None": None}
            result = bool(eval(condition, {"__builtins__": builtins}, namespace))
            logger.debug(f"Condition '{condition}' evaluated to {result}")
            return result
        except Exception as e:
            logger.warning(f"Condition evaluation failed: {condition} -> {e}")
            return False

    def _check_authority(self, authority: Dict[str, Any], chain: List[str], action_name: str) -> bool:
        delegations = authority.get("delegations", [])
        now = datetime.now(timezone.utc)
        for del_id in chain:
            for d in delegations:
                if d.get("id", "") == del_id and action_name in d.get("permissions", []):
                    valid_from = d.get("valid_from", now)
                    valid_until = d.get("valid_until", now)
                    if valid_from <= now <= valid_until:
                        return True
        return False

    def _check_capability(self, authority: Dict[str, Any], tool_name: str, perms: List[str]) -> bool:
        global_caps = authority.get("global_tool_capabilities", {})
        allowed = global_caps.get(tool_name, [])
        return all(p in allowed for p in perms)

    def analyze_impact(
        self,
        baseline_policy: Dict[str, Any],
        baseline_authority: Dict[str, Any],
        proposed_policy: Dict[str, Any],
        proposed_authority: Dict[str, Any],
    ) -> ImpactReport:
        baseline_results: Dict[str, GovernanceState] = {}
        proposed_results: Dict[str, GovernanceState] = {}
        decisions_by_action: Dict[str, DecisionTrace] = {}

        for trace in self.traces:
            env = trace.environment
            for decision in trace.decisions:
                aid = str(decision.action.id)
                ctx = {**decision.context, **env}
                baseline_results[aid] = self.evaluate_decision(
                    decision, baseline_policy, baseline_authority, ctx
                )
                proposed_results[aid] = self.evaluate_decision(
                    decision, proposed_policy, proposed_authority, ctx
                )
                decisions_by_action[aid] = decision

        total_decisions = len(baseline_results)
        logger.info(f"Evaluated {total_decisions} decisions.")

        transitions = TransitionCounts()
        blast = BlastRadius()
        explanations: Dict[str, str] = {}
        affected_agents = set()
        affected_tools = set()
        affected_policies = set()
        affected_types = set()
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
                    affected_agents.add(str(decision.agent_id))
                    affected_tools.add(decision.action.tool)
                    affected_policies.add(decision.policy_version)
                    affected_types.add(decision.action.name)
                    total_exposure += getattr(decision.action, "transaction_amount", 0.0)

        blast.agents_affected = list(affected_agents)
        blast.tools_affected = list(affected_tools)
        blast.policy_versions_affected = list(affected_policies)
        blast.decision_types_affected = list(affected_types)

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

    def _calculate_severity(self, transitions: TransitionCounts, exposure: float, impact_rate: float) -> str:
        affected = transitions.admissible_to_inadmissible + transitions.inadmissible_to_admissible
        if affected == 0:
            return "LOW"

        score = 0
        if exposure > 10_000_000:
            score += 3
        elif exposure > 1_000_000:
            score += 2
        elif exposure > 100_000:
            score += 1

        if impact_rate > 10:
            score += 2
        elif impact_rate > 5:
            score += 1

        if transitions.inadmissible_to_admissible > 0:
            score += 2
        if transitions.admissible_to_inadmissible > 0:
            score += 1

        if score >= 6:
            return "CRITICAL"
        elif score >= 4:
            return "HIGH"
        elif score >= 2:
            return "MEDIUM"
        else:
            return "LOW"

    def _calculate_recommendation(self, transitions: TransitionCounts, severity: str) -> str:
        affected = transitions.admissible_to_inadmissible + transitions.inadmissible_to_admissible
        if affected == 0:
            return "ALLOW"
        if severity in ("CRITICAL", "HIGH"):
            return "BLOCK"
        if severity == "MEDIUM":
            return "REVIEW"
        return "ALLOW"

    def _build_regression_message(self, transitions: TransitionCounts, proposed_policy: Dict[str, Any]) -> str:
        a2i = transitions.admissible_to_inadmissible
        i2a = transitions.inadmissible_to_admissible
        if a2i > 0 and i2a == 0:
            return f"Previously admissible decisions become inadmissible under {proposed_policy.get('version', 'new policy')}."
        if i2a > 0 and a2i == 0:
            return f"Previously inadmissible decisions become executable under {proposed_policy.get('version', 'new policy')}."
        if a2i == 0 and i2a == 0:
            return "No decision-level governance impact detected."
        return "Policy change introduces both new allowances and restrictions."