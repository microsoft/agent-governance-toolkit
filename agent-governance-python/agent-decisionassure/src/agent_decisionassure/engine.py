import logging
import uuid
import ast
import operator
from typing import List, Dict, Any, Optional
from datetime import datetime, timezone

from .models.trace import TraceBatch, DecisionTrace
from .models.admissibility import GovernanceState
from .models.impact import ImpactReport, TransitionCounts, BlastRadius

logger = logging.getLogger(__name__)

# Safe operators for policy evaluation
SAFE_OPERATORS = {
    ast.Add: operator.add,
    ast.Sub: operator.sub,
    ast.Mult: operator.mul,
    ast.Div: operator.truediv,
    ast.FloorDiv: operator.floordiv,
    ast.Mod: operator.mod,
    ast.Pow: operator.pow,
    ast.Lt: operator.lt,
    ast.LtE: operator.le,
    ast.Gt: operator.gt,
    ast.GtE: operator.ge,
    ast.Eq: operator.eq,
    ast.NotEq: operator.ne,
    ast.And: operator.and_,
    ast.Or: operator.or_,
    ast.Not: operator.not_,
    ast.USub: operator.neg,
    ast.In: lambda x, y: x in y,
    ast.NotIn: lambda x, y: x not in y,
    ast.Is: lambda x, y: x is y,
    ast.IsNot: lambda x, y: x is not y,
}


class SafeEvaluator:
    """Safe evaluation of policy conditions without using eval()."""

    def __init__(self, namespace: Dict[str, Any]):
        self.namespace = namespace

    def evaluate(self, expr: str) -> bool:
        """Safely evaluate a condition expression."""
        try:
            tree = ast.parse(expr, mode='eval')
            return self._visit(tree.body)
        except Exception as e:
            logger.warning(f"Failed to evaluate condition '{expr}': {e}")
            return False

    def _visit(self, node):
        if isinstance(node, ast.Constant):
            return node.value
        elif isinstance(node, ast.Name):
            if node.id in self.namespace:
                return self.namespace[node.id]
            raise NameError(f"Name '{node.id}' not found")
        elif isinstance(node, ast.Attribute):
            obj = self._visit(node.value)
            return getattr(obj, node.attr)
        elif isinstance(node, ast.Subscript):
            obj = self._visit(node.value)
            idx = self._visit(node.slice)
            return obj[idx]
        elif isinstance(node, ast.Call):
            func = self._visit(node.func)
            args = [self._visit(arg) for arg in node.args]
            kwargs = {kw.arg: self._visit(kw.value) for kw in node.keywords}
            return func(*args, **kwargs)
        elif isinstance(node, ast.BinOp):
            left = self._visit(node.left)
            right = self._visit(node.right)
            op_type = type(node.op)
            if op_type in SAFE_OPERATORS:
                return SAFE_OPERATORS[op_type](left, right)
            raise TypeError(f"Unsupported operator: {op_type}")
        elif isinstance(node, ast.Compare):
            left = self._visit(node.left)
            for op, comp in zip(node.ops, node.comparators):
                right = self._visit(comp)
                op_type = type(op)
                if op_type in SAFE_OPERATORS:
                    result = SAFE_OPERATORS[op_type](left, right)
                    if not result:
                        return False
                    left = right
                else:
                    raise TypeError(f"Unsupported operator: {op_type}")
            return True
        elif isinstance(node, ast.BoolOp):
            values = [self._visit(v) for v in node.values]
            if isinstance(node.op, ast.And):
                return all(values)
            elif isinstance(node.op, ast.Or):
                return any(values)
        elif isinstance(node, ast.UnaryOp):
            operand = self._visit(node.operand)
            if isinstance(node.op, ast.Not):
                return not operand
            elif isinstance(node.op, ast.USub):
                return -operand
            raise TypeError(f"Unsupported unary operator: {type(node.op)}")
        elif isinstance(node, ast.Lambda):
            def lambda_func(*args):
                return self._visit(node.body)
            return lambda_func
        raise TypeError(f"Unsupported AST node type: {type(node)}")


class ImpactEngine:
    def __init__(self, traces: List[TraceBatch]):
        self.traces = traces

    def evaluate_decision(
        self,
        decision: DecisionTrace,
        policy: Dict[str, Any],
        authority: Dict[str, Any],
        context: Dict[str, Any],
    ) -> GovernanceState:
        model_version = decision.context.get("model_version", "") or decision.model_version or ""

        # Fail closed: missing model data is NOT approved
        if not model_version:
            logger.warning(f"Decision {decision.action.id} has empty model_version; marking inadmissible.")
            model_approved = False
        else:
            model_approved = (
                model_version.startswith("approved_")
                or model_version in ("v1", "v2")
            )

        # Evidence freshness: fail if stale
        max_age = context.get("max_evidence_age_hours", 1.0)  # default 1 hour
        evidence_fresh = decision.evidence_age_hours <= max_age

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

        # Fail closed on stale evidence
        if not evidence_fresh:
            state.mark_inadmissible(f"Evidence is stale ({decision.evidence_age_hours:.1f}h > {max_age:.1f}h threshold)")

        # Policy check
        if not self._evaluate_policy(policy, decision):
            state.mark_inadmissible(f"Policy {state.policy_version} denies this action")

        # Authority check
        if not self._check_authority(authority, decision.authority_chain, decision.action.name, decision.timestamp):
            state.mark_inadmissible("Authority chain invalid or expired")

        # Capability check
        if not self._check_capability(authority, decision.action.tool, decision.tool_permissions_at_time):
            state.mark_inadmissible(
                f"Tool {decision.action.tool} permissions exceed authorized capabilities"
            )

        # Model check (already computed)
        if not model_approved:
            state.mark_inadmissible(f"Model version '{model_version}' not approved")

        logger.debug(
            f"Decision {decision.action.id}: admissible={state.is_admissible}, reason={state.reason}"
        )
        return state

    def _evaluate_policy(self, policy: Dict[str, Any], decision: DecisionTrace) -> bool:
        rules = policy.get("rules", [])
        default_effect = policy.get("default_effect", "DENY")

        # Build safe namespace
        namespace = {
            "context": decision.context,
            "action": decision.action,
            "agent_id": str(decision.agent_id),
            "timestamp": decision.timestamp,
            "str": str,
            "int": int,
            "float": float,
            "bool": bool,
            "len": len,
            "list": list,
            "dict": dict,
        }

        for rule in sorted(rules, key=lambda r: r.get("priority", 0), reverse=True):
            condition = rule.get("condition", "")
            effect = rule.get("effect", "DENY")
            if condition:
                evaluator = SafeEvaluator(namespace)
                if evaluator.evaluate(condition):
                    logger.debug(f"Rule matched: {condition} -> {effect}")
                    return effect == "ALLOW"

        logger.debug(f"No rule matched, default: {default_effect}")
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
