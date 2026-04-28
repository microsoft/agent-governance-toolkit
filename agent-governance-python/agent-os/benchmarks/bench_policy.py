# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""Benchmarks for policy evaluation."""

from __future__ import annotations

import tempfile
import time
from pathlib import Path
from typing import Any, Dict, List

from agent_os.policies.evaluator import PolicyEvaluator
from agent_os.policies.schema import (
    PolicyAction,
    PolicyCondition,
    PolicyDefaults,
    PolicyDocument,
    PolicyOperator,
    PolicyRule,
)
from agent_os.policies.shared import (
    Condition,
    SharedPolicyEvaluator,
    SharedPolicyRule,
)


def _sync_timer(func, iterations: int = 10_000) -> Dict[str, Any]:
    """Run a synchronous function *iterations* times and return latency stats."""
    latencies: List[float] = []
    for _ in range(iterations):
        start = time.perf_counter()
        func()
        latencies.append((time.perf_counter() - start) * 1_000)
    latencies.sort()
    total_seconds = sum(latencies) / 1_000
    return {
        "iterations": iterations,
        "total_seconds": round(total_seconds, 4),
        "ops_per_sec": round(iterations / total_seconds) if total_seconds > 0 else 0,
        "p50_ms": round(latencies[len(latencies) // 2], 4),
        "p95_ms": round(latencies[int(len(latencies) * 0.95)], 4),
        "p99_ms": round(latencies[int(len(latencies) * 0.99)], 4),
    }


def _make_policy_doc(num_rules: int) -> PolicyDocument:
    """Create a PolicyDocument with *num_rules* rules."""
    rules = [
        PolicyRule(
            name=f"rule-{i}",
            condition=PolicyCondition(
                field="action",
                operator=PolicyOperator.EQ,
                value=f"action_{i}",
            ),
            action=PolicyAction.DENY if i % 3 == 0 else PolicyAction.ALLOW,
            priority=i,
        )
        for i in range(num_rules)
    ]
    return PolicyDocument(
        version="1.0",
        name=f"bench-policy-{num_rules}",
        rules=rules,
        defaults=PolicyDefaults(action=PolicyAction.ALLOW),
    )


def bench_single_rule_evaluation(iterations: int = 10_000) -> Dict[str, Any]:
    """Benchmark evaluating a single-rule policy."""
    evaluator = PolicyEvaluator(policies=[_make_policy_doc(1)])
    ctx = {"action": "action_0", "agent_id": "bench"}

    return {"name": "Single Rule Evaluation", **_sync_timer(lambda: evaluator.evaluate(ctx), iterations)}


def bench_10_rule_policy(iterations: int = 10_000) -> Dict[str, Any]:
    """Benchmark evaluating a 10-rule policy."""
    evaluator = PolicyEvaluator(policies=[_make_policy_doc(10)])
    ctx = {"action": "action_9", "agent_id": "bench"}

    return {"name": "Policy Evaluation (10 rules)", **_sync_timer(lambda: evaluator.evaluate(ctx), iterations)}


def bench_100_rule_policy(iterations: int = 10_000) -> Dict[str, Any]:
    """Benchmark evaluating a 100-rule policy."""
    evaluator = PolicyEvaluator(policies=[_make_policy_doc(100)])
    ctx = {"action": "action_99", "agent_id": "bench"}

    return {"name": "Policy Evaluation (100 rules)", **_sync_timer(lambda: evaluator.evaluate(ctx), iterations)}


def bench_yaml_policy_load(iterations: int = 1_000) -> Dict[str, Any]:
    """Benchmark loading a policy from YAML."""
    try:
        import yaml
    except ImportError:
        return {"name": "YAML Policy Load", "skipped": True, "reason": "pyyaml not installed"}

    doc = _make_policy_doc(10)
    with tempfile.NamedTemporaryFile(mode="w", suffix=".yaml", delete=False) as f:
        yaml.dump(
            {
                "version": doc.version,
                "name": doc.name,
                "rules": [
                    {
                        "name": r.name,
                        "condition": {
                            "field": r.condition.field,
                            "operator": r.condition.operator.value,
                            "value": r.condition.value,
                        },
                        "action": r.action.value,
                        "priority": r.priority,
                    }
                    for r in doc.rules
                ],
            },
            f,
        )
        yaml_path = f.name

    def load() -> None:
        PolicyDocument.from_yaml(yaml_path)

    result = {"name": "YAML Policy Load", **_sync_timer(load, iterations)}
    Path(yaml_path).unlink(missing_ok=True)
    return result


def bench_shared_policy_evaluation(iterations: int = 10_000) -> Dict[str, Any]:
    """Benchmark SharedPolicyEvaluator cross-project evaluation."""
    evaluator = SharedPolicyEvaluator()
    rules = [
        SharedPolicyRule(
            id=f"shared-{i}",
            action="deny" if i % 3 == 0 else "allow",
            conditions=[Condition(field="agent_id", operator="eq", value=f"agent-{i}")],
            priority=i,
        )
        for i in range(10)
    ]
    ctx = {"agent_id": "agent-9", "action": "query"}

    return {
        "name": "SharedPolicy Cross-Project Eval",
        **_sync_timer(lambda: evaluator.evaluate(ctx, rules), iterations),
    }


def run_all() -> List[Dict[str, Any]]:
    """Run all policy benchmarks and return results."""
    return [
        bench_single_rule_evaluation(),
        bench_10_rule_policy(),
        bench_100_rule_policy(),
        bench_yaml_policy_load(),
        bench_shared_policy_evaluation(),
    ]


if __name__ == "__main__":
    import json

    for result in run_all():
        print(json.dumps(result, indent=2))
