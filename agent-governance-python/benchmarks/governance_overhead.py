#!/usr/bin/env python3
# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""
Governance Overhead Benchmark (Issue #720)

Measures the latency overhead of agent governance layers by comparing
governed vs ungoverned execution paths. Uses real implementations from
agent-os, agent-mesh, and agent-hypervisor.

Usage:
    py -3.12 benchmarks/governance_overhead.py

Outputs:
    - Console table with p50/p95/p99 latencies
    - benchmarks/results/governance_overhead.json
    - docs/benchmarks/charts/latency_comparison.png
    - docs/benchmarks/charts/overhead_breakdown.png
"""

from __future__ import annotations

import asyncio
import json
import os
import platform
import sys
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable

import numpy as np

# ---------------------------------------------------------------------------
# Path setup — make packages importable from repo root
# ---------------------------------------------------------------------------
_ROOT = Path(__file__).resolve().parent.parent
for _pkg in ("agent-os", "agent-mesh", "agent-hypervisor"):
    sys.path.insert(0, str(_ROOT / "packages" / _pkg / "src"))

# ---------------------------------------------------------------------------
# Agent-OS: policy evaluation
# ---------------------------------------------------------------------------
from agent_os.policies.evaluator import PolicyEvaluator as OSPolicyEvaluator
from agent_os.policies.schema import (
    PolicyAction,
    PolicyCondition,
    PolicyDefaults,
    PolicyDocument,
    PolicyOperator,
    PolicyRule,
)

# ---------------------------------------------------------------------------
# Agent-Mesh: trust policy evaluation, audit logging, credentials
# ---------------------------------------------------------------------------
from agentmesh.governance.trust_policy import (
    ConditionOperator,
    TrustCondition,
    TrustDefaults,
    TrustPolicy,
    TrustRule,
)
from agentmesh.governance.policy_evaluator import (
    PolicyEvaluator as TrustPolicyEvaluator,
)
from agentmesh.governance.audit import AuditLog, MerkleAuditChain
from agentmesh.identity.credentials import Credential, CredentialManager

# ---------------------------------------------------------------------------
# Agent-Hypervisor: ring enforcement, delta audit, session lifecycle
# ---------------------------------------------------------------------------
from hypervisor import Hypervisor, SessionConfig, ExecutionRing
from hypervisor.rings.enforcer import RingEnforcer
from hypervisor.models import ActionDescriptor, ReversibilityLevel
from hypervisor.audit.delta import DeltaEngine, VFSChange
from hypervisor.liability.vouching import VouchingEngine


# ═══════════════════════════════════════════════════════════════════════════
# Benchmark infrastructure
# ═══════════════════════════════════════════════════════════════════════════

ITERATIONS = 1_000
WARMUP = 100


@dataclass
class BenchmarkResult:
    """Stores latency measurements for a single benchmark."""

    name: str
    category: str
    iterations: int
    latencies_ms: list[float] = field(default_factory=list, repr=False)

    @property
    def p50(self) -> float:
        return float(np.percentile(self.latencies_ms, 50))

    @property
    def p95(self) -> float:
        return float(np.percentile(self.latencies_ms, 95))

    @property
    def p99(self) -> float:
        return float(np.percentile(self.latencies_ms, 99))

    @property
    def mean(self) -> float:
        return float(np.mean(self.latencies_ms))

    @property
    def ops_per_sec(self) -> float:
        total_s = sum(self.latencies_ms) / 1_000
        return self.iterations / total_s if total_s > 0 else 0

    def to_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "category": self.category,
            "iterations": self.iterations,
            "p50_ms": round(self.p50, 4),
            "p95_ms": round(self.p95, 4),
            "p99_ms": round(self.p99, 4),
            "mean_ms": round(self.mean, 4),
            "ops_per_sec": round(self.ops_per_sec),
        }


def bench_sync(
    name: str, category: str, func: Callable[[], Any], iterations: int = ITERATIONS
) -> BenchmarkResult:
    """Benchmark a synchronous function."""
    # Warmup
    for _ in range(WARMUP):
        func()

    latencies: list[float] = []
    for _ in range(iterations):
        start = time.perf_counter()
        func()
        latencies.append((time.perf_counter() - start) * 1_000)

    result = BenchmarkResult(
        name=name, category=category, iterations=iterations, latencies_ms=latencies
    )
    return result


def bench_async(
    name: str, category: str, coro_func: Callable, iterations: int = ITERATIONS
) -> BenchmarkResult:
    """Benchmark an async function."""

    async def _run() -> list[float]:
        # Warmup
        for _ in range(WARMUP):
            await coro_func()
        latencies: list[float] = []
        for _ in range(iterations):
            start = time.perf_counter()
            await coro_func()
            latencies.append((time.perf_counter() - start) * 1_000)
        return latencies

    latencies = asyncio.run(_run())
    return BenchmarkResult(
        name=name, category=category, iterations=iterations, latencies_ms=latencies
    )


# ═══════════════════════════════════════════════════════════════════════════
# Fixtures — real objects from the toolkit
# ═══════════════════════════════════════════════════════════════════════════


def _make_os_policy(num_rules: int = 10) -> PolicyDocument:
    """Create an Agent-OS PolicyDocument with N rules."""
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


def _make_trust_policy(num_rules: int = 10) -> TrustPolicy:
    """Create an Agent-Mesh TrustPolicy with N rules."""
    rules = [
        TrustRule(
            name=f"trust-rule-{i}",
            condition=TrustCondition(
                field="trust_score",
                operator=ConditionOperator.gte,
                value=100 * i,
            ),
            action="allow" if i % 2 == 0 else "deny",
            priority=i,
        )
        for i in range(num_rules)
    ]
    return TrustPolicy(
        name="bench-trust-policy",
        rules=rules,
        defaults=TrustDefaults(min_trust_score=500, max_delegation_depth=3),
    )


# ═══════════════════════════════════════════════════════════════════════════
# SECTION 1: Ungoverned baseline — raw function calls with zero governance
# ═══════════════════════════════════════════════════════════════════════════


def run_ungoverned_baselines() -> list[BenchmarkResult]:
    """Measure baseline cost of a trivial agent action with no governance."""
    results: list[BenchmarkResult] = []

    # 1a. Bare function call (no-op action)
    def noop_action():
        _ = {"action": "read_data", "agent_id": "bench", "params": {"key": "val"}}

    results.append(bench_sync("Bare action (no governance)", "baseline", noop_action))

    # 1b. Simulated LLM-tool-call overhead (dict construction + validation)
    def simulated_tool_call():
        request = {
            "action": "read_data",
            "agent_id": "bench-agent",
            "params": {"key": "value", "table": "users"},
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }
        # Simulate minimal validation
        assert request["action"] in ("read_data", "write_data", "delete")
        return {"success": True, "data": [1, 2, 3]}

    results.append(
        bench_sync("Simulated tool call (no governance)", "baseline", simulated_tool_call)
    )

    return results


# ═══════════════════════════════════════════════════════════════════════════
# SECTION 2: Agent-OS policy evaluation overhead
# ═══════════════════════════════════════════════════════════════════════════


def run_policy_benchmarks() -> list[BenchmarkResult]:
    """Benchmark Agent-OS PolicyEvaluator at various rule counts."""
    results: list[BenchmarkResult] = []

    for num_rules in (1, 10, 50, 100):
        evaluator = OSPolicyEvaluator(policies=[_make_os_policy(num_rules)])
        # Context that matches the last rule (worst case — full scan)
        ctx = {"action": f"action_{num_rules - 1}", "agent_id": "bench"}

        results.append(
            bench_sync(
                f"Policy eval ({num_rules} rules)",
                "policy",
                lambda e=evaluator, c=ctx: e.evaluate(c),
            )
        )

    return results


# ═══════════════════════════════════════════════════════════════════════════
# SECTION 3: Agent-Mesh trust policy evaluation
# ═══════════════════════════════════════════════════════════════════════════


def run_trust_benchmarks() -> list[BenchmarkResult]:
    """Benchmark Agent-Mesh TrustPolicyEvaluator."""
    results: list[BenchmarkResult] = []

    for num_rules in (1, 10, 50):
        policy = _make_trust_policy(num_rules)
        evaluator = TrustPolicyEvaluator(policies=[policy])
        ctx = {"trust_score": 750, "delegation_depth": 2, "agent_namespace": "default"}

        results.append(
            bench_sync(
                f"Trust policy eval ({num_rules} rules)",
                "trust",
                lambda e=evaluator, c=ctx: e.evaluate(c),
            )
        )

    return results


# ═══════════════════════════════════════════════════════════════════════════
# SECTION 4: Credential verification overhead
# ═══════════════════════════════════════════════════════════════════════════


def run_credential_benchmarks() -> list[BenchmarkResult]:
    """Benchmark credential issuance and token verification."""
    results: list[BenchmarkResult] = []
    mgr = CredentialManager()

    # Credential issuance
    results.append(
        bench_sync(
            "Credential issuance",
            "credential",
            lambda: mgr.issue(
                "did:mesh:bench",
                capabilities=["read:data", "write:data"],
                ttl_seconds=900,
            ),
        )
    )

    # Token validation (issue once, then validate repeatedly)
    cred = mgr.issue("did:mesh:bench-validate", capabilities=["read:data"])
    token = cred.token

    results.append(
        bench_sync(
            "Token validation",
            "credential",
            lambda: mgr.validate(token),
        )
    )

    # Credential.verify_token (hash comparison only)
    results.append(
        bench_sync(
            "Token hash verify",
            "credential",
            lambda: cred.verify_token(token),
        )
    )

    return results


# ═══════════════════════════════════════════════════════════════════════════
# SECTION 5: Audit logging overhead (Merkle chain)
# ═══════════════════════════════════════════════════════════════════════════


def run_audit_benchmarks() -> list[BenchmarkResult]:
    """Benchmark Agent-Mesh AuditLog with Merkle integrity."""
    results: list[BenchmarkResult] = []

    # Single audit entry write
    audit = AuditLog()
    counter = [0]

    def log_entry():
        counter[0] += 1
        audit.log(
            event_type="tool_invocation",
            agent_did="did:mesh:bench",
            action="read_data",
            resource="/api/data",
            data={"key": "value"},
            outcome="success",
        )

    results.append(bench_sync("Audit log write (Merkle)", "audit", log_entry))

    # Audit chain verify after 100 entries
    chain = MerkleAuditChain()
    from agentmesh.governance.audit import AuditEntry as MeshAuditEntry

    for i in range(100):
        entry = MeshAuditEntry(
            event_type="tool_invocation",
            agent_did="did:mesh:bench",
            action=f"action_{i}",
        )
        chain.add_entry(entry)

    results.append(
        bench_sync(
            "Merkle chain verify (100 entries)",
            "audit",
            lambda: chain.verify_chain(),
        )
    )

    return results


# ═══════════════════════════════════════════════════════════════════════════
# SECTION 6: Hypervisor ring enforcement
# ═══════════════════════════════════════════════════════════════════════════


def run_ring_benchmarks() -> list[BenchmarkResult]:
    """Benchmark hypervisor ring computation and enforcement."""
    results: list[BenchmarkResult] = []
    enforcer = RingEnforcer()

    # Ring computation from trust score
    results.append(
        bench_sync(
            "Ring computation",
            "rings",
            lambda: enforcer.compute_ring(0.85),
            iterations=10_000,
        )
    )

    # Ring enforcement check
    action = ActionDescriptor(
        action_id="deploy-model",
        name="deploy_model",
        execute_api="/api/deploy",
        reversibility=ReversibilityLevel.FULL,
    )
    results.append(
        bench_sync(
            "Ring enforcement check",
            "rings",
            lambda: enforcer.check(
                ExecutionRing.RING_1_PRIVILEGED, action, eff_score=0.85
            ),
            iterations=10_000,
        )
    )

    return results


# ═══════════════════════════════════════════════════════════════════════════
# SECTION 7: Hypervisor delta audit
# ═══════════════════════════════════════════════════════════════════════════


def run_delta_benchmarks() -> list[BenchmarkResult]:
    """Benchmark hypervisor delta capture and hash chain."""
    results: list[BenchmarkResult] = []

    # Delta capture
    counter = [0]

    def capture_delta():
        counter[0] += 1
        de = DeltaEngine(f"bench-{counter[0]}")
        de.capture(
            "did:mesh:bench",
            [VFSChange(path="/data/file.txt", operation="add", content_hash="abc123")],
        )

    results.append(bench_sync("Delta capture", "delta_audit", capture_delta))

    # Hash chain root (10 deltas)
    def hash_chain_10():
        de = DeltaEngine("bench-chain")
        for i in range(10):
            de.capture(
                "did:mesh:bench",
                [VFSChange(path=f"/f{i}", operation="add", content_hash=f"h{i}")],
            )
        de.compute_hash_chain_root()

    results.append(bench_sync("Hash chain root (10 deltas)", "delta_audit", hash_chain_10))

    return results


# ═══════════════════════════════════════════════════════════════════════════
# SECTION 8: Hypervisor session lifecycle (async)
# ═══════════════════════════════════════════════════════════════════════════


def run_session_benchmarks() -> list[BenchmarkResult]:
    """Benchmark hypervisor session create/join/activate/terminate."""
    results: list[BenchmarkResult] = []

    async def session_lifecycle():
        hv = Hypervisor()
        s = await hv.create_session(config=SessionConfig(), creator_did="did:mesh:admin")
        await hv.join_session(s.sso.session_id, "did:mesh:agent", sigma_raw=0.8)
        await hv.activate_session(s.sso.session_id)
        await hv.terminate_session(s.sso.session_id)

    results.append(
        bench_async("Session lifecycle", "hypervisor", session_lifecycle, iterations=500)
    )

    return results


# ═══════════════════════════════════════════════════════════════════════════
# SECTION 9: End-to-end governed vs ungoverned comparison
# ═══════════════════════════════════════════════════════════════════════════


def run_e2e_comparison() -> list[BenchmarkResult]:
    """Compare full governed pipeline vs ungoverned execution."""
    results: list[BenchmarkResult] = []

    # --- Ungoverned path ---
    def ungoverned_action():
        request = {"action": "read_data", "agent_id": "bench", "params": {"key": "v"}}
        return {"success": True, "data": request["params"]}

    results.append(bench_sync("E2E: Ungoverned action", "e2e", ungoverned_action))

    # --- Governed path (policy + trust + audit + ring check) ---
    os_evaluator = OSPolicyEvaluator(policies=[_make_os_policy(10)])
    trust_evaluator = TrustPolicyEvaluator(policies=[_make_trust_policy(5)])
    audit = AuditLog()
    enforcer = RingEnforcer()
    action_desc = ActionDescriptor(
        action_id="read-data",
        name="read_data",
        execute_api="/api/read",
        reversibility=ReversibilityLevel.FULL,
        is_read_only=True,
    )

    def governed_action():
        ctx = {"action": "read_data", "agent_id": "bench", "params": {"key": "v"}}

        # 1. Policy evaluation (Agent-OS)
        policy_decision = os_evaluator.evaluate(ctx)

        # 2. Trust policy evaluation (Agent-Mesh)
        trust_ctx = {"trust_score": 750, "delegation_depth": 1}
        trust_decision = trust_evaluator.evaluate(trust_ctx)

        # 3. Ring enforcement (Hypervisor)
        ring = enforcer.compute_ring(0.85)
        ring_check = enforcer.check(ring, action_desc, eff_score=0.85)

        # 4. Audit logging (Agent-Mesh)
        audit.log(
            event_type="tool_invocation",
            agent_did="did:mesh:bench",
            action="read_data",
            outcome="success" if policy_decision.allowed else "denied",
            policy_decision=policy_decision.action,
        )

        # 5. Execute the actual action
        if policy_decision.allowed and trust_decision.allowed and ring_check.allowed:
            return {"success": True, "data": ctx["params"]}
        return {"success": False, "reason": "governance denied"}

    results.append(bench_sync("E2E: Governed action (full stack)", "e2e", governed_action))

    # --- Governed path (policy only, no audit) ---
    def governed_policy_only():
        ctx = {"action": "read_data", "agent_id": "bench", "params": {"key": "v"}}
        decision = os_evaluator.evaluate(ctx)
        if decision.allowed:
            return {"success": True, "data": ctx["params"]}
        return {"success": False}

    results.append(
        bench_sync("E2E: Governed (policy only)", "e2e", governed_policy_only)
    )

    return results


# ═══════════════════════════════════════════════════════════════════════════
# Output formatting
# ═══════════════════════════════════════════════════════════════════════════


def print_table(results: list[BenchmarkResult]) -> None:
    """Print a formatted results table to stdout."""
    header = f"{'Benchmark':<45} {'p50 (ms)':>10} {'p95 (ms)':>10} {'p99 (ms)':>10} {'ops/sec':>12}"
    sep = "-" * len(header)

    print()
    print("=" * len(header))
    print("  GOVERNANCE OVERHEAD BENCHMARK")
    print("=" * len(header))
    print()

    current_cat = None
    for r in results:
        if r.category != current_cat:
            current_cat = r.category
            print(sep)
            print(f"  [{current_cat.upper()}]")
            print(sep)
            print(header)
            print(sep)
        print(
            f"{r.name:<45} {r.p50:>10.4f} {r.p95:>10.4f} {r.p99:>10.4f} {r.ops_per_sec:>12,.0f}"
        )

    print(sep)
    print()

    # Compute and print overhead summary
    ungoverned = next((r for r in results if r.name == "E2E: Ungoverned action"), None)
    governed = next(
        (r for r in results if r.name == "E2E: Governed action (full stack)"), None
    )
    if ungoverned and governed:
        overhead_p50 = governed.p50 - ungoverned.p50
        overhead_p99 = governed.p99 - ungoverned.p99
        multiplier = governed.p50 / ungoverned.p50 if ungoverned.p50 > 0 else float("inf")
        print(f"  Governance overhead (p50): {overhead_p50:.4f} ms")
        print(f"  Governance overhead (p99): {overhead_p99:.4f} ms")
        print(f"  Overhead multiplier (p50): {multiplier:.1f}x")
        print()


def save_json(results: list[BenchmarkResult], path: Path) -> None:
    """Save raw results to JSON."""
    path.parent.mkdir(parents=True, exist_ok=True)
    data = {
        "benchmark": "governance_overhead",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "python": platform.python_version(),
        "platform": platform.platform(),
        "processor": platform.processor(),
        "iterations": ITERATIONS,
        "warmup": WARMUP,
        "results": [r.to_dict() for r in results],
    }

    # Add overhead summary
    ungoverned = next((r for r in results if r.name == "E2E: Ungoverned action"), None)
    governed = next(
        (r for r in results if r.name == "E2E: Governed action (full stack)"), None
    )
    if ungoverned and governed:
        data["overhead_summary"] = {
            "ungoverned_p50_ms": round(ungoverned.p50, 4),
            "governed_p50_ms": round(governed.p50, 4),
            "overhead_p50_ms": round(governed.p50 - ungoverned.p50, 4),
            "ungoverned_p99_ms": round(ungoverned.p99, 4),
            "governed_p99_ms": round(governed.p99, 4),
            "overhead_p99_ms": round(governed.p99 - ungoverned.p99, 4),
            "multiplier_p50": round(
                governed.p50 / ungoverned.p50 if ungoverned.p50 > 0 else 0, 1
            ),
        }

    with open(path, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2)
    print(f"  Results saved to {path}")


# ═══════════════════════════════════════════════════════════════════════════
# Chart generation
# ═══════════════════════════════════════════════════════════════════════════


def generate_charts(results: list[BenchmarkResult], charts_dir: Path) -> None:
    """Generate and save latency comparison and overhead breakdown charts."""
    import matplotlib
    matplotlib.use("Agg")
    import matplotlib.pyplot as plt
    import matplotlib.ticker as ticker

    charts_dir.mkdir(parents=True, exist_ok=True)

    # ── Chart 1: Latency comparison (grouped bar chart) ──────────────────

    # Pick a representative subset so the chart isn't overwhelming
    chart_benchmarks = [
        "Bare action (no governance)",
        "Policy eval (10 rules)",
        "Trust policy eval (10 rules)",
        "Ring enforcement check",
        "Audit log write (Merkle)",
        "Credential issuance",
        "Delta capture",
        "Session lifecycle",
        "E2E: Ungoverned action",
        "E2E: Governed (policy only)",
        "E2E: Governed action (full stack)",
    ]
    selected = [r for r in results if r.name in chart_benchmarks]
    # Preserve the order defined above
    order = {name: i for i, name in enumerate(chart_benchmarks)}
    selected.sort(key=lambda r: order.get(r.name, 999))

    # Short labels for the x-axis
    short_labels = {
        "Bare action (no governance)": "Bare action",
        "Policy eval (10 rules)": "Policy\n(10 rules)",
        "Trust policy eval (10 rules)": "Trust policy\n(10 rules)",
        "Ring enforcement check": "Ring\nenforce",
        "Audit log write (Merkle)": "Audit write\n(Merkle)",
        "Credential issuance": "Credential\nissue",
        "Delta capture": "Delta\ncapture",
        "Session lifecycle": "Session\nlifecycle",
        "E2E: Ungoverned action": "E2E\nUngoverned",
        "E2E: Governed (policy only)": "E2E\nPolicy only",
        "E2E: Governed action (full stack)": "E2E\nFull stack",
    }

    labels = [short_labels.get(r.name, r.name) for r in selected]
    p50_vals = [r.p50 for r in selected]
    p95_vals = [r.p95 for r in selected]
    p99_vals = [r.p99 for r in selected]

    x = np.arange(len(labels))
    bar_width = 0.25

    fig, ax = plt.subplots(figsize=(14, 6))
    bars_p50 = ax.bar(x - bar_width, p50_vals, bar_width, label="p50", color="#2196F3")
    bars_p95 = ax.bar(x, p95_vals, bar_width, label="p95", color="#FF9800")
    bars_p99 = ax.bar(x + bar_width, p99_vals, bar_width, label="p99", color="#F44336")

    ax.set_ylabel("Latency (ms)", fontsize=12)
    ax.set_title("Governance Overhead — Latency by Component (p50 / p95 / p99)", fontsize=13, fontweight="bold")
    ax.set_xticks(x)
    ax.set_xticklabels(labels, fontsize=8, ha="center")
    ax.legend(fontsize=10)
    ax.set_yscale("log")
    ax.yaxis.set_major_formatter(ticker.FuncFormatter(lambda v, _: f"{v:.4f}" if v < 0.01 else f"{v:.3f}" if v < 1 else f"{v:.1f}"))
    ax.grid(axis="y", alpha=0.3, linestyle="--")
    ax.set_axisbelow(True)

    fig.tight_layout()
    latency_path = charts_dir / "latency_comparison.png"
    fig.savefig(latency_path, dpi=150)
    plt.close(fig)
    print(f"  Chart saved to {latency_path}")

    # ── Chart 2: Overhead breakdown (horizontal bar chart) ───────────────

    # Components contributing to the E2E governed overhead
    # Pull individual component p50 values from the results
    def _find(name: str) -> float:
        r = next((r for r in results if r.name == name), None)
        return r.p50 if r else 0.0

    policy_cost = _find("Policy eval (10 rules)")
    trust_cost = _find("Trust policy eval (10 rules)")  # 5 rules used in E2E but 10 is closest
    ring_cost = _find("Ring computation") + _find("Ring enforcement check")
    audit_cost = _find("Audit log write (Merkle)")
    governed_total = _find("E2E: Governed action (full stack)")
    other_cost = max(0, governed_total - policy_cost - trust_cost - ring_cost - audit_cost)

    components = ["Policy eval", "Trust policy eval", "Ring enforce", "Audit write (Merkle)", "Other (timestamps, dicts)"]
    values = [policy_cost, trust_cost, ring_cost, audit_cost, other_cost]
    total = sum(values)
    pcts = [(v / total * 100) if total > 0 else 0 for v in values]
    colors = ["#2196F3", "#4CAF50", "#9C27B0", "#F44336", "#9E9E9E"]

    fig2, ax2 = plt.subplots(figsize=(10, 4))
    bars = ax2.barh(components, values, color=colors, edgecolor="white", linewidth=0.5)

    # Add labels on bars
    for bar, pct, val in zip(bars, pcts, values):
        label = f"{val:.4f} ms ({pct:.0f}%)"
        x_pos = bar.get_width()
        ax2.text(x_pos + governed_total * 0.02, bar.get_y() + bar.get_height() / 2,
                 label, va="center", fontsize=9)

    ax2.set_xlabel("Latency (ms)", fontsize=11)
    ax2.set_title(
        f"Governance Overhead Breakdown — {governed_total:.4f} ms total (p50)",
        fontsize=13, fontweight="bold",
    )
    ax2.set_xlim(0, max(values) * 1.5)
    ax2.grid(axis="x", alpha=0.3, linestyle="--")
    ax2.set_axisbelow(True)
    ax2.invert_yaxis()

    fig2.tight_layout()
    breakdown_path = charts_dir / "overhead_breakdown.png"
    fig2.savefig(breakdown_path, dpi=150)
    plt.close(fig2)
    print(f"  Chart saved to {breakdown_path}")


# ═══════════════════════════════════════════════════════════════════════════
# Main
# ═══════════════════════════════════════════════════════════════════════════


def main() -> None:
    all_results: list[BenchmarkResult] = []

    print("Running ungoverned baselines...", flush=True)
    all_results.extend(run_ungoverned_baselines())

    print("Running policy evaluation benchmarks...", flush=True)
    all_results.extend(run_policy_benchmarks())

    print("Running trust policy benchmarks...", flush=True)
    all_results.extend(run_trust_benchmarks())

    print("Running credential benchmarks...", flush=True)
    all_results.extend(run_credential_benchmarks())

    print("Running audit benchmarks...", flush=True)
    all_results.extend(run_audit_benchmarks())

    print("Running ring enforcement benchmarks...", flush=True)
    all_results.extend(run_ring_benchmarks())

    print("Running delta audit benchmarks...", flush=True)
    all_results.extend(run_delta_benchmarks())

    print("Running session lifecycle benchmarks...", flush=True)
    all_results.extend(run_session_benchmarks())

    print("Running E2E governed vs ungoverned...", flush=True)
    all_results.extend(run_e2e_comparison())

    print_table(all_results)

    output_path = Path(__file__).parent / "results" / "governance_overhead.json"
    save_json(all_results, output_path)

    print("Generating charts...", flush=True)
    charts_dir = _ROOT / "docs" / "benchmarks" / "charts"
    generate_charts(all_results, charts_dir)


if __name__ == "__main__":
    main()
