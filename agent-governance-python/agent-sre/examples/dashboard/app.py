# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""Agent SRE — Observability Dashboard.

Standalone Streamlit dashboard with simulated data.
When agent-sre is installed the real SDK types are used for display hints.
"""

from __future__ import annotations

import datetime as dt
import random
import sys
import time
from pathlib import Path

import numpy as np
import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
import streamlit as st

# ---------------------------------------------------------------------------
# Optional SDK imports — dashboard works without them
# ---------------------------------------------------------------------------
try:
    sys.path.insert(0, str(Path(__file__).parent.parent.parent / "src"))
    from agent_sre.slo.objectives import SLO, SLOStatus  # noqa: F401
    from agent_sre.slo.indicators import (  # noqa: F401
        TaskSuccessRate,
        CostPerTask,
        ResponseLatency,
        HallucinationRate,
    )
    from agent_sre.slo.dashboard import SLODashboard  # noqa: F401
    from agent_sre.cost.guard import CostGuard  # noqa: F401
    from agent_sre.chaos.engine import ChaosExperiment  # noqa: F401
    from agent_sre.incidents.detector import IncidentDetector  # noqa: F401

    _SDK = True
except Exception:
    _SDK = False

# ---------------------------------------------------------------------------
# Page config
# ---------------------------------------------------------------------------
st.set_page_config(
    page_title="Agent SRE Dashboard",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded",
)

PLOTLY_TEMPLATE = "plotly_dark"
COLOR_HEALTHY = "#2ecc71"
COLOR_WARNING = "#f1c40f"
COLOR_CRITICAL = "#e74c3c"
COLOR_EXHAUSTED = "#8e44ad"
COLOR_INFO = "#3498db"

AGENTS = [
    "support-bot",
    "code-reviewer",
    "data-pipeline",
    "billing-agent",
    "search-indexer",
    "deploy-agent",
    "qa-tester",
    "onboarding-flow",
]

# ---------------------------------------------------------------------------
# Deterministic random seed so refreshes stay consistent within a session
# ---------------------------------------------------------------------------
if "seed" not in st.session_state:
    st.session_state["seed"] = int(time.time())
rng = np.random.default_rng(st.session_state["seed"])

# ---------------------------------------------------------------------------
# Sidebar
# ---------------------------------------------------------------------------
st.sidebar.title("🛡️ Agent SRE")
st.sidebar.caption(f"SDK detected: **{'Yes' if _SDK else 'No (simulated)'}**")
time_range = st.sidebar.selectbox(
    "Time range", ["Last 1 h", "Last 6 h", "Last 24 h", "Last 7 d", "Last 30 d"], index=2
)
selected_agents = st.sidebar.multiselect("Filter agents", AGENTS, default=AGENTS)
st.sidebar.divider()
auto_refresh = st.sidebar.checkbox("Auto-refresh (30 s)", value=False)
if auto_refresh:
    st.sidebar.info("Dashboard will reload every 30 seconds.")
    time.sleep(0.1)  # avoid tight loop on first load
    st.empty()

HOURS = {"Last 1 h": 1, "Last 6 h": 6, "Last 24 h": 24, "Last 7 d": 168, "Last 30 d": 720}
N_POINTS = min(HOURS[time_range], 200)


# ---------------------------------------------------------------------------
# Data generators
# ---------------------------------------------------------------------------
def _ts_index(hours: int, points: int) -> pd.DatetimeIndex:
    end = dt.datetime.now(tz=dt.timezone.utc)
    start = end - dt.timedelta(hours=hours)
    return pd.date_range(start, end, periods=points)


def gen_slo_data() -> pd.DataFrame:
    """Generate SLO compliance timeline data."""
    rows: list[dict] = []
    slos = ["task-success", "p95-latency", "cost-per-task", "hallucination-rate"]
    ts = _ts_index(HOURS[time_range], N_POINTS)
    for slo in slos:
        base = rng.uniform(0.92, 0.999)
        noise = rng.normal(0, 0.008, size=len(ts))
        vals = np.clip(base + np.cumsum(noise) * 0.02, 0.80, 1.0)
        for t, v in zip(ts, vals):
            rows.append({"timestamp": t, "slo": slo, "compliance": float(v)})
    return pd.DataFrame(rows)


def gen_slo_snapshots() -> list[dict]:
    """Generate current SLO snapshots."""
    slos = [
        ("task-success", "Task Success Rate", 0.995),
        ("p95-latency", "P95 Latency", 0.99),
        ("cost-per-task", "Cost Per Task", 0.98),
        ("hallucination-rate", "Hallucination Rate", 0.95),
    ]
    snapshots = []
    for key, name, target in slos:
        budget_remaining = rng.uniform(15, 95)
        status = (
            "healthy"
            if budget_remaining > 50
            else "warning"
            if budget_remaining > 20
            else "critical"
            if budget_remaining > 0
            else "exhausted"
        )
        snapshots.append(
            {
                "name": name,
                "key": key,
                "target": target,
                "status": status,
                "budget_remaining": round(budget_remaining, 1),
                "burn_rate_1h": round(rng.uniform(0.2, 8.0), 2),
                "burn_rate_6h": round(rng.uniform(0.3, 5.0), 2),
                "current_value": round(rng.uniform(target - 0.04, target + 0.005), 4),
            }
        )
    return snapshots


def gen_indicator_table() -> pd.DataFrame:
    indicators = []
    for agent in selected_agents:
        indicators.append(
            {
                "Agent": agent,
                "Success Rate": f"{rng.uniform(0.96, 0.999):.3f}",
                "P95 Latency (ms)": int(rng.uniform(120, 4800)),
                "Cost / Task ($)": f"{rng.uniform(0.02, 0.48):.3f}",
                "Hallucination %": f"{rng.uniform(0.5, 6.0):.1f}",
            }
        )
    return pd.DataFrame(indicators)


def gen_cost_data() -> tuple[pd.DataFrame, pd.DataFrame, list[dict]]:
    """Return (agent_budgets_df, cost_trend_df, alerts)."""
    budgets = []
    for agent in selected_agents:
        limit = rng.uniform(50, 200)
        spent = rng.uniform(5, limit * 1.05)
        budgets.append(
            {
                "agent": agent,
                "daily_limit": round(limit, 2),
                "spent_today": round(min(spent, limit * 1.1), 2),
                "utilization": round(min(spent / limit, 1.1) * 100, 1),
            }
        )
    budget_df = pd.DataFrame(budgets).sort_values("utilization", ascending=False)

    ts = _ts_index(HOURS[time_range], N_POINTS)
    rows = []
    for agent in selected_agents:
        base = rng.uniform(1, 15)
        noise = rng.normal(0, 1.5, size=len(ts))
        vals = np.clip(base + np.cumsum(noise) * 0.1, 0.5, 50)
        for t, v in zip(ts, vals):
            rows.append({"timestamp": t, "agent": agent, "cost_usd": float(v)})
    trend_df = pd.DataFrame(rows)

    severities = ["info", "warning", "critical"]
    alerts = []
    for _ in range(rng.integers(2, 7)):
        sev = rng.choice(severities, p=[0.5, 0.35, 0.15])
        agent = rng.choice(selected_agents)
        alerts.append(
            {
                "severity": sev,
                "agent": agent,
                "message": f"{'Budget exceeded' if sev == 'critical' else 'Approaching limit' if sev == 'warning' else 'Cost recorded'} for {agent}",
                "value": f"${rng.uniform(10, 200):.2f}",
                "time": (dt.datetime.now(tz=dt.timezone.utc) - dt.timedelta(minutes=int(rng.integers(1, 300)))).strftime("%H:%M"),
            }
        )
    return budget_df, trend_df, alerts


def gen_chaos_data() -> list[dict]:
    experiments = [
        {
            "name": "tool-timeout-blast",
            "agent": "support-bot",
            "state": "completed",
            "fault": "tool_timeout",
            "resilience": {
                "overall": round(rng.uniform(60, 95), 1),
                "fault_tolerance": round(rng.uniform(55, 98), 1),
                "recovery_time": round(rng.uniform(40, 90), 1),
                "degradation": round(rng.uniform(50, 95), 1),
                "cost_impact": round(rng.uniform(60, 99), 1),
            },
            "duration_s": 1800,
            "faults_injected": int(rng.integers(12, 45)),
            "started": (dt.datetime.now(tz=dt.timezone.utc) - dt.timedelta(hours=3)).isoformat(),
        },
        {
            "name": "llm-degraded-canary",
            "agent": "code-reviewer",
            "state": "completed",
            "fault": "llm_degraded",
            "resilience": {
                "overall": round(rng.uniform(50, 85), 1),
                "fault_tolerance": round(rng.uniform(45, 80), 1),
                "recovery_time": round(rng.uniform(30, 75), 1),
                "degradation": round(rng.uniform(35, 85), 1),
                "cost_impact": round(rng.uniform(50, 90), 1),
            },
            "duration_s": 900,
            "faults_injected": int(rng.integers(5, 20)),
            "started": (dt.datetime.now(tz=dt.timezone.utc) - dt.timedelta(hours=1)).isoformat(),
        },
        {
            "name": "cost-spike-test",
            "agent": "billing-agent",
            "state": "running",
            "fault": "cost_spike",
            "resilience": {
                "overall": 0,
                "fault_tolerance": 0,
                "recovery_time": 0,
                "degradation": 0,
                "cost_impact": 0,
            },
            "duration_s": 600,
            "faults_injected": int(rng.integers(2, 10)),
            "started": (dt.datetime.now(tz=dt.timezone.utc) - dt.timedelta(minutes=5)).isoformat(),
        },
    ]
    return experiments


def gen_incident_data() -> list[dict]:
    now = dt.datetime.now(tz=dt.timezone.utc)
    return [
        {
            "id": "INC-1042",
            "title": "SLO breach — task-success for support-bot",
            "severity": "P1",
            "state": "investigating",
            "agent": "support-bot",
            "detected": (now - dt.timedelta(minutes=22)).strftime("%H:%M:%S"),
            "acknowledged": (now - dt.timedelta(minutes=20)).strftime("%H:%M:%S"),
            "resolved": None,
            "signals": ["slo_breach", "error_budget_exhausted"],
            "mttr_min": None,
        },
        {
            "id": "INC-1041",
            "title": "Cost anomaly — billing-agent spike",
            "severity": "P2",
            "state": "mitigating",
            "agent": "billing-agent",
            "detected": (now - dt.timedelta(minutes=48)).strftime("%H:%M:%S"),
            "acknowledged": (now - dt.timedelta(minutes=45)).strftime("%H:%M:%S"),
            "resolved": None,
            "signals": ["cost_anomaly", "latency_spike"],
            "mttr_min": None,
        },
        {
            "id": "INC-1040",
            "title": "Latency spike — search-indexer",
            "severity": "P3",
            "state": "resolved",
            "agent": "search-indexer",
            "detected": (now - dt.timedelta(hours=4)).strftime("%H:%M:%S"),
            "acknowledged": (now - dt.timedelta(hours=3, minutes=55)).strftime("%H:%M:%S"),
            "resolved": (now - dt.timedelta(hours=3, minutes=30)).strftime("%H:%M:%S"),
            "signals": ["latency_spike"],
            "mttr_min": 30,
        },
        {
            "id": "INC-1039",
            "title": "Tool failure rate elevated — qa-tester",
            "severity": "P4",
            "state": "resolved",
            "agent": "qa-tester",
            "detected": (now - dt.timedelta(hours=8)).strftime("%H:%M:%S"),
            "acknowledged": (now - dt.timedelta(hours=7, minutes=50)).strftime("%H:%M:%S"),
            "resolved": (now - dt.timedelta(hours=7)).strftime("%H:%M:%S"),
            "signals": ["tool_failure_spike"],
            "mttr_min": 60,
        },
    ]


def gen_rollout_data() -> dict:
    steps = [
        {"name": "Shadow", "weight": 0, "status": "complete", "duration_s": 3600},
        {"name": "Canary 5%", "weight": 5, "status": "complete", "duration_s": 1800},
        {"name": "Canary 25%", "weight": 25, "status": "active", "duration_s": 3600},
        {"name": "Canary 50%", "weight": 50, "status": "pending", "duration_s": 3600},
        {"name": "Full rollout", "weight": 100, "status": "pending", "duration_s": 0},
    ]
    return {
        "name": "deploy-agent-v2.4.0",
        "agent": "deploy-agent",
        "strategy": "canary",
        "state": "canary",
        "current_step": 2,
        "steps": steps,
        "shadow_match_rate": round(rng.uniform(0.91, 0.98), 3),
        "canary_success_rate": round(rng.uniform(0.985, 0.999), 4),
        "baseline_success_rate": round(rng.uniform(0.990, 0.999), 4),
        "canary_p95_ms": int(rng.integers(180, 600)),
        "baseline_p95_ms": int(rng.integers(200, 500)),
        "canary_cost": round(rng.uniform(0.10, 0.35), 3),
        "baseline_cost": round(rng.uniform(0.12, 0.30), 3),
    }


POLICIES = [
    "content-safety",
    "rate-limit",
    "cost-budget",
    "pii-filter",
    "tool-access",
    "hallucination-guard",
    "auth-scope",
    "output-filter",
]


def gen_policy_heatmap_data(
    view: str = "agent_x_time",
) -> tuple[pd.DataFrame, pd.DataFrame, pd.DataFrame]:
    """Return (eval_heatmap_df, violation_heatmap_df, summary_df) for policy heatmap widget.

    ``view`` is either ``'agent_x_time'`` (agents × time buckets) or
    ``'policy_x_time'`` (policies × time buckets).
    Data is sourced from governance metrics via OpenTelemetry conventions;
    here we generate realistic simulated values in the same shape the OTel
    exporter would produce.
    """
    hours = HOURS[time_range]
    # Bucket width: 1 h buckets for short ranges, 4 h or day buckets for long.
    if hours <= 6:
        n_buckets = hours
        bucket_label = "hour"
    elif hours <= 48:
        n_buckets = hours
        bucket_label = "hour"
    else:
        n_buckets = hours // 4
        bucket_label = "4-hour"

    n_buckets = min(n_buckets, 48)  # cap display columns

    end = dt.datetime.now(tz=dt.timezone.utc).replace(minute=0, second=0, microsecond=0)
    buckets = [end - dt.timedelta(hours=(n_buckets - 1 - i)) for i in range(n_buckets)]
    bucket_labels = [b.strftime("%m/%d %H:%M") for b in buckets]

    if view == "agent_x_time":
        rows_eval: list[dict] = []
        rows_viol: list[dict] = []
        for agent in selected_agents:
            # Each agent has a characteristic baseline rate and occasional spikes
            base_eval = rng.uniform(20, 200)
            base_viol = rng.uniform(0.01, 0.12)  # violation fraction
            spike_at = rng.integers(0, max(1, n_buckets - 1))
            for i, label in enumerate(bucket_labels):
                spike = 4.0 if i == spike_at else 1.0
                eval_count = int(base_eval * spike * rng.uniform(0.7, 1.3))
                viol_count = int(eval_count * base_viol * spike * rng.uniform(0.5, 1.5))
                rows_eval.append({"y": agent, "x": label, "z": eval_count})
                rows_viol.append({"y": agent, "x": label, "z": viol_count})
        eval_df = pd.DataFrame(rows_eval)
        viol_df = pd.DataFrame(rows_viol)
        y_label = "Agent"
    else:
        rows_eval = []
        rows_viol = []
        for policy in POLICIES:
            base_eval = rng.uniform(10, 300)
            base_viol = rng.uniform(0.005, 0.20)
            spike_at = rng.integers(0, max(1, n_buckets - 1))
            for i, label in enumerate(bucket_labels):
                spike = 5.0 if i == spike_at else 1.0
                eval_count = int(base_eval * spike * rng.uniform(0.6, 1.4))
                viol_count = int(eval_count * base_viol * spike * rng.uniform(0.5, 2.0))
                rows_eval.append({"y": policy, "x": label, "z": eval_count})
                rows_viol.append({"y": policy, "x": label, "z": viol_count})
        eval_df = pd.DataFrame(rows_eval)
        viol_df = pd.DataFrame(rows_viol)
        y_label = "Policy"

    # Summary table
    if view == "agent_x_time":
        entities = selected_agents
    else:
        entities = POLICIES

    summary_rows = []
    for entity in entities:
        evals = eval_df[eval_df["y"] == entity]["z"].sum()
        viols = viol_df[viol_df["y"] == entity]["z"].sum()
        peak_bucket = eval_df[eval_df["y"] == entity].nlargest(1, "z")["x"].values
        summary_rows.append(
            {
                y_label: entity,
                "Total Evaluations": int(evals),
                "Total Violations": int(viols),
                "Violation Rate": f"{viols / max(evals, 1):.2%}",
                "Peak Bucket": peak_bucket[0] if len(peak_bucket) else "—",
            }
        )
    summary_df = pd.DataFrame(summary_rows).sort_values("Total Violations", ascending=False)

    return eval_df, viol_df, summary_df


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------
def status_color(status: str) -> str:
    return {
        "healthy": COLOR_HEALTHY,
        "warning": COLOR_WARNING,
        "critical": COLOR_CRITICAL,
        "exhausted": COLOR_EXHAUSTED,
    }.get(status, COLOR_INFO)


def severity_color(sev: str) -> str:
    return {"P1": COLOR_CRITICAL, "P2": "#e67e22", "P3": COLOR_WARNING, "P4": COLOR_INFO}.get(
        sev, COLOR_INFO
    )


def severity_badge(sev: str) -> str:
    colors = {"critical": "🔴", "warning": "🟡", "info": "🔵"}
    return f"{colors.get(sev, '⚪')} {sev.upper()}"


def _gauge(value: float, title: str, thresholds: tuple[float, float] = (2.0, 6.0)) -> go.Figure:
    color = COLOR_HEALTHY if value < thresholds[0] else COLOR_WARNING if value < thresholds[1] else COLOR_CRITICAL
    fig = go.Figure(
        go.Indicator(
            mode="gauge+number",
            value=value,
            title={"text": title, "font": {"size": 13}},
            gauge={
                "axis": {"range": [0, 12], "tickwidth": 1},
                "bar": {"color": color},
                "bgcolor": "#1e1e1e",
                "steps": [
                    {"range": [0, thresholds[0]], "color": "#1a3a1a"},
                    {"range": [thresholds[0], thresholds[1]], "color": "#3a3a1a"},
                    {"range": [thresholds[1], 12], "color": "#3a1a1a"},
                ],
            },
            number={"suffix": "x", "font": {"size": 22}},
        )
    )
    fig.update_layout(
        template=PLOTLY_TEMPLATE,
        height=180,
        margin=dict(l=20, r=20, t=40, b=10),
        paper_bgcolor="rgba(0,0,0,0)",
        plot_bgcolor="rgba(0,0,0,0)",
    )
    return fig


# ---------------------------------------------------------------------------
# TABS
# ---------------------------------------------------------------------------
tab_slo, tab_cost, tab_chaos, tab_inc, tab_delivery, tab_policy = st.tabs(
    ["📊 SLO Health", "💰 Cost Management", "🧪 Chaos Engineering", "🚨 Incidents", "🚀 Progressive Delivery", "🔥 Policy Heatmap"]
)

# ========================== TAB 1: SLO Health ==============================
with tab_slo:
    snapshots = gen_slo_snapshots()
    healthy = sum(1 for s in snapshots if s["status"] == "healthy")
    warning = sum(1 for s in snapshots if s["status"] == "warning")
    critical = sum(1 for s in snapshots if s["status"] == "critical")
    exhausted = sum(1 for s in snapshots if s["status"] == "exhausted")

    c1, c2, c3, c4, c5 = st.columns(5)
    c1.metric("Total SLOs", len(snapshots))
    c2.metric("Healthy", healthy, delta=f"{healthy}" if healthy else None, delta_color="normal")
    c3.metric("Warning", warning, delta=f"-{warning}" if warning else "0", delta_color="inverse")
    c4.metric("Critical", critical, delta=f"-{critical}" if critical else "0", delta_color="inverse")
    c5.metric("Exhausted", exhausted, delta=f"-{exhausted}" if exhausted else "0", delta_color="inverse")

    st.subheader("Error Budget Burn Rates")
    cols = st.columns(len(snapshots))
    for col, snap in zip(cols, snapshots):
        with col:
            st.plotly_chart(_gauge(snap["burn_rate_1h"], f"{snap['key']} — 1 h"), use_container_width=True)
            st.plotly_chart(_gauge(snap["burn_rate_6h"], f"{snap['key']} — 6 h"), use_container_width=True)

    st.subheader("SLO Compliance Timeline")
    slo_df = gen_slo_data()
    fig_slo = px.line(
        slo_df,
        x="timestamp",
        y="compliance",
        color="slo",
        template=PLOTLY_TEMPLATE,
        labels={"compliance": "Compliance", "timestamp": ""},
    )
    fig_slo.update_layout(
        height=340,
        legend=dict(orientation="h", y=-0.15),
        yaxis_tickformat=".1%",
        margin=dict(l=40, r=20, t=10, b=40),
    )
    for snap in snapshots:
        fig_slo.add_hline(y=snap["target"], line_dash="dot", line_color="gray", opacity=0.4)
    st.plotly_chart(fig_slo, use_container_width=True)

    st.subheader("Indicator Breakdown")
    st.dataframe(gen_indicator_table(), use_container_width=True, hide_index=True)

# ========================== TAB 2: Cost Management =========================
with tab_cost:
    budget_df, trend_df, cost_alerts = gen_cost_data()

    total_spent = budget_df["spent_today"].sum()
    total_limit = budget_df["daily_limit"].sum()
    avg_util = budget_df["utilization"].mean()
    c1, c2, c3, c4 = st.columns(4)
    c1.metric("Total Spent Today", f"${total_spent:,.2f}", delta=f"${total_spent - total_limit:+,.2f}")
    c2.metric("Daily Budget", f"${total_limit:,.2f}")
    c3.metric("Avg Utilization", f"{avg_util:.1f}%", delta=f"{avg_util - 70:+.1f}%", delta_color="inverse")
    c4.metric("Active Alerts", len(cost_alerts), delta=f"-{len(cost_alerts)}", delta_color="inverse")

    left, right = st.columns([3, 2])
    with left:
        st.subheader("Per-Agent Budget Utilization")
        fig_budget = go.Figure()
        fig_budget.add_trace(
            go.Bar(
                y=budget_df["agent"],
                x=budget_df["spent_today"],
                orientation="h",
                name="Spent",
                marker_color=[
                    COLOR_CRITICAL if u > 90 else COLOR_WARNING if u > 70 else COLOR_HEALTHY
                    for u in budget_df["utilization"]
                ],
            )
        )
        fig_budget.add_trace(
            go.Bar(
                y=budget_df["agent"],
                x=budget_df["daily_limit"] - budget_df["spent_today"].clip(upper=budget_df["daily_limit"]),
                orientation="h",
                name="Remaining",
                marker_color="rgba(100,100,100,0.3)",
            )
        )
        fig_budget.update_layout(
            barmode="stack",
            template=PLOTLY_TEMPLATE,
            height=max(250, len(budget_df) * 40),
            margin=dict(l=20, r=20, t=10, b=30),
            legend=dict(orientation="h", y=-0.15),
            xaxis_title="USD",
        )
        st.plotly_chart(fig_budget, use_container_width=True)

    with right:
        st.subheader("Top Spenders")
        top = budget_df.nlargest(5, "spent_today")[["agent", "spent_today", "utilization"]].copy()
        top.columns = ["Agent", "Spent ($)", "Util %"]
        st.dataframe(top, use_container_width=True, hide_index=True)

    st.subheader("Cost Trend")
    fig_trend = px.line(
        trend_df,
        x="timestamp",
        y="cost_usd",
        color="agent",
        template=PLOTLY_TEMPLATE,
        labels={"cost_usd": "Cost (USD)", "timestamp": ""},
    )
    fig_trend.update_layout(
        height=320,
        legend=dict(orientation="h", y=-0.18),
        margin=dict(l=40, r=20, t=10, b=40),
    )
    st.plotly_chart(fig_trend, use_container_width=True)

    st.subheader("Daily Cost Breakdown by Agent")
    daily_df = trend_df.copy()
    daily_df["date"] = daily_df["timestamp"].dt.date
    daily_agg = daily_df.groupby(["date", "agent"])["cost_usd"].sum().reset_index()
    fig_stack = px.bar(
        daily_agg,
        x="date",
        y="cost_usd",
        color="agent",
        template=PLOTLY_TEMPLATE,
        labels={"cost_usd": "Cost (USD)", "date": ""},
    )
    fig_stack.update_layout(
        barmode="stack",
        height=300,
        margin=dict(l=40, r=20, t=10, b=40),
        legend=dict(orientation="h", y=-0.2),
    )
    st.plotly_chart(fig_stack, use_container_width=True)

    st.subheader("Cost Alerts")
    alert_df = pd.DataFrame(cost_alerts)
    alert_df["severity"] = alert_df["severity"].apply(severity_badge)
    st.dataframe(alert_df, use_container_width=True, hide_index=True)

# ========================== TAB 3: Chaos Engineering =======================
with tab_chaos:
    experiments = gen_chaos_data()

    c1, c2, c3 = st.columns(3)
    running = sum(1 for e in experiments if e["state"] == "running")
    completed = sum(1 for e in experiments if e["state"] == "completed")
    total_faults = sum(e["faults_injected"] for e in experiments)
    c1.metric("Experiments", len(experiments))
    c2.metric("Running", running, delta=str(running))
    c3.metric("Faults Injected", total_faults)

    left, right = st.columns([3, 2])
    with left:
        st.subheader("Experiments")
        for exp in experiments:
            state_icon = "🟢" if exp["state"] == "completed" else "🔵" if exp["state"] == "running" else "⏳"
            with st.expander(f"{state_icon} **{exp['name']}** — {exp['agent']}  [{exp['state']}]", expanded=exp["state"] == "running"):
                ec1, ec2, ec3 = st.columns(3)
                ec1.metric("Fault Type", exp["fault"])
                ec2.metric("Duration", f"{exp['duration_s']}s")
                ec3.metric("Faults", exp["faults_injected"])
                if exp["resilience"]["overall"] > 0:
                    st.metric("Fault Impact Score", f"{exp['resilience']['overall']}%")

    with right:
        st.subheader("Resilience Radar")
        completed_exps = [e for e in experiments if e["state"] == "completed"]
        if completed_exps:
            categories = ["Fault Tolerance", "Recovery Time", "Degradation", "Cost Impact"]
            fig_radar = go.Figure()
            for exp in completed_exps:
                r = exp["resilience"]
                fig_radar.add_trace(
                    go.Scatterpolar(
                        r=[r["fault_tolerance"], r["recovery_time"], r["degradation"], r["cost_impact"]],
                        theta=categories,
                        fill="toself",
                        name=exp["name"],
                        opacity=0.65,
                    )
                )
            fig_radar.update_layout(
                polar=dict(
                    bgcolor="rgba(0,0,0,0)",
                    radialaxis=dict(visible=True, range=[0, 100], gridcolor="#333"),
                    angularaxis=dict(gridcolor="#333"),
                ),
                template=PLOTLY_TEMPLATE,
                height=380,
                margin=dict(l=40, r=40, t=30, b=30),
                legend=dict(orientation="h", y=-0.15),
            )
            st.plotly_chart(fig_radar, use_container_width=True)

    st.subheader("Fault Injection Timeline")
    timeline_rows = []
    for exp in experiments:
        start = dt.datetime.fromisoformat(exp["started"])
        for i in range(exp["faults_injected"]):
            offset = rng.uniform(0, exp["duration_s"])
            timeline_rows.append(
                {
                    "timestamp": start + dt.timedelta(seconds=offset),
                    "experiment": exp["name"],
                    "fault": exp["fault"],
                }
            )
    if timeline_rows:
        tl_df = pd.DataFrame(timeline_rows).sort_values("timestamp")
        fig_tl = px.strip(
            tl_df,
            x="timestamp",
            y="experiment",
            color="fault",
            template=PLOTLY_TEMPLATE,
            labels={"timestamp": "", "experiment": ""},
        )
        fig_tl.update_traces(marker_size=8)
        fig_tl.update_layout(height=220, margin=dict(l=20, r=20, t=10, b=30))
        st.plotly_chart(fig_tl, use_container_width=True)

    st.subheader("Before / After Comparison")
    if completed_exps:
        ba_rows = []
        for exp in completed_exps:
            ba_rows.append({"Experiment": exp["name"], "Metric": "Success Rate", "Before": f"{rng.uniform(0.98, 0.999):.3f}", "After": f"{rng.uniform(0.92, 0.98):.3f}"})
            ba_rows.append({"Experiment": exp["name"], "Metric": "P95 Latency (ms)", "Before": f"{int(rng.integers(200, 400))}", "After": f"{int(rng.integers(350, 800))}"})
            ba_rows.append({"Experiment": exp["name"], "Metric": "Avg Cost ($)", "Before": f"{rng.uniform(0.10, 0.25):.3f}", "After": f"{rng.uniform(0.15, 0.40):.3f}"})
        st.dataframe(pd.DataFrame(ba_rows), use_container_width=True, hide_index=True)

    st.divider()
    if st.button("🔴 Run Chaos Test", type="primary"):
        with st.spinner("Injecting fault: tool_timeout → support-bot …"):
            progress = st.progress(0)
            for i in range(100):
                time.sleep(0.03)
                progress.progress(i + 1)
            st.success("Chaos experiment **ad-hoc-timeout-test** completed — Resilience: **78.3%**")
            st.balloons()

# ========================== TAB 4: Incidents ===============================
with tab_inc:
    incidents = gen_incident_data()
    active = [i for i in incidents if i["state"] != "resolved"]
    resolved = [i for i in incidents if i["state"] == "resolved"]
    resolved_mttr = [i["mttr_min"] for i in resolved if i["mttr_min"] is not None]

    c1, c2, c3, c4 = st.columns(4)
    c1.metric("Active Incidents", len(active), delta=f"-{len(active)}", delta_color="inverse")
    c2.metric("Resolved (window)", len(resolved))
    c3.metric("MTTR (avg)", f"{np.mean(resolved_mttr):.0f} min" if resolved_mttr else "N/A")
    c4.metric("P1 Open", sum(1 for i in active if i["severity"] == "P1"), delta="-1", delta_color="inverse")

    st.subheader("Active Incidents")
    for inc in active:
        color = severity_color(inc["severity"])
        st.markdown(
            f"""<div style="border-left:4px solid {color};padding:8px 12px;margin-bottom:8px;
            background:rgba(255,255,255,0.03);border-radius:4px;">
            <strong>{inc['severity']}</strong> &nbsp; {inc['title']} &nbsp;
            <code>{inc['state']}</code><br/>
            <small>Agent: {inc['agent']} · Detected: {inc['detected']} · Ack: {inc['acknowledged']}</small>
            </div>""",
            unsafe_allow_html=True,
        )

    left, right = st.columns(2)
    with left:
        st.subheader("Incident Timeline")
        tl_data = []
        for inc in incidents:
            tl_data.append({"incident": inc["id"], "event": "Detected", "time": inc["detected"]})
            tl_data.append({"incident": inc["id"], "event": "Acknowledged", "time": inc["acknowledged"]})
            if inc["resolved"]:
                tl_data.append({"incident": inc["id"], "event": "Resolved", "time": inc["resolved"]})
        tl_df = pd.DataFrame(tl_data)
        event_colors = {"Detected": COLOR_CRITICAL, "Acknowledged": COLOR_WARNING, "Resolved": COLOR_HEALTHY}
        fig_itl = px.scatter(
            tl_df,
            x="time",
            y="incident",
            color="event",
            color_discrete_map=event_colors,
            template=PLOTLY_TEMPLATE,
            symbol="event",
            size_max=12,
        )
        fig_itl.update_traces(marker_size=12)
        fig_itl.update_layout(height=260, margin=dict(l=20, r=20, t=10, b=30), xaxis_title="", yaxis_title="")
        st.plotly_chart(fig_itl, use_container_width=True)

    with right:
        st.subheader("MTTR by Severity")
        mttr_data = [
            {"Severity": "P1", "Avg MTTR (min)": int(rng.integers(15, 45))},
            {"Severity": "P2", "Avg MTTR (min)": int(rng.integers(20, 60))},
            {"Severity": "P3", "Avg MTTR (min)": int(rng.integers(25, 90))},
            {"Severity": "P4", "Avg MTTR (min)": int(rng.integers(40, 120))},
        ]
        fig_mttr = px.bar(
            pd.DataFrame(mttr_data),
            x="Severity",
            y="Avg MTTR (min)",
            color="Severity",
            color_discrete_map={"P1": COLOR_CRITICAL, "P2": "#e67e22", "P3": COLOR_WARNING, "P4": COLOR_INFO},
            template=PLOTLY_TEMPLATE,
        )
        fig_mttr.update_layout(height=260, margin=dict(l=20, r=20, t=10, b=30), showlegend=False)
        st.plotly_chart(fig_mttr, use_container_width=True)

    st.subheader("Signal Correlation")
    signal_map: dict[str, list[str]] = {}
    for inc in incidents:
        for sig in inc["signals"]:
            signal_map.setdefault(sig, []).append(inc["id"])
    corr_rows = [{"Signal": sig, "Triggered Incidents": ", ".join(incs)} for sig, incs in signal_map.items()]
    st.dataframe(pd.DataFrame(corr_rows), use_container_width=True, hide_index=True)

# ========================== TAB 5: Progressive Delivery ====================
with tab_delivery:
    rollout = gen_rollout_data()

    c1, c2, c3, c4 = st.columns(4)
    c1.metric("Rollout", rollout["name"])
    c2.metric("Strategy", rollout["strategy"].upper())
    c3.metric("Current Weight", f"{rollout['steps'][rollout['current_step']]['weight']}%")
    c4.metric("Shadow Match", f"{rollout['shadow_match_rate']:.1%}")

    st.subheader("Rollout Progress")
    step_df = pd.DataFrame(rollout["steps"])
    step_colors = {"complete": COLOR_HEALTHY, "active": COLOR_INFO, "pending": "#555"}
    fig_steps = go.Figure()
    for _, row in step_df.iterrows():
        fig_steps.add_trace(
            go.Bar(
                x=[row["weight"] or 1],
                y=[row["name"]],
                orientation="h",
                marker_color=step_colors.get(row["status"], "#555"),
                showlegend=False,
                text=f"{row['weight']}% — {row['status']}",
                textposition="inside",
            )
        )
    fig_steps.update_layout(
        template=PLOTLY_TEMPLATE,
        height=240,
        barmode="group",
        margin=dict(l=20, r=20, t=10, b=30),
        xaxis_title="Traffic Weight %",
        yaxis=dict(autorange="reversed"),
    )
    st.plotly_chart(fig_steps, use_container_width=True)

    st.subheader("Canary vs Baseline")
    left, right = st.columns(2)
    with left:
        comparison = pd.DataFrame(
            {
                "Metric": ["Success Rate", "P95 Latency (ms)", "Cost / Task ($)"],
                "Canary": [rollout["canary_success_rate"], rollout["canary_p95_ms"], rollout["canary_cost"]],
                "Baseline": [rollout["baseline_success_rate"], rollout["baseline_p95_ms"], rollout["baseline_cost"]],
            }
        )
        fig_comp = go.Figure()
        fig_comp.add_trace(go.Bar(x=comparison["Metric"], y=comparison["Canary"], name="Canary", marker_color=COLOR_INFO))
        fig_comp.add_trace(go.Bar(x=comparison["Metric"], y=comparison["Baseline"], name="Baseline", marker_color="#888"))
        fig_comp.update_layout(
            barmode="group",
            template=PLOTLY_TEMPLATE,
            height=300,
            margin=dict(l=20, r=20, t=10, b=30),
            legend=dict(orientation="h", y=-0.2),
        )
        st.plotly_chart(fig_comp, use_container_width=True)

    with right:
        st.markdown("**Shadow Test Match Rate**")
        fig_shadow = go.Figure(
            go.Indicator(
                mode="gauge+number",
                value=rollout["shadow_match_rate"] * 100,
                title={"text": "Match %", "font": {"size": 14}},
                number={"suffix": "%", "font": {"size": 32}},
                gauge={
                    "axis": {"range": [0, 100]},
                    "bar": {"color": COLOR_HEALTHY if rollout["shadow_match_rate"] > 0.9 else COLOR_WARNING},
                    "bgcolor": "#1e1e1e",
                    "steps": [
                        {"range": [0, 80], "color": "#3a1a1a"},
                        {"range": [80, 90], "color": "#3a3a1a"},
                        {"range": [90, 100], "color": "#1a3a1a"},
                    ],
                },
            )
        )
        fig_shadow.update_layout(
            template=PLOTLY_TEMPLATE,
            height=260,
            margin=dict(l=30, r=30, t=40, b=10),
            paper_bgcolor="rgba(0,0,0,0)",
        )
        st.plotly_chart(fig_shadow, use_container_width=True)

    st.subheader("Rollout Event Timeline")
    now = dt.datetime.now(tz=dt.timezone.utc)
    events = [
        {"time": (now - dt.timedelta(hours=2)).strftime("%H:%M"), "event": "Shadow started", "step": 0},
        {"time": (now - dt.timedelta(hours=1)).strftime("%H:%M"), "event": "Shadow passed — match 95.2%", "step": 0},
        {"time": (now - dt.timedelta(minutes=50)).strftime("%H:%M"), "event": "Canary 5% started", "step": 1},
        {"time": (now - dt.timedelta(minutes=20)).strftime("%H:%M"), "event": "Canary 5% passed analysis", "step": 1},
        {"time": (now - dt.timedelta(minutes=18)).strftime("%H:%M"), "event": "Canary 25% started", "step": 2},
    ]
    st.dataframe(pd.DataFrame(events), use_container_width=True, hide_index=True)

# ========================== TAB 6: Policy Heatmap ==========================
with tab_policy:
    st.subheader("🔥 Policy Evaluation Heatmap")
    st.caption(
        "Visualises governance metric density from the OpenTelemetry pipeline. "
        "Color intensity reflects evaluation count or violation count per time bucket. "
        "Use the controls below to switch between views."
    )

    ctrl_left, ctrl_right = st.columns([2, 3])
    with ctrl_left:
        heatmap_view = st.radio(
            "Heatmap axes",
            ["agent_x_time", "policy_x_time"],
            format_func=lambda v: "Agent × Time" if v == "agent_x_time" else "Policy × Time",
            horizontal=True,
        )
    with ctrl_right:
        heatmap_metric = st.radio(
            "Color metric",
            ["evaluations", "violations"],
            format_func=lambda v: "Evaluation Count" if v == "evaluations" else "Violation Count",
            horizontal=True,
        )

    eval_df, viol_df, summary_df = gen_policy_heatmap_data(view=heatmap_view)
    plot_df = eval_df if heatmap_metric == "evaluations" else viol_df
    color_label = "Evaluations" if heatmap_metric == "evaluations" else "Violations"
    color_scale = "Blues" if heatmap_metric == "evaluations" else "Reds"
    y_axis_label = "Agent" if heatmap_view == "agent_x_time" else "Policy"

    # Pivot to matrix form for imshow
    pivot = plot_df.pivot(index="y", columns="x", values="z").fillna(0)

    fig_heatmap = go.Figure(
        go.Heatmap(
            z=pivot.values,
            x=list(pivot.columns),
            y=list(pivot.index),
            colorscale=color_scale,
            hoverongaps=False,
            hovertemplate=(
                f"<b>{y_axis_label}:</b> %{{y}}<br>"
                "<b>Time:</b> %{x}<br>"
                f"<b>{color_label}:</b> %{{z:,}}<extra></extra>"
            ),
            colorbar=dict(
                title=dict(text=color_label, side="right"),
                thickness=14,
            ),
        )
    )
    fig_heatmap.update_layout(
        template=PLOTLY_TEMPLATE,
        height=max(300, len(pivot) * 38 + 80),
        margin=dict(l=20, r=20, t=30, b=80),
        xaxis=dict(
            title="Time bucket",
            tickangle=-45,
            tickfont=dict(size=10),
            side="bottom",
        ),
        yaxis=dict(title=y_axis_label, autorange="reversed"),
        paper_bgcolor="rgba(0,0,0,0)",
        plot_bgcolor="rgba(0,0,0,0)",
    )
    st.plotly_chart(fig_heatmap, use_container_width=True)

    # KPI strip
    total_evals = int(eval_df["z"].sum())
    total_viols = int(viol_df["z"].sum())
    overall_viol_rate = total_viols / max(total_evals, 1)
    peak_row = eval_df.loc[eval_df["z"].idxmax()]
    peak_entity = peak_row["y"]
    peak_time = peak_row["x"]

    k1, k2, k3, k4 = st.columns(4)
    k1.metric("Total Evaluations", f"{total_evals:,}")
    k2.metric(
        "Total Violations",
        f"{total_viols:,}",
        delta=f"{overall_viol_rate:.2%} rate",
        delta_color="inverse",
    )
    k3.metric(
        "Peak Activity",
        peak_entity,
        delta=peak_time,
        help="Entity with the highest single-bucket evaluation count",
    )
    k4.metric(
        "Violation Rate",
        f"{overall_viol_rate:.2%}",
        delta=f"{(overall_viol_rate - 0.05):.2%} vs 5% baseline",
        delta_color="inverse",
    )

    st.divider()

    # Side-by-side: eval vs violation distribution
    left_col, right_col = st.columns(2)

    with left_col:
        st.subheader("Evaluation Distribution")
        agg_eval = eval_df.groupby("y")["z"].sum().reset_index().sort_values("z", ascending=True)
        fig_eval_bar = go.Figure(
            go.Bar(
                y=agg_eval["y"],
                x=agg_eval["z"],
                orientation="h",
                marker_color=COLOR_INFO,
                hovertemplate=f"<b>%{{y}}</b><br>Evaluations: %{{x:,}}<extra></extra>",
            )
        )
        fig_eval_bar.update_layout(
            template=PLOTLY_TEMPLATE,
            height=max(220, len(agg_eval) * 32),
            margin=dict(l=10, r=20, t=10, b=30),
            xaxis_title="Evaluations",
            yaxis_title=y_axis_label,
        )
        st.plotly_chart(fig_eval_bar, use_container_width=True)

    with right_col:
        st.subheader("Violation Distribution")
        agg_viol = viol_df.groupby("y")["z"].sum().reset_index().sort_values("z", ascending=True)
        fig_viol_bar = go.Figure(
            go.Bar(
                y=agg_viol["y"],
                x=agg_viol["z"],
                orientation="h",
                marker_color=COLOR_CRITICAL,
                hovertemplate=f"<b>%{{y}}</b><br>Violations: %{{x:,}}<extra></extra>",
            )
        )
        fig_viol_bar.update_layout(
            template=PLOTLY_TEMPLATE,
            height=max(220, len(agg_viol) * 32),
            margin=dict(l=10, r=20, t=10, b=30),
            xaxis_title="Violations",
            yaxis_title=y_axis_label,
        )
        st.plotly_chart(fig_viol_bar, use_container_width=True)

    st.subheader("Summary Table")
    st.caption(
        "Sorted by total violations. 'Peak Bucket' shows the time window with the "
        "highest evaluation count — useful for spotting recurring patterns (e.g. "
        "every Tuesday at 3 PM)."
    )
    st.dataframe(summary_df, use_container_width=True, hide_index=True)

# ---------------------------------------------------------------------------
# Auto-refresh
# ---------------------------------------------------------------------------
if auto_refresh:
    time.sleep(30)
    st.rerun()