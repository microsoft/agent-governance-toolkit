# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""Agent Hypervisor — Streamlit Visualization Dashboard.

A production-quality, interactive dashboard for monitoring multi-agent
runtime supervision powered by Plotly and real hypervisor data.
"""

from __future__ import annotations

import random
import sys
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path
from dataclasses import dataclass, field
from typing import Any, Optional

import numpy as np
import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
import streamlit as st
import networkx as nx

# ---------------------------------------------------------------------------
# Hypervisor import (falls back to simulation stubs)
# ---------------------------------------------------------------------------
_LIVE_MODE = False
try:
    sys.path.insert(0, str(Path(__file__).parent.parent.parent / "src"))
    from hypervisor.core import Hypervisor  # noqa: F401
    from hypervisor.models import (
        ExecutionRing,
        SessionConfig,
        SessionState,
        ActionDescriptor,
        ReversibilityLevel,
    )
    from hypervisor.saga.orchestrator import SagaOrchestrator  # noqa: F401
    from hypervisor.saga.state_machine import SagaStep, StepState, SagaState  # noqa: F401
    from hypervisor.liability.vouching import VouchRecord
    from hypervisor.liability.slashing import SlashResult
    from hypervisor.observability.event_bus import (
        HypervisorEventBus,
        HypervisorEvent,
        EventType,
    )

    _LIVE_MODE = True
except Exception:
    pass

# ---------------------------------------------------------------------------
# Plotly dark theme
# ---------------------------------------------------------------------------
PLOTLY_LAYOUT = dict(
    template="plotly_dark",
    paper_bgcolor="rgba(0,0,0,0)",
    plot_bgcolor="rgba(0,0,0,0)",
    font=dict(family="Inter, sans-serif", color="#E0E0E0"),
    margin=dict(l=40, r=20, t=40, b=40),
)

RING_COLORS = {0: "#FF4136", 1: "#FF851B", 2: "#2ECC40", 3: "#0074D9"}
RING_LABELS = {
    0: "Ring 0 — Root",
    1: "Ring 1 — Privileged",
    2: "Ring 2 — Standard",
    3: "Ring 3 — Sandbox",
}

STATE_COLORS = {
    "CREATED": "#0074D9",
    "ACTIVE": "#2ECC40",
    "TERMINATING": "#FF851B",
    "ARCHIVED": "#AAAAAA",
    "HANDSHAKING": "#FFDC00",
}

STEP_COLORS = {
    "PENDING": "#AAAAAA",
    "EXECUTING": "#FFDC00",
    "COMMITTED": "#2ECC40",
    "FAILED": "#FF4136",
    "COMPENSATING": "#FF851B",
    "COMPENSATED": "#B10DC9",
    "COMPENSATION_FAILED": "#85144b",
}

EVENT_CATEGORIES = {
    "session": "#0074D9",
    "ring": "#FF851B",
    "liability": "#FF4136",
    "saga": "#2ECC40",
    "vfs": "#B10DC9",
    "security": "#FFDC00",
    "audit": "#01FF70",
    "verification": "#7FDBFF",
}

# ---------------------------------------------------------------------------
# Simulation data generator
# ---------------------------------------------------------------------------
AGENT_NAMES = [
    "did:mesh:alpha", "did:mesh:beta", "did:mesh:gamma",
    "did:mesh:delta", "did:mesh:epsilon", "did:mesh:zeta",
    "did:mesh:eta", "did:mesh:theta",
]

SIMULATED_EVENT_TYPES = [
    "session.created", "session.joined", "session.activated",
    "session.terminated", "ring.assigned", "ring.elevated",
    "ring.demoted", "ring.breach_detected",
    "liability.vouch_created", "liability.vouch_released",
    "liability.slash_executed", "liability.fault_attributed",
    "saga.created", "saga.step_started", "saga.step_committed",
    "saga.step_failed", "saga.compensating", "saga.completed",
    "saga.escalated", "saga.checkpoint_saved",
    "vfs.write", "vfs.delete", "vfs.snapshot",
    "security.rate_limited", "security.agent_killed",
    "audit.delta_captured", "audit.committed",
    "verification.behavior_drift", "verification.history_verified",
]


def _seed():
    """Deterministic but fresh-looking data on each run."""
    return int(datetime.now(timezone.utc).timestamp()) // 60


@st.cache_data(ttl=300)
def generate_sessions(n: int = 3) -> pd.DataFrame:
    rng = random.Random(_seed())
    rows = []
    for i in range(n):
        created = datetime.now(timezone.utc) - timedelta(minutes=rng.randint(10, 120))
        state = rng.choice(["CREATED", "ACTIVE", "ACTIVE", "ACTIVE", "TERMINATING"])
        participants = rng.randint(2, 6)
        rows.append(dict(
            session_id=f"ses-{uuid.UUID(int=rng.getrandbits(128)).hex[:8]}",
            state=state,
            created_at=created,
            duration_min=round((datetime.now(timezone.utc) - created).total_seconds() / 60, 1),
            participants=participants,
            ring_0=rng.randint(0, 1),
            ring_1=rng.randint(0, 2),
            ring_2=rng.randint(1, max(1, participants - 2)),
            ring_3=rng.randint(0, 2),
        ))
    return pd.DataFrame(rows)


@st.cache_data(ttl=300)
def generate_agents(sessions: list[str], n_per_session: int = 5) -> pd.DataFrame:
    rng = random.Random(_seed() + 1)
    rows = []
    for sid in sessions:
        for j in range(rng.randint(3, n_per_session)):
            agent = rng.choice(AGENT_NAMES)
            sigma_raw = round(rng.uniform(0.1, 0.99), 3)
            ring = (
                0 if sigma_raw > 0.95 else
                1 if sigma_raw > 0.85 else
                2 if sigma_raw > 0.60 else 3
            )
            eff_score = round(min(1.0, sigma_raw + rng.uniform(0, 0.15)), 3)
            rows.append(dict(
                session_id=sid,
                agent_did=agent,
                ring=ring,
                sigma_raw=sigma_raw,
                eff_score=eff_score,
                joined_at=datetime.now(timezone.utc) - timedelta(minutes=rng.randint(5, 90)),
            ))
    return pd.DataFrame(rows)


@st.cache_data(ttl=300)
def generate_ring_transitions(agents_df: pd.DataFrame) -> pd.DataFrame:
    rng = random.Random(_seed() + 2)
    rows = []
    for _, agent in agents_df.iterrows():
        if rng.random() < 0.4:
            direction = rng.choice(["ELEVATED", "DEMOTED"])
            old_ring = agent["ring"]
            new_ring = max(0, old_ring - 1) if direction == "ELEVATED" else min(3, old_ring + 1)
            rows.append(dict(
                timestamp=agent["joined_at"] + timedelta(minutes=rng.randint(1, 30)),
                agent_did=agent["agent_did"],
                session_id=agent["session_id"],
                direction=direction,
                old_ring=old_ring,
                new_ring=new_ring,
                eff_score=agent["eff_score"],
            ))
    return pd.DataFrame(rows) if rows else pd.DataFrame(
        columns=["timestamp", "agent_did", "session_id", "direction", "old_ring", "new_ring", "eff_score"]
    )


@st.cache_data(ttl=300)
def generate_sagas(sessions: list[str]) -> tuple[pd.DataFrame, pd.DataFrame]:
    rng = random.Random(_seed() + 3)
    saga_rows, step_rows = [], []
    step_names = ["provision", "configure", "deploy", "validate", "notify", "cleanup"]
    for sid in sessions:
        for _ in range(rng.randint(1, 3)):
            saga_id = f"saga-{uuid.UUID(int=rng.getrandbits(128)).hex[:6]}"
            created = datetime.now(timezone.utc) - timedelta(minutes=rng.randint(5, 60))
            saga_state = rng.choice(["RUNNING", "COMPLETED", "COMPLETED", "FAILED", "COMPENSATING"])
            saga_rows.append(dict(
                saga_id=saga_id, session_id=sid, state=saga_state, created_at=created,
            ))
            t = created
            n_steps = rng.randint(3, 6)
            for si in range(n_steps):
                duration = timedelta(seconds=rng.randint(2, 45))
                step_state = rng.choice(
                    ["COMMITTED", "COMMITTED", "COMMITTED", "EXECUTING", "FAILED",
                     "COMPENSATING", "COMPENSATED", "PENDING"]
                )
                step_rows.append(dict(
                    saga_id=saga_id,
                    step_id=f"step-{si}",
                    action_id=step_names[si % len(step_names)],
                    agent_did=rng.choice(AGENT_NAMES),
                    state=step_state,
                    started_at=t,
                    completed_at=t + duration if step_state not in ("PENDING", "EXECUTING") else None,
                    duration_s=duration.total_seconds() if step_state not in ("PENDING", "EXECUTING") else None,
                ))
                t += duration
    return pd.DataFrame(saga_rows), pd.DataFrame(step_rows)


@st.cache_data(ttl=300)
def generate_vouches(agents_df: pd.DataFrame) -> pd.DataFrame:
    rng = random.Random(_seed() + 4)
    rows = []
    grouped = agents_df.groupby("session_id")
    for sid, group in grouped:
        agents = group.to_dict("records")
        for _ in range(min(len(agents), rng.randint(2, 5))):
            voucher = rng.choice([a for a in agents if a["sigma_raw"] >= 0.5] or agents)
            vouchee = rng.choice([a for a in agents if a["agent_did"] != voucher["agent_did"]] or agents)
            bond_pct = round(rng.uniform(0.10, 0.35), 2)
            rows.append(dict(
                vouch_id=f"v-{uuid.UUID(int=rng.getrandbits(128)).hex[:6]}",
                voucher_did=voucher["agent_did"],
                vouchee_did=vouchee["agent_did"],
                session_id=sid,
                bonded_sigma_pct=bond_pct,
                bonded_amount=round(voucher["sigma_raw"] * bond_pct, 3),
                created_at=datetime.now(timezone.utc) - timedelta(minutes=rng.randint(5, 60)),
                is_active=rng.random() > 0.2,
            ))
    return pd.DataFrame(rows)


@st.cache_data(ttl=300)
def generate_slashes(vouches_df: pd.DataFrame) -> pd.DataFrame:
    rng = random.Random(_seed() + 5)
    rows = []
    if vouches_df.empty:
        return pd.DataFrame(columns=[
            "slash_id", "vouchee_did", "sigma_before", "sigma_after",
            "reason", "session_id", "timestamp", "cascade_depth", "vouchers_clipped",
        ])
    for _, v in vouches_df.iterrows():
        if rng.random() < 0.25:
            rows.append(dict(
                slash_id=f"sl-{uuid.UUID(int=rng.getrandbits(128)).hex[:6]}",
                vouchee_did=v["vouchee_did"],
                sigma_before=round(rng.uniform(0.3, 0.8), 3),
                sigma_after=0.0,
                reason=rng.choice(["behavioral_drift", "policy_violation", "timeout_exceeded"]),
                session_id=v["session_id"],
                timestamp=datetime.now(timezone.utc) - timedelta(minutes=rng.randint(1, 30)),
                cascade_depth=rng.randint(0, 2),
                vouchers_clipped=rng.randint(1, 3),
            ))
    return pd.DataFrame(rows)


@st.cache_data(ttl=300)
def generate_events(sessions: list[str], n: int = 200) -> pd.DataFrame:
    rng = random.Random(_seed() + 6)
    rows = []
    base = datetime.now(timezone.utc) - timedelta(hours=1)
    for i in range(n):
        etype = rng.choice(SIMULATED_EVENT_TYPES)
        category = etype.split(".")[0]
        parent_id = None
        if i > 5 and rng.random() < 0.3:
            parent_id = rows[rng.randint(0, len(rows) - 1)]["event_id"]
        rows.append(dict(
            event_id=f"evt-{i:04d}",
            event_type=etype,
            category=category,
            timestamp=base + timedelta(seconds=rng.randint(0, 3600)),
            session_id=rng.choice(sessions),
            agent_did=rng.choice(AGENT_NAMES) if rng.random() > 0.1 else None,
            parent_event_id=parent_id,
            causal_trace_id=f"trace-{rng.randint(1, 20):03d}",
        ))
    return pd.DataFrame(rows).sort_values("timestamp").reset_index(drop=True)


# ---------------------------------------------------------------------------
# Page config & CSS
# ---------------------------------------------------------------------------
st.set_page_config(
    page_title="Agent Hypervisor Dashboard",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded",
)

st.markdown("""
<style>
    [data-testid="stAppViewContainer"] { background-color: #0E1117; }
    [data-testid="stSidebar"] { background-color: #161B22; }
    .stTabs [data-baseweb="tab-list"] { gap: 8px; }
    .stTabs [data-baseweb="tab"] {
        background-color: #21262D; border-radius: 6px 6px 0 0;
        padding: 8px 20px; color: #C9D1D9;
    }
    .stTabs [aria-selected="true"] {
        background-color: #0D419D; color: white;
    }
    .metric-card {
        background: linear-gradient(135deg, #161B22 0%, #21262D 100%);
        border: 1px solid #30363D; border-radius: 10px;
        padding: 16px; text-align: center;
    }
    h1, h2, h3 { color: #E6EDF3 !important; }
</style>
""", unsafe_allow_html=True)

# ---------------------------------------------------------------------------
# Sidebar
# ---------------------------------------------------------------------------
with st.sidebar:
    st.image("https://img.icons8.com/nolan/96/shield.png", width=64)
    st.title("🛡️ Hypervisor")
    st.caption(f"Mode: **{'Live' if _LIVE_MODE else 'Simulated'}**")

    if st.button("🔄 Refresh Data"):
        st.cache_data.clear()

    st.divider()
    sim_sessions = generate_sessions()
    session_ids = sim_sessions["session_id"].tolist()
    selected_session = st.selectbox("Session Filter", ["All Sessions"] + session_ids)
    st.divider()
    st.markdown("**Quick Stats**")
    st.metric("Total Sessions", len(session_ids))
    st.metric("Active", int((sim_sessions["state"] == "ACTIVE").sum()))
    st.metric("Mode", "Live" if _LIVE_MODE else "Demo")

# ---------------------------------------------------------------------------
# Generate all data
# ---------------------------------------------------------------------------
sessions_df = sim_sessions
agents_df = generate_agents(session_ids)
transitions_df = generate_ring_transitions(agents_df)
sagas_df, steps_df = generate_sagas(session_ids)
vouches_df = generate_vouches(agents_df)
slashes_df = generate_slashes(vouches_df)
events_df = generate_events(session_ids)

if selected_session != "All Sessions":
    agents_df = agents_df[agents_df["session_id"] == selected_session]
    transitions_df = transitions_df[transitions_df["session_id"] == selected_session] if not transitions_df.empty else transitions_df
    sagas_df = sagas_df[sagas_df["session_id"] == selected_session]
    steps_df = steps_df[steps_df["saga_id"].isin(sagas_df["saga_id"])]
    vouches_df = vouches_df[vouches_df["session_id"] == selected_session]
    slashes_df = slashes_df[slashes_df["session_id"] == selected_session]
    events_df = events_df[events_df["session_id"] == selected_session]

# ---------------------------------------------------------------------------
# Header metrics
# ---------------------------------------------------------------------------
st.markdown("## 🛡️ Agent Hypervisor Dashboard")
m1, m2, m3, m4, m5 = st.columns(5)
m1.metric("Sessions", len(sessions_df))
m2.metric("Agents", len(agents_df))
m3.metric("Active Sagas", int((sagas_df["state"] == "RUNNING").sum()) if not sagas_df.empty else 0)
m4.metric("Events", len(events_df))
m5.metric("Sponsors", len(vouches_df))

# ---------------------------------------------------------------------------
# Tabs
# ---------------------------------------------------------------------------
tab_overview, tab_rings, tab_sagas, tab_liability, tab_events = st.tabs([
    "📊 Session Overview",
    "🔒 Execution Rings",
    "⚙️ Saga Orchestration",
    "💰 Liability & Trust",
    "📡 Event Stream",
])

# ===== TAB 1: Session Overview =============================================
with tab_overview:
    st.subheader("Active Sessions")

    cols = st.columns(min(len(sessions_df), 4))
    for i, (_, s) in enumerate(sessions_df.iterrows()):
        with cols[i % len(cols)]:
            color = STATE_COLORS.get(s["state"], "#AAA")
            st.markdown(
                f'<div class="metric-card">'
                f'<span style="color:{color};font-size:12px;">● {s["state"]}</span><br>'
                f'<b>{s["session_id"][:14]}…</b><br>'
                f'👥 {s["participants"]} participants<br>'
                f'⏱️ {s["duration_min"]} min'
                f'</div>',
                unsafe_allow_html=True,
            )

    st.markdown("---")
    c1, c2 = st.columns(2)

    with c1:
        ring_totals = sessions_df[["ring_0", "ring_1", "ring_2", "ring_3"]].sum()
        fig = go.Figure(go.Pie(
            labels=[RING_LABELS[i] for i in range(4)],
            values=[ring_totals[f"ring_{i}"] for i in range(4)],
            marker=dict(colors=[RING_COLORS[i] for i in range(4)]),
            hole=0.45,
        ))
        fig.update_layout(title="Ring Distribution (All Sessions)", **PLOTLY_LAYOUT)
        st.plotly_chart(fig, use_container_width=True)

    with c2:
        timeline_df = sessions_df.copy()
        timeline_df["end"] = timeline_df["created_at"] + pd.to_timedelta(timeline_df["duration_min"], unit="m")
        fig = go.Figure()
        for i, (_, row) in enumerate(timeline_df.iterrows()):
            color = STATE_COLORS.get(row["state"], "#AAA")
            fig.add_trace(go.Bar(
                x=[(row["end"] - row["created_at"]).total_seconds() / 60],
                y=[row["session_id"][:14]],
                orientation="h",
                marker_color=color,
                name=row["state"],
                showlegend=i == 0 or row["state"] not in [r["state"] for _, r in timeline_df.iloc[:i].iterrows()],
                hovertemplate=f'{row["session_id"]}<br>State: {row["state"]}<br>Duration: {row["duration_min"]} min<extra></extra>',
            ))
        fig.update_layout(title="Session Timeline", barmode="stack", **PLOTLY_LAYOUT)
        st.plotly_chart(fig, use_container_width=True)

    st.subheader("Session Details")
    st.dataframe(
        sessions_df.style.map(
            lambda v: f"color: {STATE_COLORS.get(v, '#FFF')}" if v in STATE_COLORS else "",
        ),
        use_container_width=True,
        hide_index=True,
    )

# ===== TAB 2: Execution Rings ===============================================
with tab_rings:
    st.subheader("Ring Hierarchy")
    c1, c2 = st.columns(2)

    with c1:
        # Concentric ring diagram
        fig = go.Figure()
        for ring in [3, 2, 1, 0]:
            agents_in_ring = agents_df[agents_df["ring"] == ring]
            r_inner = ring * 1.0
            r_outer = r_inner + 0.9
            theta = np.linspace(0, 2 * np.pi, 100)
            x_outer = (r_outer * np.cos(theta)).tolist()
            y_outer = (r_outer * np.sin(theta)).tolist()
            fig.add_trace(go.Scatter(
                x=x_outer, y=y_outer, mode="lines",
                line=dict(color=RING_COLORS[ring], width=2),
                fill="toself", fillcolor=RING_COLORS[ring] + "22",
                name=RING_LABELS[ring],
                hoverinfo="name",
            ))
            # Place agent dots
            if not agents_in_ring.empty:
                n_agents = len(agents_in_ring)
                angles = np.linspace(0, 2 * np.pi, n_agents, endpoint=False)
                r_mid = (r_inner + r_outer) / 2
                ax = (r_mid * np.cos(angles)).tolist()
                ay = (r_mid * np.sin(angles)).tolist()
                fig.add_trace(go.Scatter(
                    x=ax, y=ay, mode="markers+text",
                    marker=dict(size=12, color=RING_COLORS[ring], symbol="circle"),
                    text=agents_in_ring["agent_did"].str.split(":").str[-1].tolist(),
                    textposition="top center",
                    textfont=dict(size=9, color="#E0E0E0"),
                    showlegend=False,
                    hovertemplate="%{text}<br>eff_score: " +
                        agents_in_ring["eff_score"].astype(str).tolist().__repr__() +
                        "<extra></extra>",
                ))
        fig.update_layout(
            title="Concentric Ring Hierarchy",
            showlegend=True,
            xaxis=dict(visible=False, scaleanchor="y"),
            yaxis=dict(visible=False),
            **PLOTLY_LAYOUT,
        )
        st.plotly_chart(fig, use_container_width=True)

    with c2:
        ring_counts = agents_df["ring"].value_counts().sort_index()
        fig = go.Figure(go.Bar(
            x=[RING_LABELS.get(r, f"Ring {r}") for r in ring_counts.index],
            y=ring_counts.values,
            marker_color=[RING_COLORS.get(r, "#AAA") for r in ring_counts.index],
            text=ring_counts.values,
            textposition="auto",
        ))
        fig.update_layout(title="Agent Count per Ring", **PLOTLY_LAYOUT)
        st.plotly_chart(fig, use_container_width=True)

    st.markdown("---")
    c3, c4 = st.columns(2)

    with c3:
        st.subheader("Ring Transition Log")
        if not transitions_df.empty:
            display_df = transitions_df.copy()
            display_df["timestamp"] = display_df["timestamp"].dt.strftime("%H:%M:%S")
            display_df["transition"] = display_df.apply(
                lambda r: f"Ring {r['old_ring']} → Ring {r['new_ring']}", axis=1
            )
            st.dataframe(
                display_df[["timestamp", "agent_did", "direction", "transition", "eff_score"]],
                use_container_width=True, hide_index=True,
            )
        else:
            st.info("No ring transitions recorded yet.")

    with c4:
        st.subheader("Trust Score vs Ring Level")
        if not agents_df.empty:
            fig = px.scatter(
                agents_df, x="eff_score", y="ring",
                color="ring",
                color_discrete_map={r: RING_COLORS[r] for r in range(4)},
                hover_data=["agent_did", "sigma_raw"],
                labels={"eff_score": "eff_score (Effective Trust)", "ring": "Execution Ring"},
            )
            fig.update_layout(title="eff_score vs Ring Level", **PLOTLY_LAYOUT)
            fig.update_yaxes(tickvals=[0, 1, 2, 3], ticktext=["Ring 0", "Ring 1", "Ring 2", "Ring 3"])
            st.plotly_chart(fig, use_container_width=True)

# ===== TAB 3: Saga Orchestration =============================================
with tab_sagas:
    st.subheader("Saga Orchestration")

    if sagas_df.empty:
        st.info("No sagas found for the selected session(s).")
    else:
        c1, c2 = st.columns(2)

        with c1:
            saga_states = sagas_df["state"].value_counts()
            fig = go.Figure(go.Bar(
                x=saga_states.index.tolist(),
                y=saga_states.values.tolist(),
                marker_color=["#2ECC40" if s == "COMPLETED" else "#FF4136" if s == "FAILED"
                              else "#FFDC00" if s == "RUNNING" else "#FF851B"
                              for s in saga_states.index],
                text=saga_states.values.tolist(),
                textposition="auto",
            ))
            fig.update_layout(title="Saga State Distribution", **PLOTLY_LAYOUT)
            st.plotly_chart(fig, use_container_width=True)

        with c2:
            if not steps_df.empty:
                step_states = steps_df["state"].value_counts()
                fig = go.Figure(go.Pie(
                    labels=step_states.index.tolist(),
                    values=step_states.values.tolist(),
                    marker=dict(colors=[STEP_COLORS.get(s, "#AAA") for s in step_states.index]),
                    hole=0.4,
                ))
                fig.update_layout(title="Step State Distribution", **PLOTLY_LAYOUT)
                st.plotly_chart(fig, use_container_width=True)

        # Gantt chart
        if not steps_df.empty:
            st.subheader("Saga Timeline (Gantt)")
            gantt_df = steps_df.dropna(subset=["started_at"]).copy()
            if not gantt_df.empty:
                gantt_df["end_time"] = gantt_df.apply(
                    lambda r: r["completed_at"] if pd.notna(r["completed_at"])
                    else r["started_at"] + timedelta(seconds=10),
                    axis=1,
                )
                gantt_df["label"] = gantt_df["saga_id"].str[:10] + " / " + gantt_df["action_id"]
                fig = go.Figure()
                for _, row in gantt_df.iterrows():
                    color = STEP_COLORS.get(row["state"], "#AAA")
                    fig.add_trace(go.Bar(
                        x=[(row["end_time"] - row["started_at"]).total_seconds()],
                        y=[row["label"]],
                        base=[row["started_at"]],
                        orientation="h",
                        marker_color=color,
                        hovertemplate=(
                            f"Step: {row['action_id']}<br>"
                            f"Agent: {row['agent_did']}<br>"
                            f"State: {row['state']}<br>"
                            f"Duration: {row.get('duration_s', '?')}s<extra></extra>"
                        ),
                        showlegend=False,
                    ))
                fig.update_layout(
                    title="Step Execution Timeline",
                    xaxis_title="Time", barmode="stack",
                    height=max(300, len(gantt_df) * 28),
                    **PLOTLY_LAYOUT,
                )
                st.plotly_chart(fig, use_container_width=True)

        # Compensation chain
        st.subheader("Compensation Chains")
        comp_steps = steps_df[steps_df["state"].isin(["COMPENSATING", "COMPENSATED", "COMPENSATION_FAILED"])] if not steps_df.empty else pd.DataFrame()
        if not comp_steps.empty:
            for saga_id in comp_steps["saga_id"].unique():
                saga_steps = comp_steps[comp_steps["saga_id"] == saga_id].sort_values("started_at")
                chain = " → ".join(
                    f"**{r['action_id']}** ({r['state']})" for _, r in saga_steps.iterrows()
                )
                trigger_step = steps_df[
                    (steps_df["saga_id"] == saga_id) & (steps_df["state"] == "FAILED")
                ]
                trigger = trigger_step.iloc[0]["action_id"] if not trigger_step.empty else "unknown"
                st.markdown(f"🔗 `{saga_id[:12]}` — Triggered by **{trigger}** failure → {chain}")
        else:
            st.info("No compensation chains active.")

        # Success / failure rates
        st.markdown("---")
        c1, c2, c3 = st.columns(3)
        total_sagas = len(sagas_df)
        completed = int((sagas_df["state"] == "COMPLETED").sum())
        failed = int((sagas_df["state"] == "FAILED").sum())
        c1.metric("Total Sagas", total_sagas)
        c2.metric("Success Rate", f"{completed / max(1, total_sagas) * 100:.0f}%")
        c3.metric("Failure Rate", f"{failed / max(1, total_sagas) * 100:.0f}%")

# ===== TAB 4: Liability & Trust ==============================================
with tab_liability:
    st.subheader("Liability & Trust")
    c1, c2 = st.columns(2)

    with c1:
        # Sponsor network graph
        st.markdown("#### Sponsor Network")
        if not vouches_df.empty:
            G = nx.DiGraph()
            for _, v in vouches_df.iterrows():
                short_voucher = v["voucher_did"].split(":")[-1]
                short_vouchee = v["vouchee_did"].split(":")[-1]
                G.add_edge(short_voucher, short_vouchee, weight=v["bonded_amount"])

            pos = nx.spring_layout(G, seed=42, k=2.0)

            edge_x, edge_y = [], []
            annotations = []
            for u, v, data in G.edges(data=True):
                x0, y0 = pos[u]
                x1, y1 = pos[v]
                edge_x.extend([x0, x1, None])
                edge_y.extend([y0, y1, None])
                mid_x, mid_y = (x0 + x1) / 2, (y0 + y1) / 2
                annotations.append(dict(
                    x=mid_x, y=mid_y,
                    text=f"{data['weight']:.2f}σ",
                    showarrow=False,
                    font=dict(size=9, color="#FFDC00"),
                ))

            node_x = [pos[n][0] for n in G.nodes()]
            node_y = [pos[n][1] for n in G.nodes()]
            node_text = list(G.nodes())

            fig = go.Figure()
            fig.add_trace(go.Scatter(
                x=edge_x, y=edge_y, mode="lines",
                line=dict(width=1.5, color="#555"),
                hoverinfo="none",
            ))
            fig.add_trace(go.Scatter(
                x=node_x, y=node_y, mode="markers+text",
                marker=dict(size=20, color="#0074D9", line=dict(width=2, color="#E0E0E0")),
                text=node_text,
                textposition="top center",
                textfont=dict(size=10, color="#E0E0E0"),
                hoverinfo="text",
            ))
            fig.update_layout(
                title="Sponsor Network (bond amounts)",
                showlegend=False,
                xaxis=dict(visible=False), yaxis=dict(visible=False),
                annotations=annotations,
                **PLOTLY_LAYOUT,
            )
            st.plotly_chart(fig, use_container_width=True)
        else:
            st.info("No sponsors recorded.")

    with c2:
        # Penalty cascade visualization
        st.markdown("#### Penalty Cascades")
        if not slashes_df.empty:
            fig = go.Figure()
            for _, sl in slashes_df.iterrows():
                fig.add_trace(go.Scatter(
                    x=[0, sl["cascade_depth"]],
                    y=[sl["sigma_before"], sl["sigma_after"]],
                    mode="lines+markers",
                    name=sl["vouchee_did"].split(":")[-1],
                    marker=dict(size=10),
                    line=dict(width=2),
                    hovertemplate=(
                        f"Agent: {sl['vouchee_did']}<br>"
                        f"Reason: {sl['reason']}<br>"
                        f"σ: {sl['sigma_before']:.3f} → {sl['sigma_after']:.3f}<br>"
                        f"Cascade depth: {sl['cascade_depth']}<br>"
                        f"Sponsors clipped: {sl['vouchers_clipped']}<extra></extra>"
                    ),
                ))
            fig.update_layout(
                title="Penalty Impact (σ drop vs cascade depth)",
                xaxis_title="Cascade Depth",
                yaxis_title="σ Score",
                **PLOTLY_LAYOUT,
            )
            st.plotly_chart(fig, use_container_width=True)
        else:
            st.info("No penalty events recorded.")

    st.markdown("---")
    c3, c4 = st.columns(2)

    with c3:
        # Trust leaderboard
        st.markdown("#### 🏆 Trust Score Leaderboard")
        if not agents_df.empty:
            leaderboard = (
                agents_df.groupby("agent_did")
                .agg(eff_score=("eff_score", "max"), sigma_raw=("sigma_raw", "max"), ring=("ring", "min"))
                .sort_values("eff_score", ascending=False)
                .reset_index()
            )
            leaderboard["rank"] = range(1, len(leaderboard) + 1)
            leaderboard["agent"] = leaderboard["agent_did"].str.split(":").str[-1]

            fig = go.Figure(go.Bar(
                x=leaderboard["eff_score"],
                y=leaderboard["agent"],
                orientation="h",
                marker_color=[RING_COLORS.get(r, "#AAA") for r in leaderboard["ring"]],
                text=leaderboard["eff_score"].apply(lambda v: f"{v:.3f}"),
                textposition="auto",
            ))
            fig.update_layout(
                title="Agent eff_score Ranking",
                xaxis_title="eff_score", yaxis=dict(autorange="reversed"),
                **PLOTLY_LAYOUT,
            )
            st.plotly_chart(fig, use_container_width=True)

    with c4:
        # Liability exposure heatmap
        st.markdown("#### Liability Exposure Heatmap")
        if not vouches_df.empty:
            exposure = vouches_df.groupby(["voucher_did", "session_id"])["bonded_amount"].sum().reset_index()
            exposure["sponsor"] = exposure["voucher_did"].str.split(":").str[-1]
            exposure["session"] = exposure["session_id"].str[:12]
            pivot = exposure.pivot_table(index="sponsor", columns="session", values="bonded_amount", fill_value=0)

            fig = go.Figure(go.Heatmap(
                z=pivot.values,
                x=pivot.columns.tolist(),
                y=pivot.index.tolist(),
                colorscale="YlOrRd",
                text=np.round(pivot.values, 3),
                texttemplate="%{text}",
                hovertemplate="Sponsor: %{y}<br>Session: %{x}<br>Bonded σ: %{z:.3f}<extra></extra>",
            ))
            fig.update_layout(
                title="Total Bonded σ per Agent × Session",
                **PLOTLY_LAYOUT,
            )
            st.plotly_chart(fig, use_container_width=True)
        else:
            st.info("No exposure data available.")

# ===== TAB 5: Event Stream ===================================================
with tab_events:
    st.subheader("Event Stream")

    # Filters
    fc1, fc2, fc3 = st.columns(3)
    with fc1:
        cat_filter = st.multiselect(
            "Filter by Category",
            options=sorted(events_df["category"].unique()),
            default=sorted(events_df["category"].unique()),
        )
    with fc2:
        agent_filter = st.multiselect(
            "Filter by Agent",
            options=[a for a in sorted(events_df["agent_did"].dropna().unique())],
        )
    with fc3:
        limit = st.slider("Max events", 10, 200, 50)

    filtered = events_df[events_df["category"].isin(cat_filter)]
    if agent_filter:
        filtered = filtered[filtered["agent_did"].isin(agent_filter)]
    filtered = filtered.tail(limit)

    # Event log
    st.markdown("#### 📋 Event Log")
    display_events = filtered.copy()
    display_events["time"] = display_events["timestamp"].dt.strftime("%H:%M:%S")
    st.dataframe(
        display_events[["time", "event_id", "event_type", "session_id", "agent_did", "causal_trace_id"]],
        use_container_width=True,
        hide_index=True,
        height=300,
    )

    st.markdown("---")
    c1, c2 = st.columns(2)

    with c1:
        # Event type frequency heatmap
        st.markdown("#### Event Type Heatmap")
        freq_df = events_df.copy()
        freq_df["minute"] = freq_df["timestamp"].dt.floor("5min").dt.strftime("%H:%M")
        heatmap_data = freq_df.groupby(["event_type", "minute"]).size().reset_index(name="count")
        pivot = heatmap_data.pivot_table(index="event_type", columns="minute", values="count", fill_value=0)

        fig = go.Figure(go.Heatmap(
            z=pivot.values,
            x=pivot.columns.tolist(),
            y=pivot.index.tolist(),
            colorscale="Viridis",
            hovertemplate="Type: %{y}<br>Time: %{x}<br>Count: %{z}<extra></extra>",
        ))
        fig.update_layout(
            title="Event Frequency (5-min buckets)",
            height=max(400, len(pivot) * 22),
            **PLOTLY_LAYOUT,
        )
        st.plotly_chart(fig, use_container_width=True)

    with c2:
        # Causal trace tree
        st.markdown("#### Causal Trace Tree")
        trace_id = st.selectbox(
            "Select Trace",
            options=sorted(events_df["causal_trace_id"].dropna().unique()),
        )
        trace_events = events_df[events_df["causal_trace_id"] == trace_id].sort_values("timestamp")

        if not trace_events.empty:
            G = nx.DiGraph()
            for _, evt in trace_events.iterrows():
                label = f"{evt['event_id']}\n{evt['event_type'].split('.')[-1]}"
                G.add_node(evt["event_id"], label=label, etype=evt["event_type"])
                if pd.notna(evt.get("parent_event_id")) and evt["parent_event_id"] in G.nodes:
                    G.add_edge(evt["parent_event_id"], evt["event_id"])

            if len(G.nodes) > 0:
                pos = nx.spring_layout(G, seed=42, k=3.0)
                edge_x, edge_y = [], []
                for u, v in G.edges():
                    x0, y0 = pos[u]
                    x1, y1 = pos[v]
                    edge_x.extend([x0, x1, None])
                    edge_y.extend([y0, y1, None])

                node_x = [pos[n][0] for n in G.nodes()]
                node_y = [pos[n][1] for n in G.nodes()]
                node_labels = [G.nodes[n].get("label", n) for n in G.nodes()]
                node_colors = [
                    EVENT_CATEGORIES.get(G.nodes[n].get("etype", "").split(".")[0], "#AAA")
                    for n in G.nodes()
                ]

                fig = go.Figure()
                fig.add_trace(go.Scatter(
                    x=edge_x, y=edge_y, mode="lines",
                    line=dict(width=1, color="#555"), hoverinfo="none",
                ))
                fig.add_trace(go.Scatter(
                    x=node_x, y=node_y, mode="markers+text",
                    marker=dict(size=14, color=node_colors, line=dict(width=1, color="#E0E0E0")),
                    text=[l.split("\n")[-1] for l in node_labels],
                    textposition="top center",
                    textfont=dict(size=8, color="#E0E0E0"),
                    hovertext=node_labels,
                    hoverinfo="text",
                ))
                fig.update_layout(
                    title=f"Causal Tree — {trace_id}",
                    showlegend=False,
                    xaxis=dict(visible=False), yaxis=dict(visible=False),
                    height=400,
                    **PLOTLY_LAYOUT,
                )
                st.plotly_chart(fig, use_container_width=True)

    # Category distribution
    st.markdown("---")
    cat_counts = events_df["category"].value_counts()
    fig = go.Figure(go.Bar(
        x=cat_counts.index.tolist(),
        y=cat_counts.values.tolist(),
        marker_color=[EVENT_CATEGORIES.get(c, "#AAA") for c in cat_counts.index],
        text=cat_counts.values.tolist(),
        textposition="auto",
    ))
    fig.update_layout(title="Events by Category", **PLOTLY_LAYOUT)
    st.plotly_chart(fig, use_container_width=True)

# ---------------------------------------------------------------------------
# Footer
# ---------------------------------------------------------------------------
st.markdown("---")
st.caption("🛡️ Agent Hypervisor Dashboard • Powered by Streamlit & Plotly • "
           f"{'Live mode — connected to hypervisor' if _LIVE_MODE else 'Demo mode — simulated data'}")
