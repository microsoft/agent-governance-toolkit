# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

from __future__ import annotations

import html
import time

import pandas as pd
import plotly.express as px
import streamlit as st

from simulator import AGENTS, DECISIONS, POLICIES, append_events, initialize_state


DECISION_COLORS = {"allow": "#1e9d63", "deny": "#c43d2c", "escalate": "#d18b00"}
SEVERITY_ORDER = {"critical": 4, "high": 3, "medium": 2, "low": 1, "none": 0}


st.set_page_config(
    page_title="Agent Governance Dashboard",
    page_icon="\U0001f6e1\ufe0f",
    layout="wide",
)

st.markdown(
    """
    <style>
    :root {
        --agd-bg-1: #f2f7f4;
        --agd-bg-2: #e8efe8;
        --agd-card: #ffffff;
        --agd-text: #132026;
        --agd-muted: #4c5c5f;
        --agd-accent: #0f6b78;
        --agd-border: #dbe6e2;
    }

    .stApp {
        background:
          radial-gradient(circle at 12% 8%, #d7ece2 0%, rgba(215, 236, 226, 0) 38%),
          radial-gradient(circle at 88% 14%, #f5e8d2 0%, rgba(245, 232, 210, 0) 34%),
          linear-gradient(145deg, var(--agd-bg-1), var(--agd-bg-2));
        color: var(--agd-text);
                font-family: "Segoe UI", "Helvetica Neue", Arial, sans-serif;
    }

    h1, h2, h3 {
                font-family: "Segoe UI", "Helvetica Neue", Arial, sans-serif !important;
        letter-spacing: -0.01em;
    }

    .agd-hero {
        border: 1px solid var(--agd-border);
        background: linear-gradient(120deg, #ffffff 0%, #f7fbf9 100%);
        border-radius: 16px;
        padding: 1rem 1.2rem;
        margin-bottom: 0.65rem;
        box-shadow: 0 12px 30px rgba(26, 66, 58, 0.08);
        animation: agdFadeUp 0.55s ease-out;
    }

    .agd-hero h2 {
        margin: 0;
        font-size: 1.55rem;
        color: var(--agd-text);
    }

    .agd-hero p {
        margin: 0.4rem 0 0.2rem 0;
        color: var(--agd-muted);
    }

    .agd-badges {
        margin-top: 0.55rem;
        display: flex;
        gap: 0.45rem;
        flex-wrap: wrap;
    }

    .agd-badge {
        background: #e8f5f3;
        border: 1px solid #cce7e2;
        color: #0f6b78;
        padding: 0.24rem 0.6rem;
        border-radius: 999px;
        font-size: 0.76rem;
        font-weight: 700;
        text-transform: uppercase;
        letter-spacing: 0.04em;
    }

    .agd-kpi-grid {
        display: grid;
        grid-template-columns: repeat(4, minmax(0, 1fr));
        gap: 0.65rem;
        margin: 0.4rem 0 0.9rem 0;
    }

    .agd-kpi {
        border: 1px solid var(--agd-border);
        background: var(--agd-card);
        border-radius: 14px;
        padding: 0.65rem 0.85rem;
        box-shadow: 0 8px 18px rgba(17, 58, 50, 0.06);
        animation: agdFadeUp 0.5s ease-out;
    }

    .agd-kpi-label {
        font-size: 0.75rem;
        color: var(--agd-muted);
        text-transform: uppercase;
        letter-spacing: 0.06em;
        font-weight: 700;
    }

    .agd-kpi-value {
        font-size: 1.4rem;
        font-weight: 700;
        margin-top: 0.05rem;
    }

    .agd-kpi-sub {
        font-size: 0.74rem;
        color: #5f7273;
        margin-top: 0.1rem;
    }

    .agd-kpi-allow .agd-kpi-value { color: #1e9d63; }
    .agd-kpi-deny .agd-kpi-value { color: #c43d2c; }
    .agd-kpi-escalate .agd-kpi-value { color: #b67600; }

    code {
        font-family: "Consolas", "Courier New", monospace !important;
    }

    @media (max-width: 960px) {
        .agd-kpi-grid {
            grid-template-columns: repeat(2, minmax(0, 1fr));
        }
    }

    @keyframes agdFadeUp {
        from { opacity: 0; transform: translateY(8px); }
        to { opacity: 1; transform: translateY(0); }
    }
    </style>
    """,
    unsafe_allow_html=True,
)

initialize_state()

df: pd.DataFrame = st.session_state.events.copy()
df["timestamp"] = pd.to_datetime(df["timestamp"])


def _decision_counts(data: pd.DataFrame) -> pd.Series:
    return data["decision"].value_counts().reindex(DECISIONS, fill_value=0)


def _severity_badge(value: str) -> str:
    mapping = {
        "critical": "🔴 Critical",
        "high": "🟠 High",
        "medium": "🟡 Medium",
        "low": "🟢 Low",
        "none": "None",
    }
    return mapping.get(str(value).lower(), str(value).title())


def _style_feed(df_in: pd.DataFrame) -> pd.io.formats.style.Styler:
    def _row_style(row: pd.Series) -> list[str]:
        if row.get("status", "") == "NEW":
            return ["background-color: #fff5cc; font-weight: 700;"] * len(row)
        return [""] * len(row)

    return df_in.style.apply(_row_style, axis=1)


def _style_alerts(df_in: pd.DataFrame) -> pd.io.formats.style.Styler:
    def _severity_cell_style(value: str) -> str:
        if "Critical" in value:
            return "background-color: #ffe1df; color: #92251a; font-weight: 700;"
        if "High" in value:
            return "background-color: #ffecd7; color: #915100; font-weight: 700;"
        if "Medium" in value:
            return "background-color: #fff8d8; color: #7a6200; font-weight: 700;"
        return ""

    return df_in.style.map(_severity_cell_style, subset=["severity"])


def _render_kpi_cards(total: int, counts: pd.Series) -> None:
    allow_count = int(counts.get("allow", 0))
    deny_count = int(counts.get("deny", 0))
    escalate_count = int(counts.get("escalate", 0))

    def _pct(value: int) -> str:
        if total <= 0:
            return "0.0"
        return f"{(100.0 * value / total):.1f}"

    st.markdown(
        f"""
        <div class="agd-kpi-grid">
            <div class="agd-kpi">
                <div class="agd-kpi-label" title="Total number of policy evaluations after filters are applied">Evaluations</div>
                <div class="agd-kpi-value">{total:,}</div>
                <div class="agd-kpi-sub">Active filtered events</div>
            </div>
            <div class="agd-kpi agd-kpi-allow">
                <div class="agd-kpi-label" title="Evaluations permitted by current policy controls">Allow</div>
                <div class="agd-kpi-value">{allow_count:,}</div>
                <div class="agd-kpi-sub">{_pct(allow_count)}% of evaluations</div>
            </div>
            <div class="agd-kpi agd-kpi-deny">
                <div class="agd-kpi-label" title="Evaluations blocked by governance policy checks">Deny</div>
                <div class="agd-kpi-value">{deny_count:,}</div>
                <div class="agd-kpi-sub">{_pct(deny_count)}% of evaluations</div>
            </div>
            <div class="agd-kpi agd-kpi-escalate">
                <div class="agd-kpi-label" title="Evaluations requiring human or policy escalation">Escalate</div>
                <div class="agd-kpi-value">{escalate_count:,}</div>
                <div class="agd-kpi-sub">{_pct(escalate_count)}% of evaluations</div>
            </div>
        </div>
        """,
        unsafe_allow_html=True,
    )


st.markdown(
    """
    <div class="agd-hero">
        <h2>Agent Governance Dashboard</h2>
        <p>Real-time policy monitoring for agent interactions and trust posture.</p>
        <div class="agd-badges">
            <span class="agd-badge">Live Monitoring</span>
            <span class="agd-badge">Simulated Data</span>
            <span class="agd-badge">Audit Ready</span>
        </div>
    </div>
    """,
    unsafe_allow_html=True,
)

with st.sidebar:
    st.header("Controls")
    live_mode = st.toggle("Live mode", value=True)
    refresh_seconds = st.slider("Refresh interval (seconds)", min_value=1, max_value=10, value=2)
    events_per_tick = st.slider("Events per tick", min_value=1, max_value=15, value=4)

    if st.button("Generate one tick now", use_container_width=True):
        append_events(events_per_tick)
        st.rerun()

    st.divider()
    st.subheader("Filters")
    selected_agents = st.multiselect("Agent involvement", AGENTS, default=AGENTS)
    selected_decisions = st.multiselect("Decision", DECISIONS, default=DECISIONS)
    selected_policies = st.multiselect("Policy", POLICIES, default=POLICIES)

# Defensive checks in case values are programmatically mutated in session state.
refresh_seconds = max(1, min(10, int(refresh_seconds)))
events_per_tick = max(1, min(15, int(events_per_tick)))
selected_agents = [a for a in selected_agents if a in AGENTS]
selected_decisions = [d for d in selected_decisions if d in DECISIONS]
selected_policies = [p for p in selected_policies if p in POLICIES]

filtered = df[
    (df["agent_source"].isin(selected_agents) | df["agent_target"].isin(selected_agents))
    & df["decision"].isin(selected_decisions)
    & df["policy_name"].isin(selected_policies)
].copy()

counts = _decision_counts(filtered)
violations = filtered[filtered["violation"]]
last_updated = filtered["timestamp"].max() if not filtered.empty else df["timestamp"].max()

live_badge = "🟢 Live" if live_mode else "⚪ Paused"
last_updated_text = last_updated.strftime("%H:%M:%S") if pd.notna(last_updated) else "N/A"
st.caption(f"{live_badge} | Last updated: {last_updated_text}")

_render_kpi_cards(len(filtered), counts)

left, right = st.columns((1.4, 1))

with left:
    st.subheader("Live Policy Evaluation Feed")
    feed_df = filtered.sort_values("timestamp", ascending=False).head(40).copy()
    feed_df["status"] = ""
    if not feed_df.empty:
        feed_df.iloc[0, feed_df.columns.get_loc("status")] = "NEW"

    feed_cols = [
        "status",
        "timestamp",
        "audit_id",
        "agent_source",
        "agent_target",
        "policy_name",
        "decision",
        "trust_score",
        "severity",
    ]
    st.dataframe(
        _style_feed(feed_df[feed_cols]),
        use_container_width=True,
        hide_index=True,
        height=420,
    )

with right:
    st.subheader("Policy Coverage Overview")
    st.caption("Legend: 🟢 Allow | 🟠 Escalate | 🔴 Deny")
    coverage = (
        filtered.groupby(["policy_name", "decision"]).size().reset_index(name="count")
        if not filtered.empty
        else pd.DataFrame(columns=["policy_name", "decision", "count"])
    )
    fig_coverage = px.bar(
        coverage,
        x="policy_name",
        y="count",
        color="decision",
        barmode="stack",
        color_discrete_map=DECISION_COLORS,
        height=330,
    )
    fig_coverage.update_layout(
        margin=dict(l=10, r=10, t=10, b=10),
        legend_title_text="",
        paper_bgcolor="rgba(0,0,0,0)",
        plot_bgcolor="rgba(255,255,255,0.45)",
        font=dict(family="Segoe UI, Helvetica Neue, Arial, sans-serif", size=12, color="#132026"),
    )
    st.plotly_chart(fig_coverage, use_container_width=True)

row2_left, row2_right = st.columns((1, 1))

with row2_left:
    st.subheader("Trust Score Heatmap")
    if filtered.empty:
        st.info("No data for selected filters.")
    else:
        active_agents = sorted(set(filtered["agent_source"]).union(set(filtered["agent_target"])))
        if not active_agents:
            active_agents = AGENTS

        trust_pivot = filtered.pivot_table(
            index="agent_source",
            columns="agent_target",
            values="trust_score",
            aggfunc="mean",
        )
        trust_pivot = trust_pivot.reindex(index=active_agents, columns=active_agents)
        fig_heatmap = px.imshow(
            trust_pivot,
            text_auto=True,
            aspect="auto",
            color_continuous_scale=[[0.0, "#b7352a"], [0.5, "#f2d06e"], [1.0, "#1e9d63"]],
            zmin=0,
            zmax=100,
            height=380,
            labels={"x": "Target Agent", "y": "Source Agent", "color": "Trust Score"},
        )
        fig_heatmap.update_layout(
            margin=dict(l=10, r=10, t=10, b=10),
            coloraxis_colorbar_title="Trust",
            paper_bgcolor="rgba(0,0,0,0)",
            plot_bgcolor="rgba(255,255,255,0.45)",
            font=dict(family="Segoe UI, Helvetica Neue, Arial, sans-serif", size=12, color="#132026"),
        )
        fig_heatmap.update_xaxes(title_text="Target Agent")
        fig_heatmap.update_yaxes(title_text="Source Agent")
        st.plotly_chart(fig_heatmap, use_container_width=True)

with row2_right:
    st.subheader("Violation Alerts")
    alerts = violations.copy()
    alerts["severity_rank"] = alerts["severity"].map(SEVERITY_ORDER).fillna(0)
    alerts = alerts.sort_values(["severity_rank", "timestamp"], ascending=[False, False]).head(30)

    if alerts.empty:
        st.info("No violations detected")
    else:
        alert_table = alerts[
            [
                "timestamp",
                "audit_id",
                "agent_source",
                "policy_name",
                "decision",
                "severity",
                "violation_category",
            ]
        ].copy()
        alert_table["severity"] = alert_table["severity"].map(_severity_badge)

        st.dataframe(
            _style_alerts(alert_table),
            use_container_width=True,
            hide_index=True,
            height=360,
        )

        selected_audit_id = st.selectbox(
            "Drill-down audit event",
            options=alerts["audit_id"].tolist(),
            index=0,
        )
        chosen = alerts[alerts["audit_id"] == selected_audit_id].iloc[0]
        safe_details = html.escape(str(chosen["details"]))
        st.json(
            {
                "audit_id": chosen["audit_id"],
                "timestamp": str(chosen["timestamp"]),
                "source": chosen["agent_source"],
                "target": chosen["agent_target"],
                "policy": chosen["policy_name"],
                "decision": chosen["decision"],
                "severity": chosen["severity"],
                "category": chosen["violation_category"],
                "trust_score": float(chosen["trust_score"]),
                "details": safe_details,
            }
        )

st.subheader("Agent Activity Timeline")
if filtered.empty:
    st.info("No timeline data for selected filters.")
else:
    timeline_base = pd.concat(
        [
            filtered[["timestamp", "agent_source"]].rename(columns={"agent_source": "agent"}),
            filtered[["timestamp", "agent_target"]].rename(columns={"agent_target": "agent"}),
        ],
        ignore_index=True,
    )
    timeline = (
        timeline_base.set_index("timestamp")
        .groupby("agent")
        .resample("5s")
        .size()
        .reset_index(name="event_count")
    )
    fig_timeline = px.line(
        timeline,
        x="timestamp",
        y="event_count",
        color="agent",
        markers=False,
        height=320,
    )
    fig_timeline.update_layout(
        margin=dict(l=10, r=10, t=10, b=10),
        legend_title_text="",
        paper_bgcolor="rgba(0,0,0,0)",
        plot_bgcolor="rgba(255,255,255,0.45)",
        font=dict(family="Segoe UI, Helvetica Neue, Arial, sans-serif", size=12, color="#132026"),
    )
    st.plotly_chart(fig_timeline, use_container_width=True)

if live_mode:
    append_events(events_per_tick)
    time.sleep(refresh_seconds)
    st.rerun()
