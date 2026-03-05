# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""
AgentMesh Trust Score Dashboard
===============================
A comprehensive Plotly-based Streamlit dashboard for monitoring agent trust
networks, credential lifecycles, protocol traffic, and compliance posture.

Run with:  streamlit run trust_dashboard.py
"""

import datetime as dt
import hashlib

import numpy as np
import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
import streamlit as st
import networkx as nx

# ---------------------------------------------------------------------------
# Page config
# ---------------------------------------------------------------------------
st.set_page_config(
    page_title="AgentMesh Trust Dashboard",
    page_icon="\U0001f6e1",
    layout="wide",
)

PLOTLY_TEMPLATE = "plotly_dark"
NOW = dt.datetime.now(dt.timezone.utc)

# ---------------------------------------------------------------------------
# Simulated data
# ---------------------------------------------------------------------------

AGENTS = [
    {"name": "payment-agent", "did": "did:web:payments.mesh.io", "protocol": "A2A",
     "trust_score": 920, "dimensions": [95, 92, 88, 96, 90]},
    {"name": "customer-service", "did": "did:web:cs.mesh.io", "protocol": "A2A",
     "trust_score": 870, "dimensions": [88, 90, 85, 82, 92]},
    {"name": "data-analyst", "did": "did:web:analytics.mesh.io", "protocol": "MCP",
     "trust_score": 810, "dimensions": [90, 78, 92, 80, 85]},
    {"name": "fraud-detector", "did": "did:web:fraud.mesh.io", "protocol": "IATP",
     "trust_score": 940, "dimensions": [96, 95, 90, 98, 94]},
    {"name": "inventory-manager", "did": "did:web:inventory.mesh.io", "protocol": "MCP",
     "trust_score": 720, "dimensions": [75, 70, 82, 68, 78]},
    {"name": "email-dispatcher", "did": "did:web:email.mesh.io", "protocol": "A2A",
     "trust_score": 650, "dimensions": [60, 72, 80, 55, 68]},
    {"name": "auth-gateway", "did": "did:web:auth.mesh.io", "protocol": "IATP",
     "trust_score": 950, "dimensions": [98, 96, 94, 99, 95]},
    {"name": "report-generator", "did": "did:web:reports.mesh.io", "protocol": "MCP",
     "trust_score": 580, "dimensions": [55, 62, 70, 50, 60]},
    {"name": "scheduler", "did": "did:web:scheduler.mesh.io", "protocol": "A2A",
     "trust_score": 780, "dimensions": [80, 76, 85, 74, 82]},
    {"name": "compliance-bot", "did": "did:web:compliance.mesh.io", "protocol": "IATP",
     "trust_score": 890, "dimensions": [88, 92, 86, 84, 96]},
]

DIMENSION_LABELS = ["Competence", "Integrity", "Availability", "Security", "Compliance"]

EDGES = [
    ("payment-agent", "fraud-detector", 0.95),
    ("payment-agent", "auth-gateway", 0.90),
    ("customer-service", "email-dispatcher", 0.80),
    ("customer-service", "scheduler", 0.75),
    ("data-analyst", "report-generator", 0.70),
    ("data-analyst", "inventory-manager", 0.65),
    ("fraud-detector", "auth-gateway", 0.92),
    ("fraud-detector", "compliance-bot", 0.88),
    ("inventory-manager", "scheduler", 0.60),
    ("email-dispatcher", "scheduler", 0.55),
    ("auth-gateway", "compliance-bot", 0.93),
    ("report-generator", "compliance-bot", 0.62),
    ("payment-agent", "customer-service", 0.78),
    ("data-analyst", "fraud-detector", 0.82),
    ("scheduler", "compliance-bot", 0.70),
]

CREDENTIAL_TYPES = ["x509-mTLS", "VC-JWT", "DID-Auth", "OAuth2-Token", "API-Key"]

COMPLIANCE_FRAMEWORKS = ["EU AI Act", "SOC 2", "HIPAA", "GDPR"]


def _agent_df() -> pd.DataFrame:
    return pd.DataFrame(AGENTS)


def _score_color(score: int) -> str:
    """Return hex color on red-yellow-green gradient for 0-1000."""
    ratio = min(max(score / 1000, 0), 1)
    if ratio < 0.5:
        r, g = 255, int(255 * ratio * 2)
    else:
        r, g = int(255 * (1 - ratio) * 2), 255
    return f"rgb({r},{g},60)"


def _build_trust_history(agents: list[dict], hours: int = 24) -> pd.DataFrame:
    """Simulate trust score fluctuations over the last *hours*."""
    rng = np.random.default_rng(42)
    timestamps = pd.date_range(end=NOW, periods=hours * 4, freq="15min")
    rows = []
    for a in agents:
        base = a["trust_score"]
        noise = rng.normal(0, 12, size=len(timestamps)).cumsum()
        noise -= noise.mean()
        scores = np.clip(base + noise, 0, 1000).astype(int)
        for t, s in zip(timestamps, scores):
            rows.append({"agent": a["name"], "timestamp": t, "trust_score": s})
    return pd.DataFrame(rows)


def _build_credentials(agents: list[dict]) -> pd.DataFrame:
    rng = np.random.default_rng(7)
    rows = []
    for a in agents:
        ctype = rng.choice(CREDENTIAL_TYPES)
        issued = NOW - dt.timedelta(hours=rng.integers(2, 72))
        ttl_h = int(rng.choice([6, 12, 24, 48]))
        expires = issued + dt.timedelta(hours=ttl_h)
        remaining = (expires - NOW).total_seconds()
        status = "active" if remaining > 0 else "expired"
        if status == "active" and remaining < 3600:
            status = "expiring-soon"
        rows.append({
            "agent": a["name"], "type": ctype,
            "issued": issued.strftime("%Y-%m-%d %H:%M"),
            "expires": expires.strftime("%Y-%m-%d %H:%M"),
            "ttl_hours": ttl_h,
            "remaining_sec": max(remaining, 0),
            "status": status,
        })
    return pd.DataFrame(rows)


def _build_protocol_traffic(hours: int = 24) -> pd.DataFrame:
    rng = np.random.default_rng(99)
    timestamps = pd.date_range(end=NOW, periods=hours * 4, freq="15min")
    rows = []
    for t in timestamps:
        for proto in ["A2A", "MCP", "IATP"]:
            base = {"A2A": 120, "MCP": 80, "IATP": 45}[proto]
            rows.append({"timestamp": t, "protocol": proto,
                         "messages": int(base + rng.integers(-20, 20))})
    return pd.DataFrame(rows)


def _build_audit_log(n: int = 20) -> pd.DataFrame:
    rng = np.random.default_rng(11)
    events = [
        "Trust score re-evaluated", "Credential rotated", "Compliance check passed",
        "Anomaly flagged", "DID resolved", "Chain proof verified",
        "Credential expired", "Trust decay applied", "Policy violation detected",
        "Audit trail anchored",
    ]
    rows = []
    for i in range(n):
        rows.append({
            "timestamp": (NOW - dt.timedelta(minutes=int(rng.integers(1, 1440)))).strftime("%Y-%m-%d %H:%M"),
            "agent": rng.choice([a["name"] for a in AGENTS]),
            "event": rng.choice(events),
            "severity": rng.choice(["info", "warning", "critical"], p=[0.7, 0.2, 0.1]),
        })
    return pd.DataFrame(rows).sort_values("timestamp", ascending=False).reset_index(drop=True)


# ---------------------------------------------------------------------------
# Sidebar filters
# ---------------------------------------------------------------------------
st.sidebar.title("\U0001f6e1 Dashboard Filters")

all_names = [a["name"] for a in AGENTS]
selected_agents = st.sidebar.multiselect("Agents", all_names, default=all_names)

time_range = st.sidebar.selectbox("Time range", ["Last 6 h", "Last 12 h", "Last 24 h"], index=2)
hours_map = {"Last 6 h": 6, "Last 12 h": 12, "Last 24 h": 24}
selected_hours = hours_map[time_range]

selected_protocols = st.sidebar.multiselect(
    "Protocols", ["A2A", "MCP", "IATP"], default=["A2A", "MCP", "IATP"]
)

# Filtered agent list
filtered = [a for a in AGENTS if a["name"] in selected_agents and a["protocol"] in selected_protocols]

# ---------------------------------------------------------------------------
# Header KPIs
# ---------------------------------------------------------------------------
st.title("\U0001f6e1 AgentMesh Trust Dashboard")

if not filtered:
    st.warning("No agents match the current filters.")
    st.stop()

scores = [a["trust_score"] for a in filtered]
k1, k2, k3, k4 = st.columns(4)
k1.metric("Agents Online", len(filtered))
k2.metric("Avg Trust Score", f"{np.mean(scores):.0f}")
k3.metric("Min Trust Score", min(scores))
k4.metric("Max Trust Score", max(scores))

# ---------------------------------------------------------------------------
# Tabs
# ---------------------------------------------------------------------------
tab_net, tab_scores, tab_creds, tab_proto, tab_compliance = st.tabs(
    ["\U0001f310 Trust Network", "\U0001f4ca Trust Scores",
     "\U0001f512 Credential Lifecycle", "\U0001f4e1 Protocol Traffic",
     "\u2705 Compliance"]
)

# ========================== TAB 1: Trust Network ==========================
with tab_net:
    G = nx.Graph()
    agent_lookup = {a["name"]: a for a in AGENTS}
    for a in filtered:
        G.add_node(a["name"], **a)
    for src, dst, w in EDGES:
        if src in G.nodes and dst in G.nodes:
            G.add_edge(src, dst, weight=w)

    pos = nx.spring_layout(G, seed=42, k=1.8)

    # Edges
    edge_x, edge_y = [], []
    edge_widths = []
    for u, v, d in G.edges(data=True):
        x0, y0 = pos[u]
        x1, y1 = pos[v]
        edge_x += [x0, x1, None]
        edge_y += [y0, y1, None]
        edge_widths.append(d["weight"])

    avg_w = np.mean(edge_widths) if edge_widths else 1
    edge_trace = go.Scatter(
        x=edge_x, y=edge_y, mode="lines",
        line=dict(width=avg_w * 3, color="rgba(150,150,150,0.4)"),
        hoverinfo="none",
    )

    # Nodes
    node_x = [pos[n][0] for n in G.nodes]
    node_y = [pos[n][1] for n in G.nodes]
    node_scores = [agent_lookup[n]["trust_score"] for n in G.nodes]
    node_colors = [_score_color(s) for s in node_scores]
    node_sizes = [max(s / 25, 15) for s in node_scores]
    hover_texts = [
        f"<b>{n}</b><br>DID: {agent_lookup[n]['did']}<br>"
        f"Trust: {agent_lookup[n]['trust_score']}<br>"
        f"Protocol: {agent_lookup[n]['protocol']}"
        for n in G.nodes
    ]

    node_trace = go.Scatter(
        x=node_x, y=node_y, mode="markers+text",
        marker=dict(size=node_sizes, color=node_colors, line=dict(width=2, color="#222")),
        text=[n for n in G.nodes],
        textposition="top center",
        textfont=dict(size=10, color="white"),
        hovertext=hover_texts, hoverinfo="text",
    )

    fig_net = go.Figure(data=[edge_trace, node_trace])
    fig_net.update_layout(
        template=PLOTLY_TEMPLATE, showlegend=False,
        xaxis=dict(showgrid=False, zeroline=False, visible=False),
        yaxis=dict(showgrid=False, zeroline=False, visible=False),
        height=580, margin=dict(l=20, r=20, t=30, b=20),
        title="Agent Trust Network",
    )
    st.plotly_chart(fig_net, use_container_width=True)

# ======================== TAB 2: Trust Scores ============================
with tab_scores:
    df_agents = pd.DataFrame(filtered).sort_values("trust_score", ascending=True)

    # Leaderboard bar chart
    fig_bar = px.bar(
        df_agents, x="trust_score", y="name", orientation="h",
        color="trust_score", color_continuous_scale=["#d32f2f", "#fbc02d", "#388e3c"],
        range_color=[0, 1000], labels={"name": "Agent", "trust_score": "Trust Score"},
        title="Trust Score Leaderboard",
    )
    fig_bar.update_layout(template=PLOTLY_TEMPLATE, height=400, yaxis=dict(categoryorder="total ascending"))
    st.plotly_chart(fig_bar, use_container_width=True)

    # Radar + history side by side
    col_radar, col_hist = st.columns(2)

    with col_radar:
        sel = st.selectbox("Agent for radar breakdown", [a["name"] for a in filtered])
        agent_data = next(a for a in filtered if a["name"] == sel)
        dims = agent_data["dimensions"] + [agent_data["dimensions"][0]]
        labels = DIMENSION_LABELS + [DIMENSION_LABELS[0]]
        fig_radar = go.Figure(go.Scatterpolar(
            r=dims, theta=labels, fill="toself",
            line=dict(color="#00bcd4"),
        ))
        fig_radar.update_layout(
            template=PLOTLY_TEMPLATE, height=400,
            polar=dict(radialaxis=dict(range=[0, 100])),
            title=f"Trust Dimensions \u2014 {sel}",
        )
        st.plotly_chart(fig_radar, use_container_width=True)

    with col_hist:
        history_df = _build_trust_history(filtered, selected_hours)
        fig_hist = px.line(
            history_df, x="timestamp", y="trust_score", color="agent",
            title=f"Trust Score History ({time_range})",
            labels={"trust_score": "Score", "timestamp": ""},
        )
        fig_hist.update_layout(template=PLOTLY_TEMPLATE, height=400)
        st.plotly_chart(fig_hist, use_container_width=True)

    # Trust decay visualization
    st.subheader("Trust Decay Simulation")
    decay_hours = np.arange(0, 73)
    decay_rate = 0.015
    fig_decay = go.Figure()
    for a in filtered[:5]:
        base = a["trust_score"]
        decayed = base * np.exp(-decay_rate * decay_hours)
        fig_decay.add_trace(go.Scatter(
            x=decay_hours, y=decayed, mode="lines", name=a["name"],
        ))
    fig_decay.update_layout(
        template=PLOTLY_TEMPLATE, height=350,
        title="Projected Trust Decay Without Activity",
        xaxis_title="Hours Without Activity", yaxis_title="Trust Score",
    )
    st.plotly_chart(fig_decay, use_container_width=True)

# ===================== TAB 3: Credential Lifecycle ========================
with tab_creds:
    creds_df = _build_credentials(filtered)

    # Status table
    st.subheader("Credential Status")

    def _status_icon(s: str) -> str:
        return {"active": "\u2705 Active", "expired": "\u274c Expired",
                "expiring-soon": "\u26a0\ufe0f Expiring Soon"}.get(s, s)

    display_df = creds_df.copy()
    display_df["status"] = display_df["status"].apply(_status_icon)
    display_df["remaining"] = creds_df["remaining_sec"].apply(
        lambda s: f"{s / 3600:.1f} h" if s > 0 else "\u2014"
    )
    st.dataframe(
        display_df[["agent", "type", "issued", "expires", "remaining", "status"]],
        use_container_width=True, hide_index=True,
    )

    col_gauge, col_pie = st.columns(2)

    with col_gauge:
        st.subheader("TTL Countdown")
        active = creds_df[creds_df["remaining_sec"] > 0]
        fig_gauge = go.Figure()
        for _, row in active.iterrows():
            pct = min(row["remaining_sec"] / (row["ttl_hours"] * 3600) * 100, 100)
            fig_gauge.add_trace(go.Indicator(
                mode="gauge+number", value=pct,
                title={"text": row["agent"], "font": {"size": 12}},
                gauge=dict(
                    axis=dict(range=[0, 100]),
                    bar=dict(color="#00bcd4"),
                    steps=[
                        dict(range=[0, 25], color="#d32f2f"),
                        dict(range=[25, 60], color="#fbc02d"),
                        dict(range=[60, 100], color="#388e3c"),
                    ],
                ),
                domain=dict(
                    x=[(_ % 3) / 3, (_ % 3 + 1) / 3],
                    y=[1 - (_ // 3 + 1) / max((len(active) // 3 + 1), 1),
                       1 - (_ // 3) / max((len(active) // 3 + 1), 1)],
                ),
            ))
        fig_gauge.update_layout(template=PLOTLY_TEMPLATE, height=400)
        st.plotly_chart(fig_gauge, use_container_width=True)

    with col_pie:
        st.subheader("Credential Distribution")
        status_counts = creds_df["status"].value_counts().reset_index()
        status_counts.columns = ["status", "count"]
        color_map = {"active": "#388e3c", "expired": "#d32f2f", "expiring-soon": "#fbc02d"}
        fig_pie_cred = px.pie(
            status_counts, values="count", names="status",
            color="status", color_discrete_map=color_map,
            title="Active vs Expired vs Expiring Soon",
        )
        fig_pie_cred.update_layout(template=PLOTLY_TEMPLATE, height=400)
        st.plotly_chart(fig_pie_cred, use_container_width=True)

    # Credential rotation timeline
    st.subheader("Credential Rotation Timeline")
    timeline_df = creds_df.copy()
    timeline_df["issued_dt"] = pd.to_datetime(timeline_df["issued"])
    timeline_df["expires_dt"] = pd.to_datetime(timeline_df["expires"])
    fig_timeline = go.Figure()
    for i, row in timeline_df.iterrows():
        color = {"active": "#388e3c", "expired": "#d32f2f", "expiring-soon": "#fbc02d"}[row["status"]]
        fig_timeline.add_trace(go.Scatter(
            x=[row["issued_dt"], row["expires_dt"]],
            y=[row["agent"], row["agent"]],
            mode="lines+markers", line=dict(color=color, width=6),
            marker=dict(size=10, color=color),
            name=row["agent"], showlegend=False,
            hovertext=f"{row['agent']}: {row['type']}",
        ))
    fig_timeline.update_layout(
        template=PLOTLY_TEMPLATE, height=350,
        title="Credential Validity Windows",
        xaxis_title="Time", yaxis_title="",
    )
    st.plotly_chart(fig_timeline, use_container_width=True)

# ===================== TAB 4: Protocol Traffic ============================
with tab_proto:
    traffic_df = _build_protocol_traffic(selected_hours)
    traffic_df = traffic_df[traffic_df["protocol"].isin(selected_protocols)]

    col_pie_p, col_line_p = st.columns(2)

    with col_pie_p:
        proto_totals = traffic_df.groupby("protocol")["messages"].sum().reset_index()
        fig_proto_pie = px.pie(
            proto_totals, values="messages", names="protocol",
            title="Protocol Distribution",
            color="protocol",
            color_discrete_map={"A2A": "#42a5f5", "MCP": "#ab47bc", "IATP": "#66bb6a"},
        )
        fig_proto_pie.update_layout(template=PLOTLY_TEMPLATE, height=400)
        st.plotly_chart(fig_proto_pie, use_container_width=True)

    with col_line_p:
        fig_throughput = px.line(
            traffic_df, x="timestamp", y="messages", color="protocol",
            title=f"Message Throughput ({time_range})",
            color_discrete_map={"A2A": "#42a5f5", "MCP": "#ab47bc", "IATP": "#66bb6a"},
        )
        fig_throughput.update_layout(template=PLOTLY_TEMPLATE, height=400)
        st.plotly_chart(fig_throughput, use_container_width=True)

    # Verification pass/fail rates
    col_veri, col_pairs = st.columns(2)

    with col_veri:
        st.subheader("Trust Verification Pass/Fail")
        rng = np.random.default_rng(55)
        veri_data = []
        for proto in selected_protocols:
            total = int(proto_totals[proto_totals["protocol"] == proto]["messages"].iloc[0])
            pass_rate = {"A2A": 0.96, "MCP": 0.92, "IATP": 0.98}.get(proto, 0.9)
            passed = int(total * pass_rate)
            veri_data.append({"protocol": proto, "result": "Pass", "count": passed})
            veri_data.append({"protocol": proto, "result": "Fail", "count": total - passed})
        veri_df = pd.DataFrame(veri_data)
        fig_veri = px.bar(
            veri_df, x="protocol", y="count", color="result", barmode="group",
            color_discrete_map={"Pass": "#388e3c", "Fail": "#d32f2f"},
            title="Verification Results by Protocol",
        )
        fig_veri.update_layout(template=PLOTLY_TEMPLATE, height=380)
        st.plotly_chart(fig_veri, use_container_width=True)

    with col_pairs:
        st.subheader("Top Communication Pairs")
        pair_data = []
        for src, dst, w in sorted(EDGES, key=lambda e: e[2], reverse=True)[:8]:
            if src in selected_agents and dst in selected_agents:
                pair_data.append({"pair": f"{src} \u2194 {dst}", "weight": w})
        if pair_data:
            pair_df = pd.DataFrame(pair_data)
            fig_pairs = px.bar(
                pair_df, x="weight", y="pair", orientation="h",
                title="Top Agent Pairs by Trust Weight",
                color="weight", color_continuous_scale="teal",
            )
            fig_pairs.update_layout(template=PLOTLY_TEMPLATE, height=380,
                                    yaxis=dict(categoryorder="total ascending"))
            st.plotly_chart(fig_pairs, use_container_width=True)
        else:
            st.info("No communication pairs match current filters.")

# ======================== TAB 5: Compliance ===============================
with tab_compliance:
    rng = np.random.default_rng(22)

    # Framework status cards
    st.subheader("Compliance Framework Status")
    fw_cols = st.columns(len(COMPLIANCE_FRAMEWORKS))
    fw_status = {"EU AI Act": 92, "SOC 2": 88, "HIPAA": 95, "GDPR": 90}
    for col, fw in zip(fw_cols, COMPLIANCE_FRAMEWORKS):
        score = fw_status[fw]
        col.metric(fw, f"{score}%", delta=f"+{rng.integers(0, 4)}% this week")

    # Per-agent compliance checklist
    st.subheader("Per-Agent Compliance Checklist")
    compliance_rows = []
    for a in filtered:
        row = {"agent": a["name"]}
        for fw in COMPLIANCE_FRAMEWORKS:
            passed = rng.random() > 0.15
            row[fw] = "\u2705" if passed else "\u274c"
        compliance_rows.append(row)
    st.dataframe(pd.DataFrame(compliance_rows), use_container_width=True, hide_index=True)

    col_audit, col_chain = st.columns(2)

    with col_audit:
        st.subheader("Audit Log")
        audit_df = _build_audit_log(25)
        audit_df = audit_df[audit_df["agent"].isin(selected_agents)]

        def _sev_badge(s: str) -> str:
            return {"info": "\U0001f535 info", "warning": "\U0001f7e1 warning",
                    "critical": "\U0001f534 critical"}.get(s, s)

        audit_df["severity"] = audit_df["severity"].apply(_sev_badge)
        st.dataframe(audit_df, use_container_width=True, hide_index=True, height=400)

    with col_chain:
        st.subheader("Audit Chain Verification")
        chain_rows = []
        for a in filtered:
            root = hashlib.sha256(a["name"].encode()).hexdigest()[:16]
            verified = rng.random() > 0.1
            chain_rows.append({
                "agent": a["name"],
                "chain_root": f"0x{root}",
                "verified": "\u2705 Verified" if verified else "\u274c Failed",
                "last_check": (NOW - dt.timedelta(minutes=int(rng.integers(5, 120)))).strftime("%H:%M"),
            })
        st.dataframe(pd.DataFrame(chain_rows), use_container_width=True, hide_index=True)

    # Compliance score heatmap
    st.subheader("Compliance Score Heatmap")
    heat_data = []
    for a in filtered:
        for fw in COMPLIANCE_FRAMEWORKS:
            heat_data.append({
                "agent": a["name"], "framework": fw,
                "score": int(rng.integers(60, 100)),
            })
    heat_df = pd.DataFrame(heat_data).pivot(index="agent", columns="framework", values="score")
    fig_heat = px.imshow(
        heat_df, text_auto=True, aspect="auto",
        color_continuous_scale=["#d32f2f", "#fbc02d", "#388e3c"],
        title="Compliance Scores by Agent & Framework",
    )
    fig_heat.update_layout(template=PLOTLY_TEMPLATE, height=400)
    st.plotly_chart(fig_heat, use_container_width=True)
