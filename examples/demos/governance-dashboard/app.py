"""Agent Governance Dashboard - Real-time agent fleet visibility."""
import streamlit as st
import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
from datetime import datetime, timezone
from demo_data import generate_fleet, generate_policy_events, generate_trust_matrix, generate_lifecycle_events

st.set_page_config(page_title="Agent Governance Dashboard", page_icon="\U0001f6e1\ufe0f", layout="wide", initial_sidebar_state="expanded")

@st.cache_data(ttl=300)
def load_data():
    agents = generate_fleet(30)
    return agents, generate_policy_events(300), generate_trust_matrix(agents), generate_lifecycle_events(agents, 150)

agents, policy_events, trust_matrix, lifecycle_events = load_data()
adf = pd.DataFrame(agents)
pdf = pd.DataFrame(policy_events)
tdf = pd.DataFrame(trust_matrix)
ldf = pd.DataFrame(lifecycle_events)

st.sidebar.title("\U0001f6e1\ufe0f Agent Governance")
st.sidebar.markdown("---")
page = st.sidebar.radio("Navigate", ["Fleet Overview", "Shadow Agents", "Lifecycle Monitor", "Policy Feed", "Trust Heatmap"])
st.sidebar.markdown("---")
st.sidebar.markdown(f"**Updated:** {datetime.now(timezone.utc).strftime('%H:%M UTC')}")
st.sidebar.markdown("*Demo data mode*")
if st.sidebar.button("\U0001f504 Refresh"):
    st.cache_data.clear()
    st.rerun()

RISK_COLORS = {"critical": "#e74c3c", "high": "#e67e22", "medium": "#f1c40f", "low": "#2ecc71", "info": "#95a5a6"}
STATE_COLORS = {"active": "#2ecc71", "provisioned": "#3498db", "suspended": "#f39c12", "orphaned": "#e74c3c", "decommissioned": "#95a5a6", "pending_approval": "#9b59b6"}

if page == "Fleet Overview":
    st.title("\U0001f4ca Fleet Overview")
    total = len(adf)
    c1, c2, c3, c4, c5 = st.columns(5)
    c1.metric("Total Agents", total)
    c2.metric("Active", len(adf[adf["state"]=="active"]))
    c3.metric("Shadow (No ID)", len(adf[~adf["has_identity"]]))
    c4.metric("Orphaned", len(adf[adf["state"]=="orphaned"]))
    c5.metric("Critical Risk", len(adf[adf["risk_level"]=="critical"]))
    st.markdown("---")
    col1, col2 = st.columns(2)
    with col1:
        st.subheader("By Type")
        tc = adf["type"].value_counts().reset_index(); tc.columns = ["type", "count"]
        st.plotly_chart(px.bar(tc, x="type", y="count", color="type", color_discrete_sequence=px.colors.qualitative.Set2).update_layout(showlegend=False, height=350), use_container_width=True)
    with col2:
        st.subheader("By State")
        sc = adf["state"].value_counts().reset_index(); sc.columns = ["state", "count"]
        st.plotly_chart(px.pie(sc, values="count", names="state", color="state", color_discrete_map=STATE_COLORS).update_layout(height=350), use_container_width=True)
    col1, col2 = st.columns(2)
    with col1:
        st.subheader("Risk Distribution")
        rc = adf["risk_level"].value_counts().reindex(["critical","high","medium","low","info"], fill_value=0).reset_index(); rc.columns = ["level", "count"]
        st.plotly_chart(px.bar(rc, x="level", y="count", color="level", color_discrete_map=RISK_COLORS).update_layout(showlegend=False, height=300), use_container_width=True)
    with col2:
        st.subheader("By Owner")
        oc = adf["owner"].value_counts().head(8).reset_index(); oc.columns = ["owner", "count"]
        st.plotly_chart(px.bar(oc, x="count", y="owner", orientation="h").update_layout(height=300), use_container_width=True)
    st.subheader("Agent Fleet")
    st.dataframe(adf[["name","type","state","owner","risk_level","risk_score","trust_score","has_identity","heartbeat_count"]].sort_values("risk_score", ascending=False), use_container_width=True, height=400)

elif page == "Shadow Agents":
    st.title("\U0001f50d Shadow Agent Alerts")
    sdf = adf[~adf["has_identity"]].sort_values("risk_score", ascending=False)
    if sdf.empty:
        st.success("No shadow agents detected!")
    else:
        st.error(f"\u26a0\ufe0f {len(sdf)} shadow agents without governance identity")
        c1, c2, c3 = st.columns(3)
        c1.metric("\U0001f534 Critical", len(sdf[sdf["risk_level"]=="critical"]))
        c2.metric("\U0001f7e0 High", len(sdf[sdf["risk_level"]=="high"]))
        c3.metric("\U0001f7e1 Medium", len(sdf[sdf["risk_level"]=="medium"]))
        st.markdown("---")
        for _, a in sdf.iterrows():
            icon = {"\x63ritical": "\U0001f534", "high": "\U0001f7e0", "medium": "\U0001f7e1"}.get(a["risk_level"], "\u26aa")
            with st.expander(f"{icon} **{a['name']}** - {a['type']} (Risk: {a['risk_score']:.0f})"):
                c1, c2, c3 = st.columns(3)
                c1.write(f"**State:** {a['state']}")
                c2.write(f"**Owner:** {a['owner']}")
                c3.write(f"**Evidence:** {a['evidence_count']} observations")
                st.markdown("**Actions:** 1) Register with AgentMesh 2) Assign owner 3) Apply policies")

elif page == "Lifecycle Monitor":
    st.title("\U0001f510 Lifecycle Monitor")
    st.subheader("Provisioning Pipeline")
    states = ["pending_approval", "provisioned", "active", "suspended", "orphaned", "decommissioned"]
    counts = [len(adf[adf["state"]==s]) for s in states]
    st.plotly_chart(go.Figure(go.Funnel(y=states, x=counts, textinfo="value+percent initial")).update_layout(height=350), use_container_width=True)
    c1, c2 = st.columns(2)
    with c1:
        st.subheader("Credential Status")
        active = adf[adf["state"]=="active"]
        st.metric("With Credentials", len(active[active["credential_expires"].notna()]))
        st.metric("WITHOUT Credentials", len(active[active["credential_expires"].isna()]))
    with c2:
        st.subheader("Orphan Candidates")
        orphans = adf[adf["state"]=="orphaned"]
        st.metric("Orphaned", len(orphans))
        for _, o in orphans.iterrows():
            st.warning(f"\U0001f534 {o['name']} - Owner: {o['owner']}")
    st.subheader("Recent Events")
    st.dataframe(ldf.head(50), use_container_width=True, height=400)

elif page == "Policy Feed":
    st.title("\U0001f4c8 Policy Evaluation Feed")
    total = len(pdf)
    allows = len(pdf[pdf["decision"]=="allow"])
    denies = len(pdf[pdf["decision"]=="deny"])
    escs = len(pdf[pdf["decision"]=="escalate"])
    c1, c2, c3, c4, c5 = st.columns(5)
    c1.metric("Evaluations", total)
    c2.metric("Allowed", allows)
    c3.metric("Denied", denies)
    c4.metric("Escalated", escs)
    c5.metric("Avg Latency", f"{pdf['latency_ms'].mean():.2f}ms")
    st.markdown(f"**Violation Rate:** `{(denies+escs)/total*100:.1f}%`")
    st.markdown("---")
    c1, c2 = st.columns(2)
    with c1:
        st.subheader("By Action")
        ad = pdf.groupby(["action","decision"]).size().reset_index(name="count")
        st.plotly_chart(px.bar(ad, x="action", y="count", color="decision", color_discrete_map={"allow":"#2ecc71","deny":"#e74c3c","escalate":"#f39c12"}, barmode="stack").update_layout(height=400), use_container_width=True)
    with c2:
        st.subheader("Decisions")
        dc = pdf["decision"].value_counts().reset_index(); dc.columns = ["decision","count"]
        st.plotly_chart(px.pie(dc, values="count", names="decision", color="decision", color_discrete_map={"allow":"#2ecc71","deny":"#e74c3c","escalate":"#f39c12"}).update_layout(height=400), use_container_width=True)
    st.subheader("Recent Events")
    st.dataframe(pdf.head(50), use_container_width=True, height=400)

elif page == "Trust Heatmap":
    st.title("\U0001f310 Trust Score Heatmap")
    if tdf.empty:
        st.info("No trust data. Register agents with AgentMesh first.")
    else:
        pivot = tdf.pivot_table(values="trust_score", index="from_agent", columns="to_agent", fill_value=0)
        st.plotly_chart(px.imshow(pivot, color_continuous_scale="RdYlGn", zmin=0, zmax=1000, labels={"color":"Trust Score"}, aspect="auto").update_layout(height=600), use_container_width=True)
        st.subheader("Trust Tier Distribution")
        scores = adf[adf["trust_score"]>0]["trust_score"]
        def tier(s): return "Verified Partner" if s>=900 else "Trusted" if s>=700 else "Standard" if s>=500 else "Probationary" if s>=300 else "Untrusted"
        tiers = scores.apply(tier).value_counts().reindex(["Verified Partner","Trusted","Standard","Probationary","Untrusted"], fill_value=0).reset_index(); tiers.columns = ["tier","count"]
        st.plotly_chart(px.bar(tiers, x="tier", y="count", color="tier", color_discrete_map={"Verified Partner":"#27ae60","Trusted":"#2ecc71","Standard":"#3498db","Probationary":"#f39c12","Untrusted":"#e74c3c"}).update_layout(showlegend=False, height=350), use_container_width=True)
