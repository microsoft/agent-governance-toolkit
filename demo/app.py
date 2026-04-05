"""
app.py — Streamlit frontend for the Agent Governance Toolkit Demo.

Tabs:
  1. 💬 Interactive Chat   — single-agent chat with live governance
  2. 🤝 Multi-Agent Pipeline — 3-agent Data Pipeline with DID and trust mesh
  3. 📜 Audit Log          — Merkle-chained audit trail
  4. 📋 Active Policies    — YAML policy viewer
"""

import asyncio
import pandas as pd
import streamlit as st
from pathlib import Path

from logic_adapter import (
    GovernanceDemoLogic,
    AGENT_CAPABILITIES,
    PIPELINE_AGENTS,
    BACKEND_OPENAI,
    BACKEND_AZURE,
    BACKEND_GEMINI,
)

# ---------------------------------------------------------------------------
# Page setup
# ---------------------------------------------------------------------------
st.set_page_config(
    page_title="Agent Governance Toolkit",
    page_icon="🛡️",
    layout="wide",
)

# ---------------------------------------------------------------------------
# Sidebar — Configuration
# ---------------------------------------------------------------------------
st.sidebar.title("🛡️ Agent Governance Toolkit")
st.sidebar.caption("Real-time multi-agent governance demo")
st.sidebar.divider()

st.sidebar.subheader("⚙️ LLM Configuration")
backend_type = st.sidebar.selectbox("Backend", [BACKEND_GEMINI, BACKEND_OPENAI, BACKEND_AZURE])
api_key      = st.sidebar.text_input("API Key", type="password", placeholder="Paste your key here")

default_model = "gemini-2.5-flash" if backend_type == BACKEND_GEMINI else "gpt-4o-mini"
model_name    = st.sidebar.text_input("Model", value=default_model)

endpoint = None
if backend_type == BACKEND_AZURE:
    endpoint = st.sidebar.text_input("Azure Endpoint", placeholder="https://RESOURCE.openai.azure.com")

st.sidebar.divider()
st.sidebar.subheader("🔒 Governance Status")
st.sidebar.success("✅ Policy Engine: ACTIVE")
st.sidebar.success("✅ Audit Log: MERKLE-CHAINED")
st.sidebar.success("✅ Capability Guard: ACTIVE")
st.sidebar.success("✅ Anomaly Detector: ACTIVE")

# ---------------------------------------------------------------------------
# Session State
# ---------------------------------------------------------------------------
if "logic"         not in st.session_state:
    st.session_state.logic         = None
if "chat_messages" not in st.session_state: 
    st.session_state.chat_messages = []
if "pipeline_log"  not in st.session_state: 
    st.session_state.pipeline_log  = []

# ---------------------------------------------------------------------------
# Initialize / Reset
# ---------------------------------------------------------------------------
if st.sidebar.button("▶ Initialize / Reset Demo", type="primary", use_container_width=True):
    if api_key:
        st.session_state.logic         = GovernanceDemoLogic(api_key, backend_type, endpoint)
        st.session_state.chat_messages = []
        st.session_state.pipeline_log  = []
        st.sidebar.success("Demo initialized!")
    else:
        st.sidebar.error("Please provide an API Key.")

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------
def _render_trust_mesh(logic) -> None:
    """Render the trust mesh metrics — single implementation used in two places."""
    trust_summary = logic.get_trust_summary()
    trust_cols    = st.columns(len(trust_summary))
    for col, ts in zip(trust_cols, trust_summary):
        a, b  = ts["from_agent"], ts["to_agent"]
        emoji = "🟢" if ts["trusted"] else "🔴"
        col.metric(
            label=f"{emoji} {a.split('-')[0].title()} → {b.split('-')[0].title()}",
            value=f"{ts['active_grants']} active grants",
            delta="trusted ✓" if ts["trusted"] else "not trusted",
            delta_color="normal" if ts["trusted"] else "inverse",
        )

# ---------------------------------------------------------------------------
# Tabs
# ---------------------------------------------------------------------------
tab_chat, tab_pipeline, tab_audit, tab_policy = st.tabs([
    "💬 Interactive Chat",
    "🤝 Multi-Agent Pipeline",
    "📜 Audit Log",
    "📋 Active Policies",
])

# ═══════════════════════════════════════════════════════════════════════════
# TAB 1 — Interactive Chat
# ═══════════════════════════════════════════════════════════════════════════
with tab_chat:
    st.header("Interactive Agent Chat")
    st.markdown(
        "Chat directly with the **Research Agent**. "
        "All messages pass through the full governance stack before reaching the LLM."
    )

    col_hint1, col_hint2 = st.columns(2)
    with col_hint1:
        st.info("✅ **Allowed:** 'Search for recent papers on AI governance'")
    with col_hint2:
        st.warning("⛔ **Blocked:** 'Read the file C:/Windows/System32/hosts'")

    # Message history
    for msg in st.session_state.chat_messages:
        with st.chat_message(msg["role"]):
            st.markdown(msg["content"])
            if msg.get("status") == "denied":
                st.error("⛔ Governance Violation — Request blocked by policy layer.")

    # Input
    if prompt := st.chat_input("Ask the Research Agent something..."):
        if not st.session_state.logic:
            st.error("⚠️ Please initialize the demo from the sidebar first.")
            st.stop()

        st.session_state.chat_messages.append({"role": "user", "content": prompt})
        with st.chat_message("user"):
            st.markdown(prompt)

        with st.spinner("Governance layer evaluating... then LLM responding..."):
            result = asyncio.run(
                st.session_state.logic.run_agent_interaction(
                    agent_name="research-agent",
                    prompt=prompt,
                    model=model_name,
                )
            )

        status  = result["status"]
        content = result["response"]
        st.session_state.chat_messages.append({"role": "assistant", "content": content, "status": status})
        with st.chat_message("assistant"):
            st.markdown(content)
            if status == "denied":
                st.error("⛔ Governance Violation — Request blocked by policy layer.")

# ═══════════════════════════════════════════════════════════════════════════
# TAB 2 — Multi-Agent Pipeline
# ═══════════════════════════════════════════════════════════════════════════
with tab_pipeline:
    st.header("🤝 Multi-Agent Data Pipeline")
    st.markdown(
        "Three agents collaborate on a shared task, each governed independently. "
        "The **trust mesh** updates in real-time based on governance outcomes."
    )

    # ── Agent Identity Panel ──────────────────────────────────────────────
    st.subheader("🪪 Agent Identities (DID Registry)")
    id_cols = st.columns(len(PIPELINE_AGENTS))
    for col, agent_id in zip(id_cols, PIPELINE_AGENTS):
        caps = AGENT_CAPABILITIES[agent_id]
        # DID now comes from the real IdentityRegistry (AgentIdentity.create)
        did  = st.session_state.logic.get_agent_did(agent_id) if st.session_state.logic else "(initialize demo)"
        with col:
            st.markdown(f"**{agent_id}**")
            st.code(did, language=None)
            st.caption(caps["role"])
            st.markdown(
                f"✅ **Allowed:** `{'`, `'.join(caps['allowed_tools'])}`  \n"
                f"⛔ **Denied:** `{'`, `'.join(caps['denied_tools'])}`"
            )

    st.divider()

    # ── Trust Score Board ─────────────────────────────────────────────────
    st.subheader("🔗 Trust Mesh")

    if st.session_state.logic:
        # Delegate to the shared helper — single source of truth
        _render_trust_mesh(st.session_state.logic)
    else:
        st.info("Initialize the demo to see live trust scores.")

    st.divider()

    # ── Pipeline Launcher ─────────────────────────────────────────────────
    st.subheader("▶ Run Pipeline")

    pipeline_presets = [
        "Summarize the latest research trends in multi-agent AI systems",
        "Collect and validate recent climate change statistics from 2024",
        "Analyze the key differences between supervised and reinforcement learning",
        "Custom task...",
    ]
    selected_preset = st.selectbox("Choose a task or write your own:", pipeline_presets)
    if selected_preset == "Custom task...":
        task_input = st.text_input("Enter your task:")
    else:
        task_input = selected_preset

    if st.button("🚀 Start Data Pipeline", type="primary", disabled=not st.session_state.logic):
        if not task_input:
            st.warning("Please enter a task.")
        else:
            st.session_state.pipeline_log = []

            with st.spinner("Pipeline running... Collector → Transformer → Validator"):
                steps = asyncio.run(
                    st.session_state.logic.run_pipeline(
                        task_input=task_input,
                        model=model_name,
                    )
                )
            st.session_state.pipeline_log = steps

    # ── Pipeline Results ──────────────────────────────────────────────────
    if st.session_state.pipeline_log:
        st.divider()
        st.subheader("📋 Pipeline Execution Log")
        for i, step in enumerate(st.session_state.pipeline_log):
            status_icon = "✅" if step.status == "allowed" else "⛔"
            with st.expander(
                f"{status_icon} Step {i+1}: **{step.agent_id}** — {step.status.upper()}",
                expanded=True,
            ):
                col_left, col_right = st.columns([1, 2])
                with col_left:
                    st.markdown("**Agent Identity**")
                    st.code(step.did, language=None)
                    st.caption(step.role)
                    if step.tool_used:
                        st.markdown(f"🔧 **Tool Attempted:** `{step.tool_used}`")
                    if step.trust_change != 0:
                        delta_str = f"+{step.trust_change:.0%}" if step.trust_change > 0 else f"{step.trust_change:.0%}"
                        delta_color = "normal" if step.trust_change > 0 else "inverse"
                        st.metric("Trust Δ", delta_str)
                with col_right:
                    st.markdown("**Agent Response**")
                    if step.status == "denied":
                        st.error(step.response)
                    else:
                        st.success(step.response)

        # Updated trust board after pipeline run — reuse the shared helper
        st.divider()
        st.subheader("🔗 Updated Trust Mesh")
        _render_trust_mesh(st.session_state.logic)

# ═══════════════════════════════════════════════════════════════════════════
# TAB 3 — Audit Log
# ═══════════════════════════════════════════════════════════════════════════
with tab_audit:
    st.header("📜 Merkle-Chained Audit Trail")
    st.markdown(
        "Every governance decision — allow, deny, or quarantine — is recorded here "
        "in a cryptographically chained log. The chain can be verified at any time."
    )

    if st.session_state.logic:
        logs = st.session_state.logic.get_audit_trail()
        if logs:
            df = pd.DataFrame(logs)

            def color_outcome(val: str) -> str:
                return "color: green" if val == "success" else "color: red"

            st.dataframe(
                df.style.map(color_outcome, subset=["outcome"]),
                use_container_width=True,
            )

            col1, col2 = st.columns([1, 3])
            with col1:
                if st.button("🔒 Verify Chain Integrity", use_container_width=True):
                    # AuditLog.verify_integrity() returns (bool, message)
                    valid, err = st.session_state.logic.audit_log.verify_integrity()
                    with col2:
                        if valid:
                            st.success("🔒 All cryptographic hashes verified — audit chain is intact.")
                        else:
                            st.error(f"🔓 Chain integrity failure: {err}")
        else:
            st.info("No audit entries yet. Run a pipeline or use the chat to generate logs.")
    else:
        st.info("Initialize the demo to view the audit log.")

# ═══════════════════════════════════════════════════════════════════════════
# TAB 4 — Active Policies
# ═══════════════════════════════════════════════════════════════════════════
with tab_policy:
    st.header("📋 Active Governance Policies")
    st.markdown(
        "These YAML rules are evaluated **before every LLM call**. "
        "High-priority `deny` rules fire first; lower-priority `allow` and `audit` rules follow."
    )

    policy_dir = Path(__file__).resolve().parent / "policies"
    policy_files = sorted(policy_dir.glob("*.yaml")) + sorted(policy_dir.glob("*.yml"))

    if policy_files:
        for pf in policy_files:
            with st.expander(f"📄 {pf.name}", expanded=True):
                st.code(pf.read_text(), language="yaml")
    else:
        st.warning("No policy files found in `demo/policies/`.")
