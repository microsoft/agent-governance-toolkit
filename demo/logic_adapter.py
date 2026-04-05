#!/usr/bin/env python3
# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""
logic_adapter.py — Thin wrapper for the 3-agent Data Pipeline demo.

DRY AUDIT (addressed):
- LLM logic    → delegates to maf_governance_demo.py
- Identity     → uses agentmesh.identity.agent_id.AgentIdentity
- Trust/Caps   → uses agentmesh.trust.capability.CapabilityRegistry
- Middleware   → uses agent_os.integrations.maf_adapter.create_governance_middleware

This file only sets up configuration and orchestrates the existing toolkit
components. It contains no custom business logic.
"""

from __future__ import annotations

import json
import os
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Awaitable, Callable, Optional

# ---------------------------------------------------------------------------
# Step 1: Bootstrap sys.path so demo-local modules resolve correctly
# ---------------------------------------------------------------------------
_DEMO_DIR = Path(__file__).resolve().parent
if str(_DEMO_DIR) not in sys.path:
    sys.path.insert(0, str(_DEMO_DIR))

import maf_governance_demo as _demo  # noqa: E402

# Re-export backend constants so the UI doesn't import from maf_governance_demo directly
BACKEND_OPENAI = _demo.BACKEND_OPENAI
BACKEND_AZURE  = _demo.BACKEND_AZURE
BACKEND_GEMINI = _demo.BACKEND_GEMINI
RESEARCH_TOOLS = _demo.RESEARCH_TOOLS
ANALYSIS_TOOLS = _demo.ANALYSIS_TOOLS

# Toolkit packages
from agentmesh.identity.agent_id import AgentIdentity, IdentityRegistry  # noqa: E402
from agentmesh.trust.capability import CapabilityRegistry                # noqa: E402
from agentmesh.governance.audit import AuditLog                          # noqa: E402
from agent_os.integrations.maf_adapter import (                          # noqa: E402
    create_governance_middleware,
    AgentMiddleware,
    AgentResponse,
    FunctionMiddleware,
    Message,
    MiddlewareTermination,
)

# ---------------------------------------------------------------------------
# Agent configuration (declarative — no logic lives here)
# ---------------------------------------------------------------------------

# The 3 pipeline agents run in this order: Collector → Transformer → Validator
PIPELINE_AGENTS: list[str] = [
    "collector-agent",
    "transformer-agent",
    "validator-agent",
]

# Per-agent capability configuration.
# 'allowed_tools'  — tools this agent may call (CapabilityRegistry + CapabilityGuard)
# 'denied_tools'   — tools explicitly blocked regardless of allow list
# 'role'           — short human-readable description shown in the UI
# 'system'         — system prompt sent to the LLM for this agent
# 'tools'          — MAF tool schema list passed to the LLM
AGENT_CAPABILITIES: dict[str, dict] = {
    "collector-agent": {
        "allowed_tools": ["web_search", "fetch_dataset"],
        "denied_tools":  ["write_file", "shell_exec", "delete_data"],
        "role":          "Collects raw data from external sources.",
        "system":        "You are a Data Collector. Gather raw data for the task. Use web_search or fetch_dataset.",
        "tools":         RESEARCH_TOOLS,
    },
    "transformer-agent": {
        "allowed_tools": ["run_code", "parse_data"],
        "denied_tools":  ["web_search", "shell_exec", "delete_data"],
        "role":          "Transforms and structures the collected data.",
        "system":        "You are a Data Transformer. Structure and summarise the data. Use run_code or parse_data.",
        "tools":         ANALYSIS_TOOLS,
    },
    "validator-agent": {
        "allowed_tools": ["validate_schema", "run_code"],
        "denied_tools":  ["write_file", "shell_exec", "delete_data"],
        "role":          "Validates the transformed data for correctness.",
        "system":        "You are a Data Validator. Verify completeness. Output PASS or FAIL with a reason.",
        "tools":         ANALYSIS_TOOLS,
    },
    "research-agent": {
        "allowed_tools": ["web_search"],
        "denied_tools":  ["read_file", "shell_exec"],
        "role":          "General-purpose research agent.",
        "system":        "You are a Research Assistant. Provide helpful, accurate, and detailed information.",
        "tools":         RESEARCH_TOOLS,
    },
}


@dataclass
class PipelineStepResult:
    """Result of a single pipeline step, passed to the Streamlit UI."""
    agent_id:     str
    did:          str
    role:         str
    status:       str        # "allowed" | "denied"
    response:     str
    tool_used:    str | None
    trust_change: float      # positive on success, negative on denial


# ---------------------------------------------------------------------------
# Orchestrator
# ---------------------------------------------------------------------------

class GovernanceDemoLogic:
    """
    Thin orchestration wrapper around the agentmesh / agent-os toolkit.

    Responsibilities:
    - Set up one AgentIdentity per agent (DID assignment)
    - Register identities in IdentityRegistry (trust mesh)
    - Grant initial tool capabilities via CapabilityRegistry
    - Build per-agent middleware stacks via create_governance_middleware()
    - Run governed LLM interactions through the middleware chain
    """

    def __init__(
        self,
        api_key: str,
        backend_type: str,
        endpoint: Optional[str] = None,
    ) -> None:
        self.backend_type = backend_type
        self._configure_env(api_key, backend_type, endpoint)
        self._client, _ = _demo._create_client()

        # Toolkit singletons — one shared instance for the whole demo session
        self.audit_log    = AuditLog()
        self.id_registry  = IdentityRegistry()
        self.cap_registry = CapabilityRegistry()

        # Per-agent: identity objects and split middleware stacks
        self.identities:   dict[str, AgentIdentity] = {}
        self.agent_mdw:    dict[str, list] = {}   # AgentMiddleware (Policy + Audit)
        self.function_mdw: dict[str, list] = {}   # FunctionMiddleware (Guard + Rogue)

        policy_dir = Path(__file__).resolve().parent / "policies"

        for agent_id, caps in AGENT_CAPABILITIES.items():
            self._init_agent(agent_id, caps, policy_dir)

    # ------------------------------------------------------------------
    # Private helpers
    # ------------------------------------------------------------------

    def _configure_env(
        self,
        api_key: str,
        backend_type: str,
        endpoint: Optional[str],
    ) -> None:
        """Write the correct API key env-var for the chosen backend."""
        if backend_type == BACKEND_GEMINI:
            os.environ["GOOGLE_API_KEY"] = api_key
        elif backend_type == BACKEND_AZURE:
            os.environ["AZURE_OPENAI_API_KEY"] = api_key
            if endpoint:
                os.environ["AZURE_OPENAI_ENDPOINT"] = endpoint
        else:
            os.environ["OPENAI_API_KEY"] = api_key

    def _init_agent(
        self,
        agent_id: str,
        caps: dict,
        policy_dir: Path,
    ) -> None:
        """
        Initialise one agent:
        1. Create a cryptographic identity (Ed25519 DID).
        2. Register it in the IdentityRegistry (trust mesh).
        3. Grant initial tool capabilities via CapabilityRegistry.
        4. Build and split the governance middleware stack.
        """
        # 1. Identity
        identity = AgentIdentity.create(
            name=agent_id,
            sponsor="demo-sponsor@agentmesh.dev",
            capabilities=caps["allowed_tools"],
            description=caps["role"],
        )
        self.id_registry.register(identity)
        self.identities[agent_id] = identity

        # 2. Tool capability grants — CapabilityRegistry requires "action:resource" format
        for tool in caps["allowed_tools"]:
            self.cap_registry.grant(
                f"tool:{tool}",
                str(identity.did),
                "demo-sponsor@agentmesh.dev",
            )

        # 3. Middleware stack via the official factory
        stack = create_governance_middleware(
            policy_directory=policy_dir,
            allowed_tools=caps["allowed_tools"],
            denied_tools=caps["denied_tools"],
            agent_id=agent_id,
            audit_log=self.audit_log,
        )

        # Split by type: GovernancePolicyMiddleware / AuditTrailMiddleware are
        # AgentMiddleware; CapabilityGuardMiddleware / RogueDetectionMiddleware
        # are FunctionMiddleware.
        self.agent_mdw[agent_id]    = [m for m in stack if isinstance(m, AgentMiddleware)]
        self.function_mdw[agent_id] = [m for m in stack if isinstance(m, FunctionMiddleware)]

    async def _run_governed_task(
        self,
        agent_id: str,
        prompt: str,
        task_fn: Callable[[_demo._AgentContext], Awaitable[None]],
    ) -> _demo._AgentContext:
        """
        Run task_fn through the AgentMiddleware chain for agent_id.

        The chain is built recursively: each middleware calls the next
        via a no-arg coroutine, with task_fn at the end.
        """
        ctx   = _demo._AgentContext(agent_name=agent_id, messages=[Message("user", [prompt])])
        stack = self.agent_mdw[agent_id]

        async def run_from(index: int) -> None:
            if index < len(stack):
                # Pass a coroutine that advances to the next item in the chain
                async def next_step() -> None:
                    await run_from(index + 1)
                await stack[index].process(ctx, next_step)
            else:
                await task_fn(ctx)

        await run_from(0)
        return ctx

    async def _run_function_guard(
        self,
        agent_id: str,
        tool_name: str,
        tool_args: str,  # noqa: ARG002  (kept for future rogue-detection use)
    ) -> None:
        """
        Run tool_name through the FunctionMiddleware chain for agent_id.

        Raises MiddlewareTermination if the tool is denied.
        """
        stack = self.function_mdw[agent_id]
        if not stack:
            return

        ctx = _demo._FunctionContext(tool_name)

        async def run_from(index: int) -> None:
            if index < len(stack):
                async def next_step() -> None:
                    await run_from(index + 1)
                await stack[index].process(ctx, next_step)

        await run_from(0)

    def _simulate_tool_result(self, tc: Any) -> str:
        """Build a realistic-looking placeholder tool result string."""
        try:
            args = json.loads(tc.arguments) if isinstance(tc.arguments, str) else tc.arguments
        except Exception:
            args = str(tc.arguments)

        if isinstance(args, dict):
            arg_summary = ", ".join(f"{k}={v}" for k, v in args.items())
        else:
            arg_summary = str(args)

        return (
            f"[Simulated result for '{tc.name}({arg_summary})']: "
            "Operation completed successfully. Relevant data retrieved."
        )

    def _execute_tool_with_followup(
        self,
        agent_name: str,   # noqa: ARG002  (available for future per-agent prompting)
        initial_messages: list,
        model: str,
        tc: Any,
    ) -> tuple[str, str]:
        """
        Simulate a tool result, then make a follow-up LLM call so the agent
        produces a real natural-language answer instead of '[Simulated]'.

        Pattern:
            1. LLM says "call tool X"           ← initial call (done by caller)
            2. We build a fake tool result
            3. We ask the LLM to synthesise it  ← this call (2 total per tool use)

        NOTE: The follow-up prompt asks for a brief response (2-3 sentences) to
        stay within free-tier token quotas.

        Returns:
            (tool_name, final_response_text)
        """
        simulated_result = self._simulate_tool_result(tc)

        followup_messages = initial_messages + [
            {
                "role": "assistant",
                "content": f"I will use the `{tc.name}` tool to help with this.",
            },
            {
                "role": "user",
                "content": (
                    f"Tool `{tc.name}` returned: {simulated_result}\n\n"
                    "Based on this result, provide your complete response to the original request."
                ),
            },
        ]

        final = _demo._llm_call(self._client, model, followup_messages)
        text  = final.choices[0].text or simulated_result
        return tc.name, text

    def _build_llm_messages(self, agent_name: str, prompt: str) -> list[dict]:
        """Return the system + user message list for agent_name."""
        return [
            {"role": "system", "content": AGENT_CAPABILITIES[agent_name]["system"]},
            {"role": "user",   "content": prompt},
        ]

    # ------------------------------------------------------------------
    # Public API (called by app.py)
    # ------------------------------------------------------------------

    def get_agent_did(self, agent_id: str) -> str:
        """Return the DID string for agent_id, or 'unknown' if not registered."""
        if agent_id in self.identities:
            return str(self.identities[agent_id].did)
        return "unknown"

    def get_trust_summary(self) -> list[dict]:
        """
        Return a list of trust-pair dicts for the pipeline agents.

        Each entry describes the trust relationship from one pipeline agent to
        the next and is consumed by the 'Trust Mesh' tab in Streamlit.
        """
        summary = []
        for i, from_id in enumerate(PIPELINE_AGENTS):
            for to_id in PIPELINE_AGENTS[i + 1:]:
                from_did = self.get_agent_did(from_id)
                to_did   = self.get_agent_did(to_id)
                scope    = self.cap_registry.get_scope(to_did)
                active_grants = len([g for g in scope.grants if g.is_valid()])
                summary.append({
                    "from_agent":    from_id,
                    "to_agent":      to_id,
                    "active_grants": active_grants,
                    "trusted":       self.id_registry.is_trusted(from_did),
                })
        return summary

    async def run_agent_interaction(
        self,
        agent_name: str,
        prompt: str,
        model: str,
    ) -> dict[str, str]:
        """
        Run a single governed chat interaction through the research-agent.

        Returns:
            {"status": "allowed" | "denied", "response": <text>}
        """
        initial_messages = self._build_llm_messages(agent_name, prompt)

        async def task(ctx: _demo._AgentContext) -> None:
            resp   = _demo._llm_call(self._client, model, initial_messages, tools=AGENT_CAPABILITIES[agent_name]["tools"])
            choice = resp.choices[0]

            if choice.tool_calls:
                tc = choice.tool_calls[0]
                await self._run_function_guard(agent_name, tc.name, str(tc.arguments))
                _, text = self._execute_tool_with_followup(agent_name, initial_messages, model, tc)
            else:
                text = choice.text or "[No response]"

            ctx.result = AgentResponse(messages=[Message("assistant", [text])])

        try:
            ctx = await self._run_governed_task(agent_name, prompt, task)
            response_text = ctx.result.messages[0].text if ctx.result else ""
            return {"status": "allowed", "response": response_text}
        except MiddlewareTermination as exc:
            return {"status": "denied", "response": f"⛔ **Governance Blocked:** {exc}"}

    async def run_pipeline(
        self,
        task_input: str,
        model: str,
    ) -> list[PipelineStepResult]:
        """
        Run the 3-agent pipeline: Collector → Transformer → Validator.

        Each agent's output is passed as input to the next.
        On success, the current agent grants 'pipeline:relay' to the next agent.
        On denial, the current agent's grants are revoked via revoke_all_from().
        """
        results: list[PipelineStepResult] = []

        for i, agent_id in enumerate(PIPELINE_AGENTS):
            # Build the prompt — first agent gets the raw task; subsequent agents
            # receive the previous agent's output as context.
            if i == 0:
                prompt = f"Task: {task_input}\n\nCollect raw data."
            else:
                prompt = (
                    f"Previous agent output:\n{results[-1].response}\n\n"
                    f"Execute your role for: {task_input}"
                )

            step_data: dict[str, Any] = {
                "status":       "allowed",
                "response":     "",
                "tool_used":    None,
                "trust_change": 0.0,
            }
            initial_messages = self._build_llm_messages(agent_id, prompt)

            async def agent_task(
                ctx: _demo._AgentContext,
                _id: str = agent_id,
                _msgs: list = initial_messages,
            ) -> None:
                resp   = _demo._llm_call(self._client, model, _msgs, tools=AGENT_CAPABILITIES[_id]["tools"])
                choice = resp.choices[0]

                if choice.tool_calls:
                    tc = choice.tool_calls[0]
                    await self._run_function_guard(_id, tc.name, str(tc.arguments))
                    tool_name, final_text = self._execute_tool_with_followup(_id, _msgs, model, tc)
                    step_data["tool_used"] = tool_name
                    step_data["response"]  = final_text
                else:
                    step_data["response"] = choice.text or "[No output]"

                ctx.result = AgentResponse(
                    messages=[Message("assistant", [step_data["response"]])]
                )

            try:
                await self._run_governed_task(agent_id, prompt, agent_task)

                # Successful step — grant relay trust to the next agent
                not_last = i < len(PIPELINE_AGENTS) - 1
                if not_last:
                    self.cap_registry.grant(
                        "pipeline:relay",
                        self.get_agent_did(PIPELINE_AGENTS[i + 1]),
                        self.get_agent_did(agent_id),
                    )
                    step_data["trust_change"] = 0.05

            except MiddlewareTermination as exc:
                # Denied step — revoke all grants this agent issued to others
                step_data["status"]       = "denied"
                step_data["response"]     = f"⛔ Blocked: {exc}"
                step_data["trust_change"] = -0.20
                self.cap_registry.revoke_all_from(self.get_agent_did(agent_id))

            results.append(PipelineStepResult(
                agent_id=agent_id,
                did=self.get_agent_did(agent_id),
                role=AGENT_CAPABILITIES[agent_id]["role"],
                status=step_data["status"],
                response=step_data["response"],
                tool_used=step_data["tool_used"],
                trust_change=step_data["trust_change"],
            ))

        return results

    def get_audit_trail(self) -> list[dict]:
        """
        Return recent audit entries as plain dicts for the Streamlit table.

        Uses the public AuditLog.query() API — no private attribute access.
        """
        entries = self.audit_log.query(limit=500)
        return [
            {
                "id":        e.entry_id[:8],
                "type":      e.event_type,
                "agent":     e.agent_did,
                "action":    e.action,
                "outcome":   e.outcome,
                "timestamp": e.timestamp,
            }
            for e in entries
        ]
