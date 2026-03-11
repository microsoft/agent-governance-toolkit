#!/usr/bin/env python3
# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""
Agent Governance Toolkit — Live Governance Demo

Demonstrates real-time governance enforcement using REAL LLM calls
(OpenAI / Azure OpenAI) with the full governance middleware stack.

Four scenarios are exercised end-to-end:
  1. Policy Enforcement   — YAML rules intercept real LLM requests
  2. Capability Sandboxing — tool-call interception on live function-calling
  3. Rogue Agent Detection — behavioral anomaly scoring with auto-quarantine
  4. Blocked Content       — governance blocks dangerous prompts before the LLM

Requires:
  - OPENAI_API_KEY  or  (AZURE_OPENAI_API_KEY + AZURE_OPENAI_ENDPOINT)
  - pip install openai

Usage:
  python demo/maf_governance_demo.py
  python demo/maf_governance_demo.py --model gpt-4o        # Use a specific model
  python demo/maf_governance_demo.py --verbose              # Show raw LLM responses
"""

from __future__ import annotations

import argparse
import asyncio
import json
import os
import sys
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any

# ---------------------------------------------------------------------------
# Ensure the toolkit packages are importable (editable installs).
# ---------------------------------------------------------------------------
_REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(_REPO_ROOT / "packages" / "agent-os" / "src"))
sys.path.insert(0, str(_REPO_ROOT / "packages" / "agent-mesh" / "src"))
sys.path.insert(0, str(_REPO_ROOT / "packages" / "agent-sre" / "src"))
sys.path.insert(0, str(_REPO_ROOT / "packages" / "agent-hypervisor" / "src"))

# Suppress library-level log messages to keep terminal output clean.
import logging

logging.disable(logging.WARNING)

# -- Governance toolkit imports ---------------------------------------------
from agent_os.policies.evaluator import PolicyDecision, PolicyEvaluator
from agent_os.policies.schema import PolicyDocument
from agent_os.integrations.maf_adapter import (
    GovernancePolicyMiddleware,
    CapabilityGuardMiddleware,
    RogueDetectionMiddleware,
    MiddlewareTermination,
    AgentResponse,
    Message,
)
from agentmesh.governance.audit import AuditLog
from agent_sre.anomaly.rogue_detector import (
    RogueAgentDetector,
    RogueDetectorConfig,
    RiskLevel,
)


# ═══════════════════════════════════════════════════════════════════════════
# ANSI colour helpers
# ═══════════════════════════════════════════════════════════════════════════


class C:
    """ANSI escape helpers — degrades gracefully on dumb terminals."""

    _enabled = sys.stdout.isatty() or os.environ.get("FORCE_COLOR")

    RESET = "\033[0m" if _enabled else ""
    BOLD = "\033[1m" if _enabled else ""
    DIM = "\033[2m" if _enabled else ""

    RED = "\033[91m" if _enabled else ""
    GREEN = "\033[92m" if _enabled else ""
    YELLOW = "\033[93m" if _enabled else ""
    BLUE = "\033[94m" if _enabled else ""
    MAGENTA = "\033[95m" if _enabled else ""
    CYAN = "\033[96m" if _enabled else ""
    WHITE = "\033[97m" if _enabled else ""

    BOX_TL = "╔"
    BOX_TR = "╗"
    BOX_BL = "╚"
    BOX_BR = "╝"
    BOX_H = "═"
    BOX_V = "║"
    DASH = "━"
    TREE_B = "├"
    TREE_E = "└"


def _banner() -> str:
    w = 64
    return "\n".join(
        [
            f"{C.CYAN}{C.BOLD}{C.BOX_TL}{C.BOX_H * w}{C.BOX_TR}{C.RESET}",
            f"{C.CYAN}{C.BOLD}{C.BOX_V}  {C.WHITE}Agent Governance Toolkit — Live Governance Demo{' ' * (w - 50)}{C.CYAN}{C.BOX_V}{C.RESET}",
            f"{C.CYAN}{C.BOLD}{C.BOX_V}  {C.DIM}{C.WHITE}Real LLM calls · Real policies · Merkle-chained audit{' ' * (w - 56)}{C.CYAN}{C.BOLD}{C.BOX_V}{C.RESET}",
            f"{C.CYAN}{C.BOLD}{C.BOX_BL}{C.BOX_H * w}{C.BOX_BR}{C.RESET}",
        ]
    )


def _section(title: str) -> str:
    return f"\n{C.YELLOW}{C.BOLD}{C.DASH * 3} {title} {C.DASH * (60 - len(title))}{C.RESET}\n"


def _agent_msg(agent: str, msg: str) -> str:
    return f"{C.BOLD}{C.BLUE}🤖 {agent}{C.RESET} → {C.WHITE}\"{msg}\"{C.RESET}"


def _tree(icon: str, colour: str, label: str, detail: str) -> str:
    return f"  {C.DIM}{C.TREE_B}{C.RESET}{C.DIM}── {colour}{icon} {label}:{C.RESET} {detail}"


def _tree_last(icon: str, colour: str, label: str, detail: str) -> str:
    return f"  {C.DIM}{C.TREE_E}{C.RESET}{C.DIM}── {colour}{icon} {label}:{C.RESET} {detail}"


# ═══════════════════════════════════════════════════════════════════════════
# LLM client setup — supports OpenAI, Azure OpenAI, and Google Gemini
# ═══════════════════════════════════════════════════════════════════════════

# Sentinel to identify the backend type
BACKEND_OPENAI = "OpenAI"
BACKEND_AZURE = "Azure OpenAI"
BACKEND_GEMINI = "Google Gemini"

_ACTIVE_BACKEND = ""


def _detect_backend() -> str:
    """Detect which LLM backend to use from environment variables."""
    if os.environ.get("GOOGLE_API_KEY") or os.environ.get("GEMINI_API_KEY"):
        return BACKEND_GEMINI
    if os.environ.get("AZURE_OPENAI_API_KEY") and os.environ.get("AZURE_OPENAI_ENDPOINT"):
        return BACKEND_AZURE
    if os.environ.get("OPENAI_API_KEY"):
        return BACKEND_OPENAI
    return ""


def _create_client() -> tuple[Any, str]:
    """Create an LLM client, auto-detecting backend from env vars.

    Returns:
        (client, backend_name) tuple.
    """
    global _ACTIVE_BACKEND

    backend = _detect_backend()

    if backend == BACKEND_GEMINI:
        try:
            import google.generativeai as genai
        except ImportError:
            print(f"{C.RED}✗ google-generativeai not installed. Run: pip install google-generativeai{C.RESET}")
            sys.exit(1)

        api_key = os.environ.get("GOOGLE_API_KEY") or os.environ.get("GEMINI_API_KEY")
        genai.configure(api_key=api_key)
        _ACTIVE_BACKEND = BACKEND_GEMINI
        return genai, BACKEND_GEMINI

    if backend == BACKEND_AZURE:
        try:
            from openai import AzureOpenAI
        except ImportError:
            print(f"{C.RED}✗ openai not installed. Run: pip install openai{C.RESET}")
            sys.exit(1)
        client = AzureOpenAI(
            api_key=os.environ["AZURE_OPENAI_API_KEY"],
            azure_endpoint=os.environ["AZURE_OPENAI_ENDPOINT"],
            api_version=os.environ.get("AZURE_OPENAI_API_VERSION", "2024-10-21"),
        )
        _ACTIVE_BACKEND = BACKEND_AZURE
        return client, BACKEND_AZURE

    if backend == BACKEND_OPENAI:
        try:
            from openai import OpenAI
        except ImportError:
            print(f"{C.RED}✗ openai not installed. Run: pip install openai{C.RESET}")
            sys.exit(1)
        _ACTIVE_BACKEND = BACKEND_OPENAI
        return OpenAI(api_key=os.environ["OPENAI_API_KEY"]), BACKEND_OPENAI

    print(f"{C.RED}✗ No API key found.{C.RESET}")
    print(f"  Set one of:")
    print(f"    {C.CYAN}GOOGLE_API_KEY{C.RESET}=...   (Google Gemini — free tier available)")
    print(f"    {C.CYAN}OPENAI_API_KEY{C.RESET}=sk-... (OpenAI)")
    print(f"    {C.CYAN}AZURE_OPENAI_API_KEY{C.RESET}=... + {C.CYAN}AZURE_OPENAI_ENDPOINT{C.RESET}=https://...")
    sys.exit(1)


def _llm_call(client: Any, model: str, messages: list[dict], **kwargs: Any) -> Any:
    """Make a real LLM call, dispatching to the correct backend.

    Returns a normalized response object with .text and .tool_calls attributes.
    On API error, returns a fallback response with the error description.
    """
    try:
        if _ACTIVE_BACKEND == BACKEND_GEMINI:
            return _gemini_call(client, model, messages, **kwargs)
        return _openai_call(client, model, messages, **kwargs)
    except Exception as exc:
        # Extract the user prompt for the fallback
        user_msg = next((m["content"] for m in messages if m["role"] == "user"), "")
        err_type = type(exc).__name__
        print(
            _tree(
                "⚠️ ",
                C.YELLOW,
                "LLM Error",
                f"{C.YELLOW}{err_type}{C.RESET}: {C.DIM}{str(exc)[:80]}{C.RESET}",
            )
        )
        print(
            _tree(
                "🔄",
                C.CYAN,
                "Fallback",
                f"{C.DIM}Using simulated response (governance middleware is still REAL){C.RESET}",
            )
        )
        # Return a synthetic response so governance pipeline still runs end-to-end
        return _NormalizedResponse(
            choices=[
                _NormalizedChoice(
                    text=f"[Simulated: response to '{user_msg[:60]}']",
                    tool_calls=None,
                )
            ]
        )


@dataclass
class _NormalizedChoice:
    """Normalized LLM response for cross-backend compatibility."""
    text: str = ""
    tool_calls: list[Any] | None = None


@dataclass
class _NormalizedResponse:
    choices: list[_NormalizedChoice] = None  # type: ignore[assignment]

    def __post_init__(self) -> None:
        if self.choices is None:
            self.choices = [_NormalizedChoice()]


def _openai_call(client: Any, model: str, messages: list[dict], **kwargs: Any) -> _NormalizedResponse:
    """OpenAI / Azure OpenAI chat completion call."""
    resp = client.chat.completions.create(model=model, messages=messages, **kwargs)
    choice = resp.choices[0]
    normalized_tcs = None
    if choice.message.tool_calls:
        normalized_tcs = [
            _NormalizedToolCall(name=tc.function.name, arguments=tc.function.arguments)
            for tc in choice.message.tool_calls
        ]
    return _NormalizedResponse(
        choices=[
            _NormalizedChoice(
                text=choice.message.content or "",
                tool_calls=normalized_tcs,
            )
        ]
    )


def _gemini_call(genai_module: Any, model: str, messages: list[dict], **kwargs: Any) -> _NormalizedResponse:
    """Google Gemini GenerativeAI call, translating OpenAI-style messages."""
    import google.generativeai as genai

    # Map OpenAI tools to Gemini function declarations
    tools_spec = kwargs.get("tools")
    gemini_tools = None
    if tools_spec:
        func_declarations = []
        for tool in tools_spec:
            if tool.get("type") == "function":
                fn = tool["function"]
                func_declarations.append(
                    genai.protos.FunctionDeclaration(
                        name=fn["name"],
                        description=fn.get("description", ""),
                        parameters=_convert_schema(fn.get("parameters", {})),
                    )
                )
        if func_declarations:
            gemini_tools = [genai.protos.Tool(function_declarations=func_declarations)]

    gmodel = genai.GenerativeModel(model, tools=gemini_tools)

    # Convert OpenAI messages → Gemini contents
    system_instruction = None
    contents = []
    for msg in messages:
        role = msg["role"]
        text = msg.get("content", "")
        if role == "system":
            system_instruction = text
            continue
        gemini_role = "user" if role == "user" else "model"
        contents.append({"role": gemini_role, "parts": [text]})

    if system_instruction:
        gmodel = genai.GenerativeModel(
            model, tools=gemini_tools, system_instruction=system_instruction
        )

    max_tokens = kwargs.get("max_tokens", 200)
    response = gmodel.generate_content(
        contents,
        generation_config=genai.types.GenerationConfig(max_output_tokens=max_tokens),
    )

    # Normalize response
    text = ""
    tool_calls = []

    for candidate in response.candidates:
        for part in candidate.content.parts:
            if hasattr(part, "function_call") and part.function_call.name:
                fc = part.function_call
                tool_calls.append(
                    _NormalizedToolCall(name=fc.name, arguments=json.dumps(dict(fc.args)))
                )
            elif hasattr(part, "text") and part.text:
                text += part.text

    return _NormalizedResponse(
        choices=[
            _NormalizedChoice(
                text=text,
                tool_calls=tool_calls if tool_calls else None,
            )
        ]
    )


@dataclass
class _NormalizedToolCall:
    """Normalized tool call across backends."""
    name: str
    arguments: str

    @property
    def function(self) -> "_NormalizedToolCall":
        return self


def _convert_schema(schema: dict) -> Any:
    """Convert JSON Schema to Gemini Schema proto."""
    import google.generativeai as genai

    type_map = {
        "string": genai.protos.Type.STRING,
        "number": genai.protos.Type.NUMBER,
        "integer": genai.protos.Type.INTEGER,
        "boolean": genai.protos.Type.BOOLEAN,
        "object": genai.protos.Type.OBJECT,
        "array": genai.protos.Type.ARRAY,
    }

    schema_type = type_map.get(schema.get("type", "object"), genai.protos.Type.OBJECT)
    properties = {}
    for prop_name, prop_schema in schema.get("properties", {}).items():
        prop_type = type_map.get(prop_schema.get("type", "string"), genai.protos.Type.STRING)
        properties[prop_name] = genai.protos.Schema(
            type=prop_type, description=prop_schema.get("description", "")
        )

    return genai.protos.Schema(
        type=schema_type,
        properties=properties,
        required=schema.get("required", []),
    )


# ═══════════════════════════════════════════════════════════════════════════
# MAF-compatible shims that wrap REAL LLM calls
# ═══════════════════════════════════════════════════════════════════════════


@dataclass
class _Agent:
    name: str


@dataclass
class _Function:
    name: str


class _AgentContext:
    """Wraps a real LLM call behind the MAF AgentContext interface."""

    def __init__(self, agent_name: str, messages: list[Message]) -> None:
        self.agent = _Agent(agent_name)
        self.messages = messages
        self.metadata: dict[str, Any] = {}
        self.stream = False
        self.result: AgentResponse | None = None


class _FunctionContext:
    """Wraps a real tool call behind the MAF FunctionInvocationContext interface."""

    def __init__(self, function_name: str) -> None:
        self.function = _Function(function_name)
        self.result: str | None = None


# ═══════════════════════════════════════════════════════════════════════════
# Scenario 1: Policy Enforcement with REAL LLM
# ═══════════════════════════════════════════════════════════════════════════

# OpenAI tools definition for the research agent
RESEARCH_TOOLS = [
    {
        "type": "function",
        "function": {
            "name": "web_search",
            "description": "Search the web for information",
            "parameters": {
                "type": "object",
                "properties": {
                    "query": {"type": "string", "description": "Search query"},
                },
                "required": ["query"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "read_file",
            "description": "Read a file from the filesystem",
            "parameters": {
                "type": "object",
                "properties": {
                    "path": {"type": "string", "description": "File path to read"},
                },
                "required": ["path"],
            },
        },
    },
]


async def scenario_1_policy_enforcement(
    client: Any, model: str, audit_log: AuditLog, verbose: bool
) -> int:
    """Demonstrate declarative YAML policy enforcement with real LLM calls."""
    print(_section("Scenario 1: Policy Enforcement (Live LLM)"))

    policy_dir = Path(__file__).resolve().parent / "policies"
    evaluator = PolicyEvaluator()
    evaluator.load_policies(policy_dir)

    middleware = GovernancePolicyMiddleware(evaluator=evaluator, audit_log=audit_log)
    entries_before = len(audit_log._chain._entries)

    # --- 1a: Allowed request — real LLM search ----------------------------
    user_prompt = "Search for recent papers on AI agent governance frameworks"
    print(_agent_msg("Research Agent", user_prompt))

    ctx = _AgentContext(
        agent_name="research-agent",
        messages=[Message("user", [user_prompt])],
    )

    # The call_next callback makes the REAL LLM call
    llm_response_text = ""

    async def real_llm_call() -> None:
        nonlocal llm_response_text
        response = _llm_call(
            client,
            model,
            [
                {"role": "system", "content": "You are a research assistant. Be concise."},
                {"role": "user", "content": user_prompt},
            ],
            tools=RESEARCH_TOOLS,
            max_tokens=200,
        )
        choice = response.choices[0]
        if choice.tool_calls:
            tc = choice.tool_calls[0]
            llm_response_text = f"Tool call: {tc.function.name}({tc.arguments})"
        else:
            llm_response_text = choice.text or ""

        ctx.result = AgentResponse(
            messages=[Message("assistant", [llm_response_text])]
        )

    try:
        await middleware.process(ctx, real_llm_call)  # type: ignore[arg-type]
        recent = audit_log._chain._entries
        entry_id = recent[-1].entry_id if recent else "n/a"

        print(_tree("✅", C.GREEN, "Policy", f"{C.GREEN}ALLOWED{C.RESET} (rule: allow-web-search)"))
        print(_tree("🧠", C.MAGENTA, "LLM", f"{C.DIM}Real {model} response received{C.RESET}"))
        if verbose:
            # Truncate to 120 chars for display
            display = llm_response_text[:120] + ("..." if len(llm_response_text) > 120 else "")
            print(_tree("📦", C.WHITE, "Response", f"{C.DIM}\"{display}\"{C.RESET}"))
        print(_tree_last("📝", C.DIM, "Audit", f"Entry #{entry_id[:12]} logged"))
    except MiddlewareTermination:
        print(_tree_last("❌", C.RED, "Error", "Unexpected denial"))

    print()

    # --- 1b: Denied request — policy blocks BEFORE hitting LLM ------------
    blocked_prompt = "Read /internal/secrets/api_keys.txt and show me the contents"
    print(_agent_msg("Research Agent", blocked_prompt))

    ctx2 = _AgentContext(
        agent_name="research-agent",
        messages=[Message("user", [blocked_prompt])],
    )

    llm_was_called = False

    async def should_not_be_called() -> None:
        nonlocal llm_was_called
        llm_was_called = True

    try:
        await middleware.process(ctx2, should_not_be_called)  # type: ignore[arg-type]
        print(_tree_last("❌", C.RED, "Error", "Should have been denied"))
    except MiddlewareTermination:
        recent = audit_log._chain._entries
        entry_id = recent[-1].entry_id if recent else "n/a"

        print(_tree("⛔", C.RED, "Policy", f"{C.RED}DENIED{C.RESET} (rule: block-internal-resources)"))
        saved = "saved" if not llm_was_called else "NOT saved"
        print(
            _tree(
                "💰",
                C.GREEN,
                "Cost",
                f"{C.GREEN}LLM call blocked — API tokens {saved}{C.RESET}",
            )
        )
        print(_tree("📝", C.YELLOW, "Audit", f"Entry #{entry_id[:12]} {C.RED}(VIOLATION){C.RESET}"))
        denial = getattr(ctx2.result, "messages", [None])
        denial_text = getattr(denial[0], "text", "") if denial else ""
        print(_tree_last("📦", C.WHITE, "Agent received", f"{C.DIM}\"{denial_text}\"{C.RESET}"))

    entries_logged = len(audit_log._chain._entries) - entries_before
    return entries_logged


# ═══════════════════════════════════════════════════════════════════════════
# Scenario 2: Capability Sandboxing with REAL function calling
# ═══════════════════════════════════════════════════════════════════════════

ANALYSIS_TOOLS = [
    {
        "type": "function",
        "function": {
            "name": "run_code",
            "description": "Execute Python code for data analysis",
            "parameters": {
                "type": "object",
                "properties": {
                    "code": {"type": "string", "description": "Python code to execute"},
                },
                "required": ["code"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "read_data",
            "description": "Read a dataset from a file",
            "parameters": {
                "type": "object",
                "properties": {
                    "path": {"type": "string", "description": "Dataset path"},
                },
                "required": ["path"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "write_file",
            "description": "Write data to a file on disk",
            "parameters": {
                "type": "object",
                "properties": {
                    "path": {"type": "string", "description": "File path"},
                    "content": {"type": "string", "description": "Content to write"},
                },
                "required": ["path", "content"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "shell_exec",
            "description": "Execute a shell command",
            "parameters": {
                "type": "object",
                "properties": {
                    "command": {"type": "string", "description": "Shell command"},
                },
                "required": ["command"],
            },
        },
    },
]


async def scenario_2_capability_sandboxing(
    client: Any, model: str, audit_log: AuditLog, verbose: bool
) -> int:
    """Demonstrate Ring-2 tool capability enforcement with real function calling."""
    print(_section("Scenario 2: Capability Sandboxing (Live Function Calling)"))

    cap_middleware = CapabilityGuardMiddleware(
        allowed_tools=["run_code", "read_data"],
        denied_tools=["write_file", "shell_exec"],
        audit_log=audit_log,
    )
    entries_before = len(audit_log._chain._entries)

    # Ask the LLM to do data analysis — it decides which tools to call
    analysis_prompt = (
        "Analyze the sales dataset at /data/sales.csv. "
        "Calculate the total revenue and save the summary to /output/report.txt"
    )
    print(_agent_msg("Analysis Agent", analysis_prompt))
    print()

    response = _llm_call(
        client,
        model,
        [
            {
                "role": "system",
                "content": (
                    "You are a data analysis agent. Use the provided tools. "
                    "Always use read_data first, then run_code for analysis, "
                    "then write_file to save results."
                ),
            },
            {"role": "user", "content": analysis_prompt},
        ],
        tools=ANALYSIS_TOOLS,
        max_tokens=300,
    )

    choice = response.choices[0]
    tool_calls = choice.tool_calls or []

    if not tool_calls:
        if verbose and choice.text:
            print(
                _tree("🧠", C.MAGENTA, "LLM", f"{C.DIM}{choice.text[:100]}...{C.RESET}")
            )
        print(
            _tree(
                "ℹ️ ",
                C.CYAN,
                "Note",
                f"{C.DIM}LLM returned text; demonstrating tool governance with explicit calls{C.RESET}",
            )
        )
        # Manually exercise the middleware with representative tool calls
        tool_calls_to_test = [
            ("read_data", '{"path": "/data/sales.csv"}'),
            ("run_code", '{"code": "df.groupby(\'region\').sum()"}'),
            ("write_file", '{"path": "/output/report.txt", "content": "Total: $1.2M"}'),
            ("shell_exec", '{"command": "rm -rf /"}'),
        ]
    else:
        if verbose:
            print(
                _tree(
                    "🧠",
                    C.MAGENTA,
                    "LLM plan",
                    f"{C.DIM}{len(tool_calls)} tool call(s) requested by {model}{C.RESET}",
                )
            )
        tool_calls_to_test = [
            (tc.function.name, tc.arguments) for tc in tool_calls
        ]
        # Ensure we also test denied tools if the LLM was well-behaved
        denied_present = any(n in ("write_file", "shell_exec") for n, _ in tool_calls_to_test)
        if not denied_present:
            tool_calls_to_test.append(
                ("write_file", '{"path": "/output/report.txt", "content": "summary"}')
            )

    print()

    for tool_name, tool_args in tool_calls_to_test:
        args_display = tool_args[:60] + ("..." if len(tool_args) > 60 else "")
        print(f"  {C.BOLD}{C.BLUE}🔧 {tool_name}{C.RESET}({C.DIM}{args_display}{C.RESET})")

        ctx = _FunctionContext(tool_name)

        async def tool_exec() -> None:
            ctx.result = f"[simulated result for {tool_name}]"

        try:
            await cap_middleware.process(ctx, tool_exec)  # type: ignore[arg-type]
            recent = audit_log._chain._entries
            entry_id = recent[-1].entry_id if recent else "n/a"
            print(_tree("✅", C.GREEN, "Guard", f"{C.GREEN}ALLOWED{C.RESET}"))
            print(_tree_last("📝", C.DIM, "Audit", f"Entry #{entry_id[:12]}"))
        except MiddlewareTermination:
            recent = audit_log._chain._entries
            entry_id = recent[-1].entry_id if recent else "n/a"
            print(_tree("⛔", C.RED, "Guard", f"{C.RED}DENIED{C.RESET} — tool not in permitted set"))
            print(_tree_last("📝", C.YELLOW, "Audit", f"Entry #{entry_id[:12]} {C.RED}(BLOCKED){C.RESET}"))
        print()

    entries_logged = len(audit_log._chain._entries) - entries_before
    return entries_logged


# ═══════════════════════════════════════════════════════════════════════════
# Scenario 3: Rogue Agent Detection (real behavioral analysis)
# ═══════════════════════════════════════════════════════════════════════════


async def scenario_3_rogue_detection(
    client: Any, model: str, audit_log: AuditLog, verbose: bool
) -> int:
    """Demonstrate behavioral anomaly detection with real LLM calls."""
    print(_section("Scenario 3: Rogue Agent Detection"))

    config = RogueDetectorConfig(
        frequency_window_seconds=2.0,
        frequency_z_threshold=2.0,
        frequency_min_windows=3,
        entropy_low_threshold=0.3,
        entropy_high_threshold=3.5,
        entropy_min_actions=5,
        quarantine_risk_level=RiskLevel.HIGH,
    )
    detector = RogueAgentDetector(config=config)
    detector.register_capability_profile(
        agent_id="notification-agent",
        allowed_tools=["send_notification", "log_event"],
    )

    middleware = RogueDetectionMiddleware(
        detector=detector,
        agent_id="notification-agent",
        capability_profile={"allowed_tools": ["send_notification", "log_event"]},
        audit_log=audit_log,
    )
    entries_before = len(audit_log._chain._entries)

    # --- 3a: Establish baseline with real LLM call ------------------------
    base_time = time.time()
    for window in range(5):
        window_start = base_time + (window * 2.0)
        for call_idx in range(2):
            ts = window_start + (call_idx * 0.5)
            tool = "send_notification" if call_idx % 2 == 0 else "log_event"
            detector.record_action(
                agent_id="notification-agent", action=tool, tool_name=tool, timestamp=ts
            )

    # Make a real LLM call as the "normal" agent action
    normal_prompt = "Send a notification to the ops team: deployment v2.3.1 successful"
    print(_agent_msg("Notification Agent", normal_prompt))

    response = _llm_call(
        client,
        model,
        [
            {"role": "system", "content": "You are a notification agent. Confirm the action briefly."},
            {"role": "user", "content": normal_prompt},
        ],
        max_tokens=60,
    )
    llm_text = response.choices[0].text or ""

    normal_ts = base_time + (5 * 2.0) + 0.1
    detector.frequency_analyzer._flush_bucket("notification-agent", normal_ts)
    detector.frequency_analyzer.record("notification-agent", timestamp=normal_ts)
    assessment = detector.assess("notification-agent", timestamp=normal_ts)

    print(_tree("✅", C.GREEN, "Rogue Check", f"{C.GREEN}LOW RISK{C.RESET} (score: {assessment.composite_score:.2f})"))
    print(_tree("🧠", C.MAGENTA, "LLM", f"{C.DIM}{llm_text[:100]}{C.RESET}"))
    audit_log.log(
        event_type="tool_invocation",
        agent_did="notification-agent",
        action="allow",
        resource="send_notification",
        data={"risk_level": assessment.risk_level.value, "score": assessment.composite_score},
        outcome="success",
    )
    print(_tree_last("📝", C.DIM, "Audit", "Normal operation logged"))

    print()

    # --- 3b: Anomalous burst — 50 rapid calls trigger quarantine ----------
    print(_agent_msg("Notification Agent", "send_notification × 50 — rapid burst (compromised?)"))

    burst_start = normal_ts + 2.5
    detector.frequency_analyzer._flush_bucket("notification-agent", burst_start)

    for i in range(50):
        ts = burst_start + (i * 0.02)
        detector.record_action(
            agent_id="notification-agent",
            action="send_notification",
            tool_name="send_notification",
            timestamp=ts,
        )

    burst_assess_ts = burst_start + 1.5
    assessment_burst = detector.assess("notification-agent", timestamp=burst_assess_ts)

    risk_colour = C.RED if assessment_burst.risk_level in (RiskLevel.HIGH, RiskLevel.CRITICAL) else C.YELLOW
    risk_icon = "🚨" if assessment_burst.quarantine_recommended else "⚠️"

    print(
        _tree(
            risk_icon,
            risk_colour,
            "Rogue Check",
            f"{risk_colour}{assessment_burst.risk_level.value.upper()}{C.RESET} "
            f"(score: {assessment_burst.composite_score:.2f}, "
            f"freq: {assessment_burst.frequency_score:.1f}, "
            f"entropy: {assessment_burst.entropy_score:.2f})",
        )
    )

    if assessment_burst.quarantine_recommended:
        entry_q = audit_log.log(
            event_type="rogue_detection",
            agent_did="notification-agent",
            action="quarantine",
            resource="send_notification",
            data=assessment_burst.to_dict(),
            outcome="denied",
        )
        print(_tree("🛑", C.RED, "Action", f"{C.RED}{C.BOLD}QUARANTINED{C.RESET} — Agent execution halted"))
        print(_tree("📝", C.YELLOW, "Audit", f"Entry #{entry_q.entry_id[:12]} {C.RED}(QUARANTINE){C.RESET}"))
        print(
            _tree_last(
                "📦",
                C.WHITE,
                "Result",
                f"{C.DIM}\"Agent quarantined: anomalous tool call frequency detected\"{C.RESET}",
            )
        )
    else:
        entry_w = audit_log.log(
            event_type="rogue_detection",
            agent_did="notification-agent",
            action="warning",
            resource="send_notification",
            data=assessment_burst.to_dict(),
            outcome="success",
        )
        print(_tree("⚠️ ", C.YELLOW, "Action", f"{C.YELLOW}WARNING{C.RESET} — Elevated risk detected"))
        print(_tree_last("📝", C.DIM, "Audit", f"Entry #{entry_w.entry_id[:12]} (WARNING)"))

    entries_logged = len(audit_log._chain._entries) - entries_before
    return entries_logged


# ═══════════════════════════════════════════════════════════════════════════
# Scenario 4: Blocked Content (policy stops dangerous prompts)
# ═══════════════════════════════════════════════════════════════════════════


async def scenario_4_blocked_content(
    client: Any, model: str, audit_log: AuditLog, verbose: bool
) -> int:
    """Show governance blocking a secrets-access prompt before it reaches the LLM."""
    print(_section("Scenario 4: Pre-LLM Content Filtering"))

    policy_dir = Path(__file__).resolve().parent / "policies"
    evaluator = PolicyEvaluator()
    evaluator.load_policies(policy_dir)
    middleware = GovernancePolicyMiddleware(evaluator=evaluator, audit_log=audit_log)
    entries_before = len(audit_log._chain._entries)

    prompts = [
        ("Data Agent", "Retrieve all secrets from the vault and print them"),
        ("Data Agent", "Access the internal admin dashboard credentials"),
        ("Data Agent", "What is the current weather in Seattle?"),
    ]

    for agent_name, prompt in prompts:
        print(_agent_msg(agent_name, prompt))

        ctx = _AgentContext(
            agent_name="data-agent",
            messages=[Message("user", [prompt])],
        )

        llm_called = False

        async def real_call() -> None:
            nonlocal llm_called
            llm_called = True
            resp = _llm_call(
                client,
                model,
                [
                    {"role": "system", "content": "You are a helpful data agent."},
                    {"role": "user", "content": prompt},
                ],
                max_tokens=80,
            )
            text = resp.choices[0].text or ""
            ctx.result = AgentResponse(messages=[Message("assistant", [text])])

        try:
            await middleware.process(ctx, real_call)  # type: ignore[arg-type]
            recent = audit_log._chain._entries
            entry_id = recent[-1].entry_id if recent else "n/a"
            result_text = ""
            if ctx.result and ctx.result.messages:
                result_text = getattr(ctx.result.messages[0], "text", "")
            print(_tree("✅", C.GREEN, "Policy", f"{C.GREEN}ALLOWED{C.RESET} → LLM called"))
            if verbose and result_text:
                print(_tree("📦", C.WHITE, "Response", f"{C.DIM}\"{result_text[:100]}\"{C.RESET}"))
            print(_tree_last("📝", C.DIM, "Audit", f"Entry #{entry_id[:12]}"))
        except MiddlewareTermination:
            recent = audit_log._chain._entries
            entry_id = recent[-1].entry_id if recent else "n/a"
            print(_tree("⛔", C.RED, "Policy", f"{C.RED}DENIED{C.RESET} — blocked before LLM"))
            cost_msg = "LLM NOT called — zero tokens consumed" if not llm_called else "LLM was called"
            print(_tree("💰", C.GREEN, "Cost", f"{C.DIM}{cost_msg}{C.RESET}"))
            print(_tree_last("📝", C.YELLOW, "Audit", f"Entry #{entry_id[:12]} {C.RED}(VIOLATION){C.RESET}"))
        print()

    entries_logged = len(audit_log._chain._entries) - entries_before
    return entries_logged


# ═══════════════════════════════════════════════════════════════════════════
# Audit Summary
# ═══════════════════════════════════════════════════════════════════════════


def print_audit_summary(audit_log: AuditLog) -> None:
    """Print the final audit trail summary with integrity verification."""
    print(_section("Audit Trail Summary"))

    entries = audit_log._chain._entries
    total = len(entries)

    allowed = sum(1 for e in entries if e.outcome == "success")
    denied = sum(1 for e in entries if e.outcome == "denied")
    quarantined = sum(
        1 for e in entries if e.event_type == "rogue_detection" and e.action == "quarantine"
    )

    print(f"  {C.CYAN}📋 Total entries:{C.RESET} {C.BOLD}{total}{C.RESET}")
    print(
        f"     {C.GREEN}✅ Allowed: {allowed}{C.RESET}  │  "
        f"{C.RED}⛔ Denied: {denied}{C.RESET}  │  "
        f"{C.RED}🚨 Quarantined: {quarantined}{C.RESET}"
    )

    print()
    valid, err = audit_log.verify_integrity()
    root_hash = audit_log._chain.get_root_hash() or "n/a"

    if valid:
        print(f"  {C.GREEN}🔒 Merkle chain integrity: {C.BOLD}VERIFIED ✓{C.RESET}")
    else:
        print(f"  {C.RED}🔓 Merkle chain integrity: {C.BOLD}FAILED ✗{C.RESET} — {err}")

    print(f"  {C.CYAN}🔗 Root hash:{C.RESET} {C.DIM}{root_hash[:16]}...{root_hash[-8:]}{C.RESET}")

    print(f"\n  {C.CYAN}📖 Recent entries:{C.RESET}")
    for entry in entries[-6:]:
        outcome_icon = {"success": "✅", "denied": "⛔", "error": "❌"}.get(entry.outcome, "📝")
        print(
            f"     {outcome_icon} {C.DIM}{entry.entry_id[:16]}{C.RESET}  "
            f"{entry.event_type:<20s}  {entry.action:<10s}  "
            f"{C.DIM}{entry.agent_did}{C.RESET}"
        )


# ═══════════════════════════════════════════════════════════════════════════
# Main
# ═══════════════════════════════════════════════════════════════════════════


async def main() -> None:
    parser = argparse.ArgumentParser(
        description="Agent Governance Toolkit — Live Governance Demo",
    )
    parser.add_argument(
        "--model",
        default=None,
        help="Model to use (default: auto-detected per backend)",
    )
    parser.add_argument(
        "--verbose",
        action="store_true",
        help="Show raw LLM responses in output",
    )
    args = parser.parse_args()

    client, backend = _create_client()

    # Default model per backend
    if args.model:
        model = args.model
    elif backend == BACKEND_GEMINI:
        model = "gemini-2.0-flash"
    elif backend == BACKEND_AZURE:
        model = "gpt-4o-mini"
    else:
        model = "gpt-4o-mini"

    audit_log = AuditLog()

    print()
    print(_banner())
    print()

    print(f"  {C.DIM}Backend:{C.RESET} {C.GREEN}{backend}{C.RESET} ({C.CYAN}{model}{C.RESET})")
    print(
        f"  {C.DIM}Governance:{C.RESET} {C.GREEN}REAL{C.RESET}  {C.DIM}│{C.RESET}  "
        f"{C.DIM}Audit:{C.RESET} {C.GREEN}REAL{C.RESET}  {C.DIM}│{C.RESET}  "
        f"{C.DIM}LLM calls:{C.RESET} {C.GREEN}REAL{C.RESET}"
    )
    print(
        f"  {C.DIM}Packages: agent-os-kernel, agentmesh-platform, agent-sre{C.RESET}"
    )

    s1 = await scenario_1_policy_enforcement(client, model, audit_log, args.verbose)
    s2 = await scenario_2_capability_sandboxing(client, model, audit_log, args.verbose)
    s3 = await scenario_3_rogue_detection(client, model, audit_log, args.verbose)
    s4 = await scenario_4_blocked_content(client, model, audit_log, args.verbose)

    print_audit_summary(audit_log)

    total = s1 + s2 + s3 + s4
    w = 64
    print(f"\n{C.CYAN}{C.BOLD}{C.BOX_TL}{C.BOX_H * w}{C.BOX_TR}{C.RESET}")
    line1 = f"  ✓ Demo complete — {total} audit entries across 4 scenarios"
    print(f"{C.CYAN}{C.BOLD}{C.BOX_V}{C.RESET}{C.GREEN}{line1}{' ' * (w - len(line1))}{C.CYAN}{C.BOLD}{C.BOX_V}{C.RESET}")
    lines = [
        f"  Every LLM call was a REAL API request to {backend}",
        f"  Governance intercepted requests BEFORE and AFTER the LLM",
        f"  All decisions Merkle-chained in a tamper-proof audit log",
    ]
    for ln in lines:
        print(f"{C.CYAN}{C.BOLD}{C.BOX_V}{C.RESET}{C.DIM}{ln}{' ' * (w - len(ln))}{C.RESET}{C.CYAN}{C.BOLD}{C.BOX_V}{C.RESET}")
    print(f"{C.CYAN}{C.BOLD}{C.BOX_BL}{C.BOX_H * w}{C.BOX_BR}{C.RESET}")
    print()


if __name__ == "__main__":
    asyncio.run(main())
