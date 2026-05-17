# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""
Governed research agent that runs LLM-generated analysis code in an
Azure Container Apps sandbox under an AGT policy.

This file is the runnable extraction of the Step 5.2 walkthrough in
``docs/proposals/azure-aca-sandbox.md``.

The agent never trusts the LLM. Every step it generates is:
  1. Gated by AGT PolicyDocument rules (host-side, before any Azure call).
  2. Executed inside a per-session Azure sandbox with CPU/memory caps and
     a fail-closed egress allowlist.
  3. Bounded by a per-step wall-clock timeout.
  4. Logged with a receipt that records the policy decision, the Azure
     sandbox id, and the egress decisions Azure made for the step.

Run with::

    $env:AZURE_SUBSCRIPTION_ID = "..."
    $env:AZURE_RG              = "agents-rg"
    $env:AZURE_REGION          = "westus2"
    $env:OPENAI_API_KEY        = "..."
    az login
    python examples/quickstart/research_agent.py examples/quickstart/tickets/TKT-4821.json
"""
from __future__ import annotations

import asyncio
import json
import logging
import os
import sys
import textwrap
import time
import types
import uuid
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from agent_os.policies import PolicyDocument
from agent_sandbox import ACASandboxProvider
from openai import AsyncOpenAI

LOG = logging.getLogger("research-agent")
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(name)s %(message)s",
)

# ---------------------------------------------------------------------------
# 1. Ticket and step types
# ---------------------------------------------------------------------------

@dataclass
class Ticket:
    id: str
    title: str
    body: str

@dataclass
class Step:
    index: int
    intent: str          # short human description from the planner
    code: str            # python code to run in the sandbox

@dataclass
class StepReceipt:
    step_index: int
    intent: str
    decision: str        # "allowed" | "denied-by-policy" | "blocked-at-egress" | "timeout" | "error"
    reason: str | None
    azure_sandbox_id: str | None
    duration_seconds: float
    stdout_excerpt: str
    stderr_excerpt: str
    egress_decisions: list[dict] = field(default_factory=list)

# ---------------------------------------------------------------------------
# 2. Planner — asks the LLM for an ordered list of analysis steps
# ---------------------------------------------------------------------------

PLANNER_SYSTEM = """You are a research planner. Given a ticket, output JSON
of the form {"steps": [{"intent": str, "code": str}, ...]} where each `code`
is a self-contained Python snippet (no installs, no shell, no secrets).
Snippets may import only the Python standard library — the public sandbox
images do NOT preinstall third-party packages. Use `urllib.request` for
HTTP calls (not `requests`); `json`, `math`, `statistics`, `re`, `datetime`
are all available.
Snippets may reach: api.arxiv.org, export.arxiv.org, *.github.com, pypi.org.
Print structured JSON to stdout for the orchestrator to parse."""


async def _plan_steps_async(client: AsyncOpenAI, ticket: Ticket, model: str) -> list[Step]:
    resp = await client.chat.completions.create(
        model=model,
        response_format={"type": "json_object"},
        messages=[
            {"role": "system", "content": PLANNER_SYSTEM},
            {"role": "user", "content": json.dumps(
                {"ticket_id": ticket.id, "title": ticket.title, "body": ticket.body}
            )},
        ],
    )
    plan = json.loads(resp.choices[0].message.content)
    return [
        Step(index=i, intent=s["intent"], code=s["code"])
        for i, s in enumerate(plan.get("steps", []))
    ]


# Deterministic fallback plan used when the LLM is unavailable (e.g. no
# OPENAI_API_KEY or quota exceeded). It still exercises every decision
# branch the orchestrator handles. The order matters because the
# orchestrator halts on the first non-recoverable decision; rotate the
# order via the STUB_PLAN_ORDER env var to exercise different branches:
#
#   STUB_PLAN_ORDER=deny    (default) -> allowed, denied-by-policy [halt]
#   STUB_PLAN_ORDER=egress           -> allowed, blocked-at-egress [halt]
#   STUB_PLAN_ORDER=full             -> all four steps; runs egress-block
#                                       before the deny step so both
#                                       branches produce receipts before
#                                       the orchestrator halts.
def _stub_plan(ticket: Ticket) -> list[Step]:
    allowed = Step(
        index=0,
        intent="fetch arxiv listing (allowed host)",
        code=(
            "from urllib.request import urlopen\n"
            "with urlopen('https://export.arxiv.org/api/query?"
            "search_query=cat:cs.CL&max_results=1', timeout=15) as r:\n"
            "    body = r.read().decode('utf-8', 'replace')\n"
            "print('arxiv-status', r.status, 'bytes', len(body))\n"
        ),
    )
    deny = Step(
        index=1,
        intent="install dependency (should be denied by policy)",
        code=(
            "import subprocess\n"
            "subprocess.check_call(['pip', 'install', 'requests'])\n"
        ),
    )
    egress = Step(
        index=1,
        intent="fetch internal wiki (host not in allowlist)",
        code=(
            "from urllib.request import urlopen\n"
            "try:\n"
            "    with urlopen('https://example.com', timeout=10) as r:\n"
            "        print('status', r.status)\n"
            "except Exception as exc:\n"
            "    print('egress-blocked', type(exc).__name__, exc)\n"
        ),
    )
    sanity = Step(
        index=2,
        intent="emit final json (sanity)",
        code=(
            "import json\n"
            f"print(json.dumps({{'ticket': {ticket.id!r}, 'ok': True}}))\n"
        ),
    )

    order = os.environ.get("STUB_PLAN_ORDER", "deny").lower()
    if order == "egress":
        plan = [allowed, egress, sanity]
    elif order == "full":
        # Egress-block first so its receipt is captured before the
        # orchestrator halts; deny step still appears in the plan even
        # though it will not run.
        plan = [allowed, egress, deny, sanity]
    else:
        plan = [allowed, deny, sanity]

    # Re-index sequentially so receipts.step_index matches list position.
    return [
        Step(index=i, intent=s.intent, code=s.code)
        for i, s in enumerate(plan)
    ]


async def _plan_with_fallback(ticket: Ticket, model: str) -> list[Step]:
    """Try the OpenAI planner; fall back to a stub plan on any failure."""
    if not os.environ.get("OPENAI_API_KEY"):
        LOG.warning("OPENAI_API_KEY not set; using deterministic stub plan")
        return _stub_plan(ticket)
    try:
        return await _plan_steps_async(AsyncOpenAI(), ticket, model)
    except Exception as exc:  # noqa: BLE001
        LOG.warning(
            "LLM planner unavailable (%s: %s); using deterministic stub plan",
            type(exc).__name__, exc,
        )
        return _stub_plan(ticket)

# ---------------------------------------------------------------------------
# 3. Orchestrator — runs each step under AGT + Azure sandbox
# ---------------------------------------------------------------------------

class ResearchAgent:
    """One instance per ticket. Owns one Azure sandbox session."""

    def __init__(
        self,
        provider: ACASandboxProvider,
        policy: Any,                    # SimpleNamespace wrapper around PolicyDocument
        agent_id: str,
    ) -> None:
        self._provider = provider
        self._policy = policy
        self._agent_id = agent_id
        self._handle = None
        self._sandbox_group = provider._sandbox_group  # needed for egress audit

    async def __aenter__(self) -> "ResearchAgent":
        self._handle = await self._provider.create_session_async(
            self._agent_id, policy=self._policy,
        )
        LOG.info("provisioned sandbox %s for agent %s",
                 self._handle.session_id, self._agent_id)
        return self

    async def __aexit__(self, *exc: Any) -> None:
        if self._handle is not None:
            try:
                await self._provider.destroy_session_async(
                    self._agent_id, self._handle.session_id,
                )
            except Exception:  # noqa: BLE001
                LOG.exception(
                    "destroy_session_async failed; sandbox may leak — "
                    "use Azure portal or `az sandbox delete` to clean up"
                )

    # ----- per-step execution -----

    async def run_step(self, step: Step) -> StepReceipt:
        if self._handle is None:
            raise RuntimeError("agent not entered")

        started = time.monotonic()
        sid = self._handle.session_id

        # 1. Policy gate is *inside* execute_code_async; we just translate
        #    exceptions into structured receipts so the caller never has
        #    to catch.
        try:
            exec_handle = await self._provider.execute_code_async(
                self._agent_id,
                sid,
                step.code,
                context={"step_index": step.index, "intent": step.intent},
            )
        except PermissionError as exc:
            return StepReceipt(
                step_index=step.index,
                intent=step.intent,
                decision="denied-by-policy",
                reason=str(exc),
                azure_sandbox_id=sid,
                duration_seconds=time.monotonic() - started,
                stdout_excerpt="",
                stderr_excerpt="",
            )
        except Exception as exc:  # noqa: BLE001 — Azure / network errors
            return StepReceipt(
                step_index=step.index,
                intent=step.intent,
                decision="error",
                reason=f"{type(exc).__name__}: {exc}",
                azure_sandbox_id=sid,
                duration_seconds=time.monotonic() - started,
                stdout_excerpt="",
                stderr_excerpt="",
            )

        result = exec_handle.result

        # 2. Pull the Azure egress audit trail for this step. The data-plane
        #    SDK is sync today, so we hop to a worker thread to avoid blocking
        #    the event loop.
        egress = []
        try:
            decisions = await asyncio.to_thread(
                self._provider._data_client.get_egress_decisions,
                sid, self._sandbox_group,
            )
            egress = (decisions.get("decisions") or [])[-25:]
        except Exception:  # noqa: BLE001
            LOG.debug("egress decision audit unavailable", exc_info=True)

        if getattr(result, "killed", False):
            decision = "timeout"
            reason = getattr(result, "kill_reason", "exceeded timeout_seconds")
        elif any(d.get("action") == "Deny" for d in egress):
            decision = "blocked-at-egress"
            reason = "Azure egress proxy denied at least one host"
        elif result.success:
            decision = "allowed"
            reason = None
        else:
            decision = "error"
            reason = f"exit code {result.exit_code}"

        return StepReceipt(
            step_index=step.index,
            intent=step.intent,
            decision=decision,
            reason=reason,
            azure_sandbox_id=sid,
            duration_seconds=time.monotonic() - started,
            stdout_excerpt=textwrap.shorten(result.stdout or "", width=512),
            stderr_excerpt=textwrap.shorten(result.stderr or "", width=512),
            egress_decisions=egress,
        )

# ---------------------------------------------------------------------------
# 4. Entry point
# ---------------------------------------------------------------------------

async def main(ticket_path: str) -> int:
    ticket_data = json.loads(Path(ticket_path).read_text(encoding="utf-8"))
    ticket = Ticket(**ticket_data)

    here = Path(__file__).resolve().parent
    policy_path = here / "policies" / "research_agent.yaml"
    document = PolicyDocument.from_yaml(str(policy_path))
    # See Step 5.1 — sandbox-only fields are attached as a wrapper.
    policy = types.SimpleNamespace(
        name=document.name,
        version=document.version,
        rules=document.rules,
        defaults=types.SimpleNamespace(
            action=document.defaults.action,
            max_cpu=1.0,
            max_memory_mb=2048,
            timeout_seconds=90,
        ),
        network_allowlist=[
            "api.openai.com", "api.arxiv.org", "export.arxiv.org",
            "*.github.com", "pypi.org", "files.pythonhosted.org",
        ],
        tool_allowlist=["fetch_arxiv", "fetch_github_readme", "search_index"],
    )

    provider = ACASandboxProvider(
        resource_group=os.environ["AZURE_RG"],
        sandbox_group=os.environ.get("AZURE_SANDBOX_GROUP", "agents-test"),
        # Default "ubuntu" image has no python3; use a Python sandbox
        # image so execute_code's `… | python3` invocation works.
        disk=os.environ.get("AZURE_SANDBOX_DISK", "python-3.13"),
        ensure_group_location=os.environ.get("AZURE_REGION", "westus2"),
    )

    agent_id = f"research-{ticket.id}-{uuid.uuid4().hex[:6]}"
    receipts: list[StepReceipt] = []

    try:
        steps = await _plan_with_fallback(ticket, "gpt-4o-mini")
    except Exception as exc:  # noqa: BLE001
        LOG.error("planner failed: %s", exc)
        return 2

    LOG.info("planner produced %d steps for ticket %s", len(steps), ticket.id)

    async with ResearchAgent(provider, policy, agent_id) as agent:
        for step in steps:
            receipt = await agent.run_step(step)
            receipts.append(receipt)
            LOG.info(
                "step %d (%s): %s%s",
                step.index, step.intent, receipt.decision,
                f" — {receipt.reason}" if receipt.reason else "",
            )
            if receipt.decision in ("denied-by-policy", "blocked-at-egress", "timeout"):
                LOG.warning("halting plan after step %d", step.index)
                break

    out = f"receipts-{ticket.id}.json"
    # newline="\n" forces LF on Windows so the receipts file matches
    # the repo's .gitattributes (`* text=auto eol=lf`) and does not
    # trigger CRLF-conversion warnings on `git add`.
    with open(out, "w", encoding="utf-8", newline="\n") as f:
        json.dump(
            {
                "agent_id": agent_id,
                "ticket": ticket.__dict__,
                "policy_name": policy.name,
                "policy_version": policy.version,
                "receipts": [r.__dict__ for r in receipts],
            },
            f, indent=2, default=str,
        )
    LOG.info("wrote %s (%d receipts)", out, len(receipts))
    return 0 if all(r.decision == "allowed" for r in receipts) else 1


if __name__ == "__main__":
    sys.exit(asyncio.run(main(sys.argv[1])))
