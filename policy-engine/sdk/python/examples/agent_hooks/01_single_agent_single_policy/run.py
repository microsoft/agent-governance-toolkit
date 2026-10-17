# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""Quickstart 01 — single agent, single policy.

The minimal integration: turn an ACS manifest into an interceptor with
:meth:`AcsInterceptor.from_manifest`, then wrap ``crew.kickoff()`` in crewAI's
``use_agent_hooks`` context manager. That is the entire surface a customer needs
to inject Agent Control Specification governance into an agent.

The single policy (``policy/output_guard.rego``) guards the ``output``
intervention point and blocks any final answer that leaks a Social Security
Number. This script shows both sides:

* a legitimate answer flows through untouched, and
* an answer that leaks PII is blocked, with the policy reason surfaced.

Run it::

    python examples/agent_hooks/01_single_agent_single_policy/run.py
"""

from __future__ import annotations

import os
import urllib.request
from pathlib import Path

from crewai import LLM, Agent, Crew, Process, Task
from crewai.hooks import use_agent_hooks

from agent_control_specification import AcsInterceptor

HERE = Path(__file__).resolve().parent

# The local open-weight model these quickstarts run against. Override with the
# ACS_EXAMPLE_MODEL / OLLAMA_BASE_URL environment variables.
_MODEL = os.environ.get("ACS_EXAMPLE_MODEL", "ollama/llama3.1:latest")
_OLLAMA_BASE_URL = os.environ.get("OLLAMA_BASE_URL", "http://localhost:11434")


def build_llm() -> LLM:
    """Return the local model client (Llama 3.1 via Ollama), pinned for reproducibility."""
    return LLM(model=_MODEL, base_url=_OLLAMA_BASE_URL, temperature=0)


def ensure_model_available() -> bool:
    """Return True if the local model endpoint is reachable, else print guidance."""
    if not _MODEL.startswith("ollama/"):
        return True
    try:
        with urllib.request.urlopen(f"{_OLLAMA_BASE_URL}/api/tags", timeout=3) as resp:
            if resp.status == 200:
                return True
    except OSError:
        # Endpoint unreachable (Ollama down/not installed); fall through to guidance.
        pass
    print(
        f"Local model endpoint {_OLLAMA_BASE_URL} is unreachable.\n"
        "Start Ollama and pull the model, e.g.:\n"
        "    ollama serve &\n"
        f"    ollama pull {_MODEL.split('/', 1)[1]}"
    )
    return False


def _run_once(acs: AcsInterceptor, ticket: str) -> tuple[bool, str]:
    """Summarize ``ticket`` with a one-agent crew, governed by ACS."""
    agent = Agent(
        role="Support Summarizer",
        goal="Summarize the customer's ticket clearly and safely.",
        backstory="A meticulous support analyst.",
        llm=build_llm(),
        verbose=False,
    )
    task = Task(
        description=(
            "Summarize the following support ticket in one sentence, including "
            f"the customer reference number exactly as written.\n\nTicket: {ticket}"
        ),
        expected_output="One short sentence.",
        agent=agent,
    )
    crew = Crew(agents=[agent], tasks=[task], process=Process.sequential, verbose=False)
    try:
        with use_agent_hooks(acs):
            result = crew.kickoff()
    except Exception as error:  # noqa: BLE001 - demonstrate the customer surface
        return False, str(error)
    return True, str(result)


def main() -> int:
    print(f"Quickstart 01: single agent, single policy (model: {_MODEL})")
    if not ensure_model_available():
        return 2
    acs = AcsInterceptor.from_manifest(HERE / "manifest.yaml")

    # A benign ticket: the model's real summary carries no PII, so it is allowed.
    ok, text = _run_once(
        acs, "Customer reset their router; reference number ORD-4471; issue resolved."
    )
    print(f"\n[1] Benign ticket -> completed={ok}")
    print(f"    model output: {text}")

    # A ticket whose reference is an SSN: the model echoes it, and the output
    # guard blocks the leak before it reaches the user.
    leaked, message = _run_once(
        acs, "Customer John reset router; reference number 123-45-6789; issue resolved."
    )
    print(f"\n[2] Ticket with SSN-shaped reference -> completed={leaked}")
    print(f"    governance: {message}")

    # Assert the governance behaviour this quickstart demonstrates.
    assert ok, f"the benign summary was blocked unexpectedly: {text}"
    assert not leaked, (
        "the SSN-shaped reference reached the user — the output guard never fired"
    )
    assert "blocked_pii_in_output" in message, (
        f"expected the PII output guard to fire, got: {message}"
    )
    print("\nOK: the policy allowed the safe summary and blocked the PII leak.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
