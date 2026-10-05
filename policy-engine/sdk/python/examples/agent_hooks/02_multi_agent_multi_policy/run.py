# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""Quickstart 02 — multiple agents, multiple policies.

The same one-line integration (`use_agent_hooks(acs)`) governs an entire crew,
no matter how many agents it has. Here a two-agent crew (a researcher hands off
to a writer) runs under a manifest that declares three policies across three
intervention points:

* ``input_firewall``   — blocks prompt-injection in the incoming request,
* ``prompt_firewall``  — blocks credential exfiltration in outgoing prompts, and
* ``output_guard``     — blocks PII (SSN) leaking in a final answer.

Because the interceptor is installed as the crew-wide governor, every agent's
lifecycle is evaluated against every applicable policy. This script runs a
benign workflow that all three policies allow, and prints the governed result.

Run it::

    python examples/agent_hooks/02_multi_agent_multi_policy/run.py
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


def main() -> int:
    print(f"Quickstart 02: multiple agents, multiple policies (model: {_MODEL})")
    if not ensure_model_available():
        return 2
    acs = AcsInterceptor.from_manifest(HERE / "manifest.yaml")

    researcher = Agent(
        role="Researcher",
        goal="Gather accurate, policy-compliant facts about the topic.",
        backstory="A diligent analyst who never fabricates sources.",
        llm=build_llm(),
        verbose=False,
    )
    writer = Agent(
        role="Writer",
        goal="Turn the research into a short, safe summary.",
        backstory="A concise editor who respects organizational policy.",
        llm=build_llm(),
        verbose=False,
    )

    research_task = Task(
        description="Research what a public library does for its community.",
        expected_output="A few factual bullet points.",
        agent=researcher,
    )
    write_task = Task(
        description="Write a one-sentence public summary from the research.",
        expected_output="One safe sentence.",
        agent=writer,
    )

    crew = Crew(
        agents=[researcher, writer],
        tasks=[research_task, write_task],
        process=Process.sequential,
        verbose=False,
    )

    # One line injects ACS across both agents for the whole run.
    result = None
    try:
        with use_agent_hooks(acs):
            result = crew.kickoff()
    except Exception as error:
        raise AssertionError(
            f"a policy blocked the benign workflow: {type(error).__name__}: {error}"
        ) from error

    # Assert governance stayed out of the way of a legitimate, benign workflow.
    assert result is not None, "the crew returned no result"
    print("\nCrew completed under 3 policies across 2 agents")
    print(str(result))
    print("\nOK: every agent lifecycle was governed; the benign workflow passed.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
