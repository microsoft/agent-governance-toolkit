from __future__ import annotations

from collections.abc import Mapping
from typing import TypeVar

from .._orchestration import AgentControl
from .._types import EnforcementMode, JsonValue
from ._generic import guard_agent_method
from ._shared import _first_callable, _resolve_control_and_target

AgentT = TypeVar("AgentT")


def guard_autogen_agent(
    control_or_agent: AgentControl | AgentT,
    agent: AgentT | None = None,
    *,
    control: AgentControl | None = None,
    method_name: str | None = None,
    snapshot: Mapping[str, JsonValue] | None = None,
    mode: EnforcementMode | str = EnforcementMode.ENFORCE,
) -> AgentT:
    """Guard an AutoGen-style agent method without importing AutoGen."""

    resolved_control, resolved_agent = _resolve_control_and_target(
        control_or_agent,
        agent,
        control=control,
        target_name="AutoGen-style agent",
        adapter_name="guard_autogen_agent",
    )
    candidates = ("a_run", "arun", "run", "a_initiate_chat", "initiate_chat", "achat")
    selected = method_name or _first_callable(resolved_agent, candidates, "AutoGen-style agent")
    return guard_agent_method(
        resolved_control,
        resolved_agent,
        selected,
        input_kwarg="input",
        snapshot=snapshot,
        mode=mode,
        blocked_methods=candidates,
    )


def guard_crewai_crew(
    control_or_crew: AgentControl | AgentT,
    crew: AgentT | None = None,
    *,
    control: AgentControl | None = None,
    method_name: str | None = None,
    snapshot: Mapping[str, JsonValue] | None = None,
    mode: EnforcementMode | str = EnforcementMode.ENFORCE,
) -> AgentT:
    """Guard a CrewAI-style crew/agent kickoff method without importing CrewAI.

    CrewAI 1.6 prompts for first-run trace viewing unless it detects a test
    environment. Set ``CREWAI_TESTING=true`` before importing CrewAI in
    headless or CI consumers. Set ``OTEL_SDK_DISABLED=true`` or
    ``CREWAI_DISABLE_TELEMETRY=true`` separately when OpenTelemetry export
    should also be disabled. ACS does not mutate process environment.
    """

    resolved_control, resolved_crew = _resolve_control_and_target(
        control_or_crew,
        crew,
        control=control,
        target_name="CrewAI-style crew",
        adapter_name="guard_crewai_crew",
    )
    candidates = ("akickoff", "kickoff", "a_kickoff")
    selected = method_name or _first_callable(resolved_crew, candidates, "CrewAI-style crew")
    return guard_agent_method(
        resolved_control,
        resolved_crew,
        selected,
        input_kwarg="inputs",
        snapshot=snapshot,
        mode=mode,
        blocked_methods=candidates,
    )
