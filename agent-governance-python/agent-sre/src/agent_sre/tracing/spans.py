# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""Helper functions to create properly attributed OpenTelemetry spans.

Each helper sets the appropriate semantic attributes from
:mod:`agent_sre.tracing.conventions` so callers don't need to
remember attribute keys.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

from agent_sre.tracing.conventions import (
    AGENT_DELEGATION_FROM,
    AGENT_DELEGATION_TO,
    AGENT_DID,
    AGENT_MODEL_NAME,
    AGENT_MODEL_PROVIDER,
    AGENT_POLICY_NAME,
    AGENT_TASK,
    AGENT_TASK_NAME,
    AGENT_TOOL_NAME,
    DELEGATION,
    LLM_INFERENCE,
    POLICY_CHECK,
    TOOL_CALL,
)

if TYPE_CHECKING:
    from opentelemetry.trace import Span, Tracer


def start_agent_task_span(
    tracer: Tracer,
    task_name: str,
    agent_did: str,
    **kwargs: Any,
) -> Span:
    """Start a span representing an agent task.

    Args:
        tracer: OpenTelemetry tracer instance.
        task_name: Human-readable task name.
        agent_did: Decentralised identifier for the agent.
        **kwargs: Extra attributes to set on the span.

    Returns:
        A started ``Span`` with agent task attributes.
    """
    span = tracer.start_span(f"agent_task:{task_name}")
    span.set_attribute("agent.span.kind", AGENT_TASK)
    span.set_attribute(AGENT_TASK_NAME, task_name)
    span.set_attribute(AGENT_DID, agent_did)
    for key, value in kwargs.items():
        span.set_attribute(key, value)
    return span


def start_tool_call_span(
    tracer: Tracer,
    tool_name: str,
    agent_did: str,
    **kwargs: Any,
) -> Span:
    """Start a span representing a tool call.

    Args:
        tracer: OpenTelemetry tracer instance.
        tool_name: Name of the tool being invoked.
        agent_did: Decentralised identifier for the calling agent.
        **kwargs: Extra attributes to set on the span.

    Returns:
        A started ``Span`` with tool call attributes.
    """
    span = tracer.start_span(f"tool_call:{tool_name}")
    span.set_attribute("agent.span.kind", TOOL_CALL)
    span.set_attribute(AGENT_TOOL_NAME, tool_name)
    span.set_attribute(AGENT_DID, agent_did)
    for key, value in kwargs.items():
        span.set_attribute(key, value)
    return span


def start_llm_inference_span(
    tracer: Tracer,
    model_name: str,
    provider: str,
    **kwargs: Any,
) -> Span:
    """Start a span representing an LLM inference call.

    Args:
        tracer: OpenTelemetry tracer instance.
        model_name: Name of the model (e.g. ``gpt-4``).
        provider: Model provider (e.g. ``openai``).
        **kwargs: Extra attributes to set on the span.

    Returns:
        A started ``Span`` with LLM inference attributes.
    """
    span = tracer.start_span(f"llm_inference:{model_name}")
    span.set_attribute("agent.span.kind", LLM_INFERENCE)
    span.set_attribute(AGENT_MODEL_NAME, model_name)
    span.set_attribute(AGENT_MODEL_PROVIDER, provider)
    for key, value in kwargs.items():
        span.set_attribute(key, value)
    return span


def start_delegation_span(
    tracer: Tracer,
    from_did: str,
    to_did: str,
    **kwargs: Any,
) -> Span:
    """Start a span representing delegation between agents.

    Args:
        tracer: OpenTelemetry tracer instance.
        from_did: DID of the delegating agent.
        to_did: DID of the delegate agent.
        **kwargs: Extra attributes to set on the span.

    Returns:
        A started ``Span`` with delegation attributes.
    """
    span = tracer.start_span(f"delegation:{from_did}->{to_did}")
    span.set_attribute("agent.span.kind", DELEGATION)
    span.set_attribute(AGENT_DELEGATION_FROM, from_did)
    span.set_attribute(AGENT_DELEGATION_TO, to_did)
    for key, value in kwargs.items():
        span.set_attribute(key, value)
    return span


def start_policy_check_span(
    tracer: Tracer,
    policy_name: str,
    agent_did: str,
    **kwargs: Any,
) -> Span:
    """Start a span representing a policy check.

    Args:
        tracer: OpenTelemetry tracer instance.
        policy_name: Name of the policy being evaluated.
        agent_did: Decentralised identifier for the agent.
        **kwargs: Extra attributes to set on the span.

    Returns:
        A started ``Span`` with policy check attributes.
    """
    span = tracer.start_span(f"policy_check:{policy_name}")
    span.set_attribute("agent.span.kind", POLICY_CHECK)
    span.set_attribute(AGENT_POLICY_NAME, policy_name)
    span.set_attribute(AGENT_DID, agent_did)
    for key, value in kwargs.items():
        span.set_attribute(key, value)
    return span
