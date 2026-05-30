# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""Snapshot builder for scenario tests.

Implements the per-intervention-point shape from
``policy-engine/spec/agt/AGT-SNAPSHOT-1.0.md`` §1 (envelope) and §2.x.
Used by the scenario tests to build deterministic policy inputs.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Iterable


def _envelope(
    *,
    agent_id: str,
    session_id: str = "session-1",
    intervention_point: str,
    tool_call_count: int = 0,
    token_count: int = 0,
    elapsed_seconds: float = 0.0,
    cost_usd: float = 0.0,
    tenant_id: str | None = None,
) -> dict[str, Any]:
    envelope: dict[str, Any] = {
        "agent": {"id": agent_id, "version": "1.0.0", "name": agent_id},
        "session": {
            "id": session_id,
            "started_at": datetime(2026, 5, 30, tzinfo=timezone.utc).isoformat(),
        },
        "intervention_point": intervention_point,
        "timestamp": datetime(2026, 5, 30, tzinfo=timezone.utc).isoformat(),
        "budgets": {
            "tool_call_count": tool_call_count,
            "token_count": token_count,
            "elapsed_seconds": elapsed_seconds,
            "cost_usd": cost_usd,
        },
    }
    if tenant_id:
        envelope["tenant"] = {"id": tenant_id, "name": tenant_id}
    return envelope


def input_snapshot(
    *,
    agent_id: str,
    body: str | dict[str, Any],
    source: str = "user",
    headers: dict[str, str] | None = None,
    source_labels: Iterable[str] = (),
    **envelope_kwargs: Any,
) -> dict[str, Any]:
    return {
        "envelope": _envelope(agent_id=agent_id, intervention_point="input", **envelope_kwargs),
        "input": {
            "body": body,
            "source": source,
            "headers": dict(headers or {}),
            "ifc": {"source_labels": list(source_labels)},
        },
    }


def pre_model_call_snapshot(
    *,
    agent_id: str,
    model_name: str,
    messages: list[dict[str, Any]],
    tools: list[dict[str, Any]] | None = None,
    request_id: str = "req-1",
    **envelope_kwargs: Any,
) -> dict[str, Any]:
    return {
        "envelope": _envelope(
            agent_id=agent_id, intervention_point="pre_model_call", **envelope_kwargs
        ),
        "model": {"name": model_name, "vendor": "test", "params": {}},
        "messages": messages,
        "tools": tools or [],
        "request_id": request_id,
    }


def post_model_call_snapshot(
    *,
    agent_id: str,
    model_name: str,
    response: dict[str, Any],
    usage: dict[str, int] | None = None,
    request_id: str = "req-1",
    **envelope_kwargs: Any,
) -> dict[str, Any]:
    return {
        "envelope": _envelope(
            agent_id=agent_id, intervention_point="post_model_call", **envelope_kwargs
        ),
        "model": {"name": model_name, "vendor": "test"},
        "request_id": request_id,
        "response": response,
        "usage": usage or {"prompt_tokens": 0, "completion_tokens": 0},
    }


def pre_tool_call_snapshot(
    *,
    agent_id: str,
    tool_name: str,
    args: dict[str, Any],
    call_id: str = "call-1",
    content_hash: str | None = None,
    **envelope_kwargs: Any,
) -> dict[str, Any]:
    tool_call: dict[str, Any] = {"name": tool_name, "args": args, "id": call_id}
    if content_hash is not None:
        tool_call["content_hash"] = content_hash
    return {
        "envelope": _envelope(
            agent_id=agent_id, intervention_point="pre_tool_call", **envelope_kwargs
        ),
        "tool_call": tool_call,
    }


def post_tool_call_snapshot(
    *,
    agent_id: str,
    tool_name: str,
    args: dict[str, Any],
    result: Any,
    error: Any = None,
    duration_ms: float = 0.0,
    call_id: str = "call-1",
    **envelope_kwargs: Any,
) -> dict[str, Any]:
    return {
        "envelope": _envelope(
            agent_id=agent_id, intervention_point="post_tool_call", **envelope_kwargs
        ),
        "tool_call": {"name": tool_name, "args": args, "id": call_id},
        "tool_result": {"value": result, "error": error, "duration_ms": duration_ms},
    }


def output_snapshot(
    *,
    agent_id: str,
    content: str | dict[str, Any],
    message_chain: list[dict[str, Any]] | None = None,
    result_labels: Iterable[str] = (),
    **envelope_kwargs: Any,
) -> dict[str, Any]:
    return {
        "envelope": _envelope(agent_id=agent_id, intervention_point="output", **envelope_kwargs),
        "response": {
            "content": content,
            "ifc": {"result_labels": list(result_labels)},
        },
        "message_chain": message_chain or [],
    }
