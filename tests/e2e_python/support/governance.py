# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""Policy/tool-schema helpers and shared not-exercised handling."""

from __future__ import annotations

import asyncio
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from agent_control_specification import AgentControl, Decision, InterventionPoint

from .logging_config import logger, redact_for_log, redact_log_text, truncate_log_text
from .models import ModelReply, ScenarioResult

MANIFEST_NAME = "acs.manifest.yaml"


def tool_schema(name: str, description: str, properties: dict[str, Any]) -> dict[str, Any]:
    return {
        "type": "function",
        "function": {
            "name": name,
            "description": description,
            "parameters": {
                "type": "object",
                "properties": properties,
                "required": list(properties),
            },
        },
    }


@dataclass(frozen=True)
class PolicyDecision:
    """Normalized view of an ACS ``pre_tool_call`` verdict."""

    allowed: bool
    verdict: str
    reason: str | None


class _RulePolicy:
    """Host-owned ACS policy dispatcher.

    Applies the single declarative rule carried in the manifest's custom
    policy ``config`` to the tool call presented at ``pre_tool_call``. Fails
    closed: any tool that does not match the rule is denied.
    """

    def evaluate(self, invocation: dict[str, Any]) -> dict[str, Any]:
        rule = invocation["adapter_config"]["config"]["rule"]
        tool_name = invocation["input"]["snapshot"]["tool_call"]["name"]
        if tool_name == rule["tool"]:
            return {
                "decision": rule["decision"],
                "reason": rule["reason"],
                "message": rule.get("message", ""),
            }
        return {
            "decision": "deny",
            "reason": "default_deny",
            "message": f"No ACS rule matches tool {tool_name!r}.",
        }


def load_acs_runtime(policy_dir: str | Path) -> AgentControl:
    """Build a native ACS runtime for the scenario's ACS manifest.

    The scenario ships a native Agent Control Specification manifest
    (``acs.manifest.yaml``) that declares the ``pre_tool_call`` intervention
    point and a host-owned custom policy. This is the same contract a
    customer would deploy; no legacy policy language is involved.
    """
    manifest = (Path(policy_dir) / MANIFEST_NAME).read_text(encoding="utf-8")
    return AgentControl.from_native(manifest, policy_dispatcher=_RulePolicy())


def evaluate_pre_tool_call(
    control: AgentControl,
    *,
    agent_id: str,
    tool_name: str,
    arguments: dict[str, Any],
    session_id: str = "session-1",
) -> PolicyDecision:
    """Evaluate a tool call at the ACS ``pre_tool_call`` intervention point."""
    snapshot = {
        "tool_call": {"id": f"{session_id}-1", "name": tool_name, "args": arguments},
        "actor": {"id": agent_id},
    }
    result = asyncio.run(
        control.evaluate_intervention_point(InterventionPoint.PRE_TOOL_CALL, snapshot)
    )
    verdict = result.verdict
    return PolicyDecision(
        allowed=verdict.decision is Decision.ALLOW,
        verdict=verdict.decision.name.lower(),
        reason=verdict.reason,
    )


def not_exercised_result(
    scenario_id: str,
    expected: str,
    reply: ModelReply,
    model_inputs: list[str],
) -> ScenarioResult:
    logger.warning(
        "Model response did not exercise scenario %s; expected %s; got %s",
        scenario_id,
        expected,
        _describe_reply(reply),
    )
    return ScenarioResult(
        decision="not_exercised",
        executed_tools=[],
        model_inputs=model_inputs,
        participation_status="not_exercised",
    )


def _describe_reply(reply: ModelReply) -> str:
    if reply.tool_call is not None:
        return (
            f"tool_call={reply.tool_call.name} "
            f"arguments={redact_for_log(reply.tool_call.arguments)}"
        )
    content = truncate_log_text(redact_log_text(reply.content.replace("\n", " ").strip()))
    return f"content={content!r}"
