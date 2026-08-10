# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""Policy/tool-schema helpers and shared not-exercised handling."""

from __future__ import annotations

import asyncio
from dataclasses import dataclass
from fnmatch import fnmatch
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

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
    policy ``config`` to the intervention-point snapshot. Each rule declares a
    ``kind`` (defaulting to ``tool_name``) that selects the matcher below.
    Fails closed: an unknown rule kind or an unmatched tool is denied.
    """

    def evaluate(self, invocation: dict[str, Any]) -> dict[str, Any]:
        rule = invocation["adapter_config"]["config"]["rule"]
        snapshot = invocation["input"]["snapshot"]
        kind = rule.get("kind", "tool_name")
        matcher = getattr(self, f"_eval_{kind}", None)
        if matcher is None:
            return _deny(f"Unknown ACS rule kind {kind!r}.")
        return matcher(rule, snapshot)

    def _eval_tool_name(
        self, rule: dict[str, Any], snapshot: dict[str, Any]
    ) -> dict[str, Any]:
        tool_name = snapshot["tool_call"]["name"]
        if tool_name == rule["tool"]:
            return {
                "decision": rule["decision"],
                "reason": rule["reason"],
                "message": rule.get("message", ""),
            }
        return _deny(f"No ACS rule matches tool {tool_name!r}.")

    def _eval_arg_allowlist(
        self, rule: dict[str, Any], snapshot: dict[str, Any]
    ) -> dict[str, Any]:
        call = snapshot["tool_call"]
        if call["name"] != rule["tool"]:
            return _deny(f"No ACS rule matches tool {call['name']!r}.")
        value = call.get("args", {}).get(rule["arg"])
        host = urlparse(value).hostname if isinstance(value, str) else None
        allowed = host is not None and any(
            fnmatch(host, pattern) for pattern in rule["allow_hosts"]
        )
        return _branch(rule, "allow" if allowed else "deny")


def _deny(message: str) -> dict[str, Any]:
    return {"decision": "deny", "reason": "default_deny", "message": message}


def _branch(rule: dict[str, Any], decision: str) -> dict[str, Any]:
    branch = rule[decision]
    return {
        "decision": decision,
        "reason": branch["reason"],
        "message": branch.get("message", ""),
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
    snapshot: dict[str, Any] = {
        "tool_call": {"id": f"{session_id}-1", "name": tool_name, "args": arguments},
        "actor": {"id": agent_id},
    }
    result = asyncio.run(
        control.evaluate_intervention_point(
            InterventionPoint.PRE_TOOL_CALL, snapshot
        )
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
