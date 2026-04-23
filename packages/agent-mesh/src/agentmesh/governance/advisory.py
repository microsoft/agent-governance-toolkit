# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""
Optional advisory checks for defense-in-depth.

Advisory checks are intentionally separated from deterministic policy
enforcement. They run only after deterministic policy evaluation allows an
action, and they can only add a flag or block.
"""

from __future__ import annotations

from collections.abc import Callable, Mapping
from typing import Any, Literal, Protocol, runtime_checkable

import httpx
from pydantic import BaseModel, Field

AdvisoryAction = Literal["allow", "flag_for_review", "block"]
AdvisoryEffect = Literal["flag_for_review", "block"]
AdvisoryOnError = Literal["allow"]
AdvisoryFunction = Callable[
    [str, dict[str, Any], Any],
    "AdvisoryResult | Mapping[str, Any] | str | bool | None",
]


class AdvisoryConfig(BaseModel):
    """Configuration for optional, non-deterministic advisory checks."""

    enabled: bool = False
    classifier: str | None = None
    actions: set[AdvisoryEffect] = Field(
        default_factory=lambda: {"flag_for_review", "block"}
    )
    on_error: AdvisoryOnError = "allow"


class AdvisoryResult(BaseModel):
    """Decision returned by an advisory classifier or reviewer."""

    action: AdvisoryAction = "allow"
    reason: str | None = None
    classifier: str | None = None
    confidence: float | None = None
    metadata: dict[str, Any] = Field(default_factory=dict)


@runtime_checkable
class AdvisoryCheck(Protocol):
    """Interface implemented by classifier endpoints, local models, or callables."""

    name: str

    def evaluate(
        self,
        agent_did: str,
        context: dict[str, Any],
        deterministic_decision: Any,
    ) -> AdvisoryResult | Mapping[str, Any] | str | bool | None:
        """Evaluate an action that has already passed deterministic policy."""


class FunctionAdvisoryCheck:
    """Wrap a custom function or local model behind the advisory interface."""

    def __init__(self, func: AdvisoryFunction, name: str = "custom") -> None:
        self.func = func
        self.name = name

    def evaluate(
        self,
        agent_did: str,
        context: dict[str, Any],
        deterministic_decision: Any,
    ) -> AdvisoryResult | Mapping[str, Any] | str | bool | None:
        """Run the configured advisory function."""
        return self.func(agent_did, context, deterministic_decision)


class EndpointAdvisoryCheck:
    """Call a classifier endpoint that returns an advisory decision."""

    def __init__(
        self,
        url: str,
        *,
        name: str = "classifier-endpoint",
        headers: Mapping[str, str] | None = None,
        timeout: float = 2.0,
    ) -> None:
        self.url = url
        self.name = name
        self.headers = dict(headers or {})
        self.timeout = timeout

    def evaluate(
        self,
        agent_did: str,
        context: dict[str, Any],
        deterministic_decision: Any,
    ) -> AdvisoryResult:
        """POST the advisory payload to the endpoint and normalize the response."""
        if hasattr(deterministic_decision, "model_dump"):
            decision_payload = deterministic_decision.model_dump(mode="json")
        else:
            decision_payload = deterministic_decision

        response = httpx.post(
            self.url,
            json={
                "agent_did": agent_did,
                "context": context,
                "deterministic_decision": decision_payload,
            },
            headers=self.headers,
            timeout=self.timeout,
        )
        response.raise_for_status()
        return normalize_advisory_result(response.json(), default_classifier=self.name)


def normalize_advisory_result(
    result: AdvisoryResult | Mapping[str, Any] | str | bool | None,
    *,
    default_classifier: str | None = None,
) -> AdvisoryResult:
    """Normalize endpoint, model, and function outputs into ``AdvisoryResult``."""
    if isinstance(result, AdvisoryResult):
        if result.classifier is None and default_classifier is not None:
            return result.model_copy(update={"classifier": default_classifier})
        return result

    if result is None:
        return AdvisoryResult(action="allow", classifier=default_classifier)

    if isinstance(result, bool):
        return AdvisoryResult(
            action="allow" if result else "block",
            classifier=default_classifier,
        )

    if isinstance(result, str):
        return AdvisoryResult(
            action=_normalize_action(result),
            classifier=default_classifier,
        )

    data = dict(result)
    raw_action = data.get("action") or data.get("decision") or data.get("verdict")
    metadata = dict(data.get("metadata") or {})
    known = {
        "action",
        "decision",
        "verdict",
        "reason",
        "classifier",
        "confidence",
        "metadata",
    }
    metadata.update({key: value for key, value in data.items() if key not in known})

    return AdvisoryResult(
        action=_normalize_action(raw_action),
        reason=data.get("reason"),
        classifier=data.get("classifier") or default_classifier,
        confidence=data.get("confidence"),
        metadata=metadata,
    )


def _normalize_action(action: Any) -> AdvisoryAction:
    if action is None:
        return "allow"

    value = str(action).strip().lower().replace("-", "_")
    if value in {"allow", "allowed", "pass", "passed", "safe", "ok", "none"}:
        return "allow"
    if value in {"flag", "flagged", "flag_for_review", "warn", "warning", "review"}:
        return "flag_for_review"
    if value in {"block", "blocked", "deny", "denied", "unsafe"}:
        return "block"

    raise ValueError(f"Unsupported advisory action: {action!r}")
