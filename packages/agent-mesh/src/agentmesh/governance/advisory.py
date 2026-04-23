# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""
Optional advisory checks for defense-in-depth.

Advisory checks are intentionally separated from deterministic policy
enforcement. They run only after deterministic policy evaluation allows an
action, and they can only add a flag or block.
"""

from __future__ import annotations

import logging
import time
from collections.abc import Callable, Mapping, Sequence
from typing import TYPE_CHECKING, Any, Literal, Protocol, runtime_checkable
from urllib.parse import urlparse

import httpx
from pydantic import BaseModel, Field

if TYPE_CHECKING:
    from .policy import PolicyDecision

logger = logging.getLogger(__name__)

AdvisoryAction = Literal["allow", "flag_for_review", "block"]
AdvisoryEffect = Literal["flag_for_review", "block"]
AdvisoryOnError = Literal["allow"]
AdvisoryFunction = Callable[
    [str, dict[str, Any], "PolicyDecision"],
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
        deterministic_decision: PolicyDecision,
    ) -> AdvisoryResult | Mapping[str, Any] | str | bool | None:
        """Evaluate an action that has already passed deterministic policy."""


class FunctionAdvisoryCheck:
    """Wrap a custom function or local model behind the advisory interface."""

    def __init__(self, func: AdvisoryFunction, name: str = "custom") -> None:
        """Create an advisory check from a Python callable."""
        self.func = func
        self.name = name

    def evaluate(
        self,
        agent_did: str,
        context: dict[str, Any],
        deterministic_decision: PolicyDecision,
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
        allowed_hosts: Sequence[str] | None = None,
        max_retries: int = 0,
        retry_backoff: float = 0.1,
    ) -> None:
        """Create an HTTPS classifier endpoint advisory check.

        Args:
            url: HTTPS endpoint that returns an advisory decision.
            name: Classifier label used in metadata.
            headers: Optional request headers, such as authorization.
            timeout: Per-request timeout in seconds.
            allowed_hosts: Optional exact host allowlist for endpoint URLs.
            max_retries: Number of retries for transient HTTP failures.
            retry_backoff: Initial exponential backoff delay in seconds.
        """
        parsed = urlparse(url)
        if parsed.scheme != "https":
            raise ValueError("Advisory endpoint must use HTTPS for secure communication.")
        if not parsed.hostname:
            raise ValueError("Advisory endpoint URL must include a hostname.")

        trusted_hosts = set(allowed_hosts or ())
        if trusted_hosts and parsed.hostname not in trusted_hosts:
            raise ValueError(f"Advisory endpoint host '{parsed.hostname}' is not allowed.")
        if timeout <= 0:
            raise ValueError("Advisory endpoint timeout must be greater than zero.")
        if max_retries < 0:
            raise ValueError("Advisory endpoint max_retries must be zero or greater.")
        if retry_backoff < 0:
            raise ValueError("Advisory endpoint retry_backoff must be zero or greater.")

        self.url = url
        self.name = name
        self.headers = dict(headers or {})
        self.timeout = timeout
        self.allowed_hosts = trusted_hosts
        self.max_retries = max_retries
        self.retry_backoff = retry_backoff

    def evaluate(
        self,
        agent_did: str,
        context: dict[str, Any],
        deterministic_decision: PolicyDecision,
    ) -> AdvisoryResult:
        """POST the advisory payload to the endpoint and normalize the response."""
        if hasattr(deterministic_decision, "model_dump"):
            decision_payload = deterministic_decision.model_dump(mode="json")
        else:
            decision_payload = deterministic_decision

        payload = {
            "agent_did": agent_did,
            "context": context,
            "deterministic_decision": decision_payload,
        }

        attempt = 0
        while True:
            try:
                response = httpx.post(
                    self.url,
                    json=payload,
                    headers=self.headers,
                    timeout=self.timeout,
                )
                response.raise_for_status()
                return normalize_advisory_result(
                    response.json(),
                    default_classifier=self.name,
                )
            except httpx.HTTPError:
                if attempt >= self.max_retries:
                    raise
                if self.retry_backoff:
                    time.sleep(min(self.retry_backoff * (2**attempt), 1.0))
                attempt += 1


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

    try:
        data = dict(result)
    except (TypeError, ValueError):
        logger.warning("Malformed advisory result %r; defaulting to allow", result)
        return AdvisoryResult(
            action="allow",
            reason="Malformed advisory result; deterministic allow preserved",
            classifier=default_classifier,
            metadata={"malformed_result": True},
        )

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

    try:
        return AdvisoryResult(
            action=_normalize_action(raw_action),
            reason=data.get("reason"),
            classifier=data.get("classifier") or default_classifier,
            confidence=data.get("confidence"),
            metadata=metadata,
        )
    except Exception as exc:
        logger.warning("Invalid advisory result %r; defaulting to allow", result)
        return AdvisoryResult(
            action="allow",
            reason="Invalid advisory result; deterministic allow preserved",
            classifier=default_classifier,
            metadata={
                "malformed_result": True,
                "error_type": type(exc).__name__,
            },
        )


def _normalize_action(action: Any) -> AdvisoryAction:
    """Normalize classifier action labels, defaulting unknown labels to allow."""
    if action is None:
        return "allow"

    value = str(action).strip().lower().replace("-", "_")
    if value in {"allow", "allowed", "pass", "passed", "safe", "ok", "none"}:
        return "allow"
    if value in {"flag", "flagged", "flag_for_review", "warn", "warning", "review"}:
        return "flag_for_review"
    if value in {"block", "blocked", "deny", "denied", "unsafe"}:
        return "block"

    logger.warning("Unsupported advisory action %r; defaulting to allow", action)
    return "allow"
