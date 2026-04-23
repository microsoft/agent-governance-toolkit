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
import math
import re
import time
from collections.abc import Callable, Mapping, Sequence
from typing import TYPE_CHECKING, Any, Literal, Protocol, runtime_checkable
from urllib.parse import urlparse

import httpx
from pydantic import BaseModel, Field

if TYPE_CHECKING:
    from .policy import PolicyDecision

logger = logging.getLogger(__name__)

MAX_ENDPOINT_TIMEOUT_SECONDS = 5.0
MAX_ENDPOINT_RETRIES = 2
MAX_ENDPOINT_TOTAL_SECONDS = 6.0
MAX_METADATA_DEPTH = 4
MAX_METADATA_ITEMS = 50
MAX_METADATA_KEY_LENGTH = 128
MAX_METADATA_STRING_LENGTH = 4096
_METADATA_SKIP = object()
_METADATA_KEY_PATTERN = re.compile(r"[^A-Za-z0-9_.-]")

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
        total_timeout: float = MAX_ENDPOINT_TOTAL_SECONDS,
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
            total_timeout: Total timeout budget for the advisory check.
            allowed_hosts: Optional exact host allowlist for endpoint URLs.
            max_retries: Number of retries for transient HTTP failures.
            retry_backoff: Initial exponential backoff delay in seconds.
        """
        parsed = urlparse(url)
        if parsed.scheme != "https":
            raise ValueError("Advisory endpoint must use HTTPS for secure communication.")
        if not parsed.hostname:
            raise ValueError("Advisory endpoint URL must include a hostname.")

        endpoint_host = parsed.hostname.lower()
        trusted_hosts = {host.lower() for host in allowed_hosts or ()}
        if any("*" in host for host in trusted_hosts):
            raise ValueError("Wildcard advisory endpoint hosts are not supported.")
        if trusted_hosts and endpoint_host not in trusted_hosts:
            raise ValueError(f"Advisory endpoint host '{parsed.hostname}' is not allowed.")
        if timeout <= 0:
            raise ValueError("Advisory endpoint timeout must be greater than zero.")
        if timeout > MAX_ENDPOINT_TIMEOUT_SECONDS:
            raise ValueError(
                f"Advisory endpoint timeout must be <= {MAX_ENDPOINT_TIMEOUT_SECONDS:g} seconds."
            )
        if total_timeout <= 0:
            raise ValueError("Advisory endpoint total_timeout must be greater than zero.")
        if total_timeout > MAX_ENDPOINT_TOTAL_SECONDS:
            raise ValueError(
                "Advisory endpoint total_timeout must be <= "
                f"{MAX_ENDPOINT_TOTAL_SECONDS:g} seconds."
            )
        if max_retries < 0:
            raise ValueError("Advisory endpoint max_retries must be zero or greater.")
        if max_retries > MAX_ENDPOINT_RETRIES:
            raise ValueError(
                f"Advisory endpoint max_retries must be <= {MAX_ENDPOINT_RETRIES}."
            )
        if retry_backoff < 0:
            raise ValueError("Advisory endpoint retry_backoff must be zero or greater.")

        self.url = url
        self.name = name
        self.headers = dict(headers or {})
        self.timeout = timeout
        self.total_timeout = total_timeout
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

        deadline = time.monotonic() + self.total_timeout
        attempt = 0
        while True:
            try:
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    raise httpx.TimeoutException(
                        "Advisory check exceeded the total timeout budget."
                    )
                response = httpx.post(
                    self.url,
                    json=payload,
                    headers=self.headers,
                    timeout=min(self.timeout, remaining),
                )
                response.raise_for_status()
                return normalize_advisory_result(
                    response.json(),
                    default_classifier=self.name,
                )
            except httpx.HTTPError:
                if attempt >= self.max_retries:
                    raise
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    raise
                if self.retry_backoff:
                    time.sleep(min(self.retry_backoff * (2**attempt), 1.0, remaining))
                attempt += 1


def normalize_advisory_result(
    result: AdvisoryResult | Mapping[str, Any] | str | bool | None,
    *,
    default_classifier: str | None = None,
) -> AdvisoryResult:
    """Normalize endpoint, model, and function outputs into ``AdvisoryResult``."""
    if isinstance(result, AdvisoryResult):
        updates: dict[str, Any] = {"metadata": _sanitize_metadata(result.metadata)}
        if result.classifier is None and default_classifier is not None:
            updates["classifier"] = default_classifier
        return result.model_copy(update=updates)

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
        logger.error("Malformed advisory result %r; defaulting to allow", result)
        return AdvisoryResult(
            action="allow",
            reason="Malformed advisory result; deterministic allow preserved",
            classifier=default_classifier,
            metadata={"malformed_result": True},
        )

    raw_action = data.get("action") or data.get("decision") or data.get("verdict")
    metadata = _sanitize_metadata(data.get("metadata"))
    known = {
        "action",
        "decision",
        "verdict",
        "reason",
        "classifier",
        "confidence",
        "metadata",
    }
    metadata.update(
        _sanitize_metadata({key: value for key, value in data.items() if key not in known})
    )

    try:
        return AdvisoryResult(
            action=_normalize_action(raw_action),
            reason=data.get("reason"),
            classifier=data.get("classifier") or default_classifier,
            confidence=data.get("confidence"),
            metadata=metadata,
        )
    except Exception as exc:
        logger.error("Invalid advisory result %r; defaulting to allow", result)
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

    logger.error("Unsupported advisory action %r; defaulting to allow", action)
    return "allow"


def _sanitize_metadata(raw_metadata: Any, *, depth: int = 0) -> dict[str, Any]:
    """Return JSON-safe advisory metadata with sanitized keys and bounded values."""
    if raw_metadata is None:
        return {}
    if not isinstance(raw_metadata, Mapping):
        logger.error("Malformed advisory metadata %r; dropping metadata", raw_metadata)
        return {"malformed_metadata": True}

    sanitized: dict[str, Any] = {}
    for key, value in raw_metadata.items():
        clean_key = _sanitize_metadata_key(key)
        if clean_key is None:
            continue
        clean_value = _sanitize_metadata_value(value, depth=depth)
        if clean_value is not _METADATA_SKIP:
            sanitized[clean_key] = clean_value
    return sanitized


def _sanitize_metadata_key(key: Any) -> str | None:
    """Normalize advisory metadata keys into bounded, safe identifier strings."""
    key_text = _METADATA_KEY_PATTERN.sub("_", str(key))[:MAX_METADATA_KEY_LENGTH]
    key_text = key_text.strip(".-")
    if not key_text:
        return None
    if key_text.startswith("__"):
        key_text = f"metadata{key_text}"
    key_text = key_text.strip("_")
    if not key_text:
        return None
    return key_text


def _sanitize_metadata_value(value: Any, *, depth: int) -> Any:
    """Normalize advisory metadata values into bounded JSON-safe structures."""
    if value is None or isinstance(value, bool):
        return value
    if isinstance(value, int):
        return value
    if isinstance(value, float):
        return value if math.isfinite(value) else _METADATA_SKIP
    if isinstance(value, str):
        return value[:MAX_METADATA_STRING_LENGTH]
    if depth >= MAX_METADATA_DEPTH:
        return _METADATA_SKIP
    if isinstance(value, Mapping):
        return _sanitize_metadata(value, depth=depth + 1)
    if isinstance(value, Sequence) and not isinstance(value, (bytes, bytearray, str)):
        sanitized_items = []
        for item in value[:MAX_METADATA_ITEMS]:
            clean_item = _sanitize_metadata_value(item, depth=depth + 1)
            if clean_item is not _METADATA_SKIP:
                sanitized_items.append(clean_item)
        return sanitized_items
    return _METADATA_SKIP
