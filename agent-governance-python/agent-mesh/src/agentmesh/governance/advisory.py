# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""
Optional advisory layer — classifier-based defense-in-depth.

Runs AFTER deterministic policy rules pass. Can only ADD restrictions
(block or flag) — never override a deterministic deny. The deterministic
layer remains the trust boundary; the advisory layer is defense-in-depth.

Key constraints:
- Runs only when deterministic rules return ``allow``
- Can tighten (block, flag_for_review) but never loosen
- Failures default to ``allow`` (deterministic layer is canonical)
- All decisions logged with ``deterministic: false`` in audit trail

Usage::

    from agentmesh.governance.advisory import AdvisoryCheck, CallbackAdvisory

    def my_classifier(context):
        if looks_suspicious(context):
            return AdvisoryDecision(action="block", reason="Suspicious pattern")
        return AdvisoryDecision(action="allow")

    advisory = CallbackAdvisory(my_classifier)

Async classifiers (an LLM call, an HTTP judge, a second sandbox round
trip) work the same way - pass an ``async def`` callback and call the
governed function via ``GovernedCallable.acall()`` instead of ``__call__``::

    async def my_async_classifier(context):
        verdict = await call_judge_model(context)
        return AdvisoryDecision(action="block" if verdict.unsafe else "allow")

    advisory = CallbackAdvisory(my_async_classifier)
    safe_send = govern(send_email, policy="email-policy.yaml", advisory=advisory)
    await safe_send.acall(to="user@example.com", body="Hello")
"""

from __future__ import annotations

import asyncio
import inspect
import logging
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Any, Awaitable, Callable, Optional, Union

logger = logging.getLogger(__name__)


class AdvisoryMisconfiguredError(TypeError):
    """Raised when an ``AdvisoryCheck`` is wired up incorrectly - e.g. an
    async callback handed to the sync ``check()`` path instead of
    ``acheck()``. Deliberately a distinct type from a classifier's own
    runtime failures: ``govern.py``'s ``_run_advisory()``/
    ``_run_advisory_async()`` let this propagate rather than converting it
    to fail-open the way an ordinary classifier error is, since this is a
    caller wiring bug that should surface immediately rather than being
    silently degraded to "allow" on every call.
    """


_BLOCKED_HOSTS = frozenset({
    "169.254.169.254",       # cloud metadata (AWS/Azure)
    "metadata.google.internal",
    "[fd00:ec2::254]",
})


def _validate_webhook_url(url: str) -> None:
    """Reject URLs with dangerous schemes or known SSRF targets."""
    from urllib.parse import urlparse

    parsed = urlparse(url)
    if parsed.scheme not in ("http", "https"):
        raise ValueError(
            f"Unsupported URL scheme '{parsed.scheme}': only http and https are allowed"
        )
    host = (parsed.hostname or "").lower()
    if host in _BLOCKED_HOSTS:
        raise ValueError(
            f"URL host '{host}' is blocked to prevent SSRF"
        )


@dataclass
class AdvisoryDecision:
    """Result of an advisory check.

    Attributes:
        action: One of ``"allow"``, ``"block"``, ``"flag_for_review"``.
        reason: Human-readable explanation.
        confidence: Classifier confidence (0.0–1.0). Informational only.
        classifier: Name of the classifier that made the decision.
        deterministic: Always False — marks this as non-deterministic.
    """

    action: str = "allow"  # allow, block, flag_for_review
    reason: str = ""
    confidence: float = 1.0
    classifier: str = ""
    deterministic: bool = field(default=False, init=False)


class AdvisoryCheck(ABC):
    """Abstract base class for advisory classifiers."""

    @abstractmethod
    def check(self, context: dict) -> AdvisoryDecision:
        """Evaluate context and return an advisory decision.

        Args:
            context: Policy evaluation context (same dict passed to PolicyEngine).

        Returns:
            An ``AdvisoryDecision``. Return ``action="allow"`` to pass through.
        """

    async def acheck(self, context: dict) -> AdvisoryDecision:
        """Async counterpart of ``check()``, used by ``GovernedCallable.acall()``.

        The default implementation just calls the sync ``check()`` directly
        (not via a thread) - correct for classifiers that don't do I/O
        (``PatternAdvisory``, ``CompositeAdvisory`` of those), but a
        subclass that performs real I/O (an HTTP call, an LLM call, a
        second sandbox round trip) should override this to actually await
        that work rather than block the event loop. ``CallbackAdvisory``
        and ``HttpAdvisory`` below both override it for exactly that
        reason.
        """
        return self.check(context)


class CallbackAdvisory(AdvisoryCheck):
    """Advisory check backed by a custom callback function.

    Args:
        callback: Function receiving context dict, returning an
            AdvisoryDecision - either directly, or as an
            ``Awaitable[AdvisoryDecision]`` (an ``async def`` callback, or
            a sync function returning one) for use via ``acheck()``/
            ``GovernedCallable.acall()``. A coroutine-returning callback
            passed to the sync ``check()`` raises ``AdvisoryMisconfiguredError``
            instead of silently returning the coroutine object as if it
            were a decision - and, since that's a caller wiring bug rather
            than a transient failure, ``govern()`` lets it propagate rather
            than converting it to fail-open the way an ordinary classifier
            error is (see ``AdvisoryMisconfiguredError``'s own docstring). The
            same applies to a callback returning anything else that isn't
            a real ``AdvisoryDecision``.
        name: Classifier name for audit trail. Default: "callback".
        on_error: Action when callback fails. Default: "allow" (fail-open).
    """

    def __init__(
        self,
        callback: Callable[[dict], Union[AdvisoryDecision, Awaitable[AdvisoryDecision]]],
        name: str = "callback",
        on_error: str = "allow",
    ):
        self._callback = callback
        self._name = name
        self._on_error = on_error

    def check(self, context: dict) -> AdvisoryDecision:
        try:
            decision = self._callback(context)
        except Exception as e:
            logger.warning(
                "Advisory check '%s' failed: %s — defaulting to %s",
                self._name, e, self._on_error,
            )
            return AdvisoryDecision(
                action=self._on_error,
                reason=f"Classifier error: {e}",
                confidence=0.0,
                classifier=self._name,
            )

        if inspect.isawaitable(decision):
            if inspect.iscoroutine(decision):
                decision.close()  # avoid a "coroutine was never awaited" warning
            # Deliberately outside the try/except above: this is a caller
            # wiring bug (an async callback handed to the sync check() path),
            # not a transient classifier failure - it must not be silently
            # converted to fail-open the same way an actual runtime error in
            # the callback is. AdvisoryMisconfiguredError (not a plain TypeError)
            # so govern.py's _run_advisory()/_run_advisory_async() can let
            # this one propagate instead of catching it as an ordinary
            # Exception - see that class's docstring.
            raise AdvisoryMisconfiguredError(
                f"CallbackAdvisory '{self._name}' callback returned an "
                "awaitable but check() was called synchronously - use "
                "acheck() (via GovernedCallable.acall()) for an async "
                "callback instead."
            )

        # Also outside the try/except: a callback returning something that
        # isn't an AdvisoryDecision (missing .classifier) is the same class
        # of caller bug as the awaitable case above, not a transient
        # failure - it should raise (AttributeError), not fail open.
        decision.classifier = self._name
        return decision

    async def acheck(self, context: dict) -> AdvisoryDecision:
        try:
            decision = self._callback(context)
            if inspect.isawaitable(decision):
                decision = await decision
        except Exception as e:
            logger.warning(
                "Advisory check '%s' failed: %s — defaulting to %s",
                self._name, e, self._on_error,
            )
            return AdvisoryDecision(
                action=self._on_error,
                reason=f"Classifier error: {e}",
                confidence=0.0,
                classifier=self._name,
            )

        # Outside the try/except, matching check(): a malformed callback
        # return value (missing .classifier) is a caller bug, not a
        # transient failure, and should raise rather than fail open - same
        # reasoning as check()'s own isawaitable/AdvisoryMisconfiguredError case.
        decision.classifier = self._name
        return decision


class HttpAdvisory(AdvisoryCheck):
    """Advisory check via HTTP classifier endpoint.

    Posts context as JSON, expects ``{"action": "allow|block|flag_for_review", ...}``.

    Args:
        url: Classifier endpoint URL.
        name: Classifier name. Default: "http".
        timeout_seconds: Request timeout. Default: 5.
        headers: Optional HTTP headers (auth tokens, etc.).
        on_error: Action on failure. Default: "allow".
    """

    def __init__(
        self,
        url: str,
        name: str = "http",
        timeout_seconds: float = 5,
        headers: Optional[dict[str, str]] = None,
        on_error: str = "allow",
    ):
        _validate_webhook_url(url)
        self._url = url
        self._name = name
        self._timeout = timeout_seconds
        self._headers = headers or {}
        self._on_error = on_error

    def check(self, context: dict) -> AdvisoryDecision:
        import json
        import urllib.request

        payload = json.dumps(context, default=str).encode("utf-8")
        headers = {"Content-Type": "application/json", **self._headers}

        try:
            req = urllib.request.Request(
                self._url, data=payload, headers=headers, method="POST",
            )
            with urllib.request.urlopen(req, timeout=self._timeout) as resp:
                body = json.loads(resp.read().decode("utf-8"))
                return AdvisoryDecision(
                    action=body.get("action", "allow"),
                    reason=body.get("reason", ""),
                    confidence=body.get("confidence", 1.0),
                    classifier=self._name,
                )
        except Exception as e:
            logger.warning(
                "Advisory HTTP check '%s' failed: %s — defaulting to %s",
                self._name, e, self._on_error,
            )
            return AdvisoryDecision(
                action=self._on_error,
                reason=f"HTTP classifier error: {e}",
                confidence=0.0,
                classifier=self._name,
            )

    async def acheck(self, context: dict) -> AdvisoryDecision:
        # check() uses blocking urllib.request - offloading to a thread
        # keeps the event loop free for other work during the request,
        # rather than stalling it for up to timeout_seconds. Not a true
        # async HTTP client (no new dependency added for this), but it
        # solves the actual problem: GovernedCallable.acall() awaiting
        # this must not block the loop.
        return await asyncio.to_thread(self.check, context)


class PatternAdvisory(AdvisoryCheck):
    """Advisory check using regex pattern matching.

    Scans string values in context for patterns (e.g., jailbreak phrases,
    PII patterns). Lightweight, no external dependencies.

    Args:
        patterns: List of (regex_pattern, reason) tuples.
        name: Classifier name. Default: "pattern".
        action: Action when pattern matches. Default: "flag_for_review".
    """

    def __init__(
        self,
        patterns: list[tuple[str, str]],
        name: str = "pattern",
        action: str = "flag_for_review",
    ):
        import re
        self._patterns = [(re.compile(p, re.IGNORECASE), r) for p, r in patterns]
        self._name = name
        self._action = action

    def check(self, context: dict) -> AdvisoryDecision:
        text = self._extract_text(context)
        for pattern, reason in self._patterns:
            if pattern.search(text):
                return AdvisoryDecision(
                    action=self._action,
                    reason=reason,
                    confidence=0.8,
                    classifier=self._name,
                )
        return AdvisoryDecision(action="allow", classifier=self._name)

    def _extract_text(self, obj: Any, depth: int = 0) -> str:
        """Recursively extract string values from nested dicts/lists."""
        if depth > 5:
            return ""
        if isinstance(obj, str):
            return obj
        if isinstance(obj, dict):
            return " ".join(self._extract_text(v, depth + 1) for v in obj.values())
        if isinstance(obj, (list, tuple)):
            return " ".join(self._extract_text(v, depth + 1) for v in obj)
        return str(obj) if obj is not None else ""


class CompositeAdvisory(AdvisoryCheck):
    """Chains multiple advisory checks. First non-allow result wins.

    Args:
        checks: List of AdvisoryCheck instances to evaluate in order.
    """

    def __init__(self, checks: list[AdvisoryCheck]):
        self._checks = checks

    def check(self, context: dict) -> AdvisoryDecision:
        for checker in self._checks:
            decision = checker.check(context)
            if decision.action != "allow":
                return decision
        return AdvisoryDecision(action="allow", classifier="composite")

    async def acheck(self, context: dict) -> AdvisoryDecision:
        # Uses each sub-check's own acheck() (not check()), so an
        # async-capable check in the chain (e.g. CallbackAdvisory wrapping
        # an async classifier, or HttpAdvisory) actually gets to run
        # asynchronously instead of silently falling back to its blocking
        # sync path.
        for checker in self._checks:
            decision = await checker.acheck(context)
            if decision.action != "allow":
                return decision
        return AdvisoryDecision(action="allow", classifier="composite")
