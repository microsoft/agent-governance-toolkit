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
"""

from __future__ import annotations

import logging
import time
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Callable, Optional

logger = logging.getLogger(__name__)


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


class CallbackAdvisory(AdvisoryCheck):
    """Advisory check backed by a custom callback function.

    Args:
        callback: Function receiving context dict, returning AdvisoryDecision.
        name: Classifier name for audit trail. Default: "callback".
        on_error: Action when callback fails. Default: "allow" (fail-open).
    """

    def __init__(
        self,
        callback: Callable[[dict], AdvisoryDecision],
        name: str = "callback",
        on_error: str = "allow",
    ):
        self._callback = callback
        self._name = name
        self._on_error = on_error

    def check(self, context: dict) -> AdvisoryDecision:
        try:
            decision = self._callback(context)
            decision.classifier = self._name
            return decision
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
