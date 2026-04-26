# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""Graceful degradation helpers for optional toolkit dependencies.

Provides no-op fallbacks so consumers can optionally depend on the
toolkit without try/except import boilerplate.

Usage::

    from agent_os.compat import PolicyEvaluator, get_evaluator

    # Real class if agent-os-kernel installed, no-op otherwise.
"""

from __future__ import annotations

import logging
from typing import Any

logger = logging.getLogger(__name__)

try:
    from agent_os.policies.evaluator import PolicyEvaluator as _RealEvaluator

    TOOLKIT_AVAILABLE = True
except ImportError:
    TOOLKIT_AVAILABLE = False
    _RealEvaluator = None  # type: ignore[assignment, misc]


class _AllowDecision:
    allowed = True
    reason = "no-op"
    matched_rule = None


class NoOpPolicyEvaluator:
    """No-op policy evaluator — allows all actions."""

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        logger.debug("NoOpPolicyEvaluator: toolkit not installed, all actions allowed")

    def evaluate(self, *args: Any, **kwargs: Any) -> _AllowDecision:
        return _AllowDecision()

    def load_policies(self, *args: Any, **kwargs: Any) -> None:
        pass

    def add_backend(self, *args: Any, **kwargs: Any) -> None:
        pass


class NoOpGovernanceMiddleware:
    """No-op governance middleware — passes all calls through."""

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        logger.debug("NoOpGovernanceMiddleware: toolkit not installed")

    def __call__(self, func: Any) -> Any:
        return func

    def wrap(self, func: Any) -> Any:
        return func


def get_evaluator(**kwargs: Any) -> Any:
    """Get a PolicyEvaluator if available, otherwise a no-op."""
    if TOOLKIT_AVAILABLE and _RealEvaluator is not None:
        return _RealEvaluator(**kwargs)
    return NoOpPolicyEvaluator(**kwargs)


PolicyEvaluator = _RealEvaluator if TOOLKIT_AVAILABLE else NoOpPolicyEvaluator  # type: ignore[assignment]
GovernanceMiddleware = NoOpGovernanceMiddleware
