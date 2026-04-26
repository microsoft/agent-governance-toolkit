# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""
View decorators for AgentMesh trust verification in Django.
============================================================

``@trust_required(min_score=...)`` — override the global threshold for a view.
``@trust_exempt`` — skip trust verification entirely for a view.

Both decorators work with function-based views and class-based views
(when applied to the ``dispatch`` method or via ``method_decorator``).
"""

from __future__ import annotations

from functools import wraps
from typing import Any, Callable, Optional

from .middleware import _TRUST_EXEMPT_ATTR, _TRUST_REQUIRED_ATTR


def trust_required(min_score: Optional[int] = None) -> Callable[..., Any]:
    """Decorator that sets a per-view minimum trust score.

    When ``min_score`` is ``None`` the global
    ``AGENTMESH_MIN_TRUST_SCORE`` setting is used.

    Works with both function-based and class-based views::

        @trust_required(min_score=800)
        def sensitive_view(request):
            ...

        from django.utils.decorators import method_decorator

        @method_decorator(trust_required(min_score=800), name="dispatch")
        class SensitiveView(View):
            ...
    """

    def decorator(view_func: Callable[..., Any]) -> Callable[..., Any]:
        @wraps(view_func)
        def wrapper(*args: Any, **kwargs: Any) -> Any:
            return view_func(*args, **kwargs)

        if min_score is not None:
            setattr(wrapper, _TRUST_REQUIRED_ATTR, min_score)
        return wrapper

    return decorator


def trust_exempt(view_func: Callable[..., Any]) -> Callable[..., Any]:
    """Decorator that exempts a view from trust verification.

    Works with both function-based and class-based views::

        @trust_exempt
        def public_health_check(request):
            ...
    """

    @wraps(view_func)
    def wrapper(*args: Any, **kwargs: Any) -> Any:
        return view_func(*args, **kwargs)

    setattr(wrapper, _TRUST_EXEMPT_ATTR, True)
    return wrapper
