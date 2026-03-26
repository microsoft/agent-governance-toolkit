# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""
Django Trust Middleware for AgentMesh
=====================================

Django middleware and decorators for agent trust verification.
Django is an optional dependency — importing this module when Django
is not installed will not crash; individual classes raise ImportError
at instantiation time instead.
"""

from __future__ import annotations

try:
    from .decorators import trust_exempt, trust_required
    from .middleware import AgentTrustMiddleware

    __all__ = [
        "AgentTrustMiddleware",
        "trust_required",
        "trust_exempt",
    ]
except ImportError:
    # Django not installed — expose empty __all__ so the package is importable.
    __all__: list[str] = []  # type: ignore[no-redef]
