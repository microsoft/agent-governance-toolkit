# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""
Engine API capability-metadata library for AGT Studio.

This package is the reusable substrate that lets an Engine API adapter declare
each endpoint's three capability flags inline and emit them as the
``x-capability-flags`` OpenAPI extension. It is library-only: it exposes no HTTP
routes. The FastAPI reference adapter (issue #3) imports this package to wire its
routes.

See ``docs/studio/engine-api-contract.md`` section 5 (Capability Metadata) and
section 6 (Read-only Invariant) for the normative specification.

Public surface:

* :class:`CapabilityFlags` - frozen Pydantic model of the three flags that
  enforces the read-only invariant at construction time.
* :func:`capability_flags` - decorator that validates and attaches flags to an
  endpoint callable under :data:`CAPABILITY_FLAGS_ATTR` (``__capability_flags__``).
* :func:`inject_capability_extension` - injects ``x-capability-flags`` into a
  FastAPI app's generated OpenAPI document.
* :func:`derive_studio_client_allowlist` - derives the sorted read-only client
  allowlist from a generated OpenAPI document.
* :data:`CAPABILITY_EXTENSION_KEY` - the OpenAPI extension key (``x-capability-flags``).
* :data:`CAPABILITY_FLAGS_ATTR` - the endpoint attribute name (``__capability_flags__``).
* :func:`create_app` - the FastAPI reference adapter factory. Imported lazily (it requires
  FastAPI) so the capability library above stays importable without FastAPI installed.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

from agentmesh.engine_api.capabilities import (
    CAPABILITY_FLAGS_ATTR,
    CapabilityFlags,
    capability_flags,
)
from agentmesh.engine_api.openapi import (
    CAPABILITY_EXTENSION_KEY,
    derive_studio_client_allowlist,
    inject_capability_extension,
)

if TYPE_CHECKING:  # pragma: no cover - import resolved by type checkers only
    from agentmesh.engine_api.app import create_app

__all__ = [
    "CAPABILITY_EXTENSION_KEY",
    "CAPABILITY_FLAGS_ATTR",
    "CapabilityFlags",
    "capability_flags",
    "create_app",
    "derive_studio_client_allowlist",
    "inject_capability_extension",
]


def __getattr__(name: str) -> Any:
    """Lazily expose :func:`create_app` without a package-level FastAPI import (PEP 562)."""
    if name == "create_app":
        from agentmesh.engine_api.app import create_app

        return create_app
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
