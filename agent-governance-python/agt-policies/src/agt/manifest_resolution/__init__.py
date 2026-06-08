# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""AGT manifest resolution layer.

Implements ``policy-engine/spec/agt/AGT-RESOLUTION-1.0.md``. The host
calls :func:`resolve_manifest` with a workspace ``root`` and an
``action_path``; the function discovers governance files, filters by
scope, merges them, and emits a flat ACS manifest with
``extends: []`` ready to feed the policy engine.

A resolution failure (path traversal, cycle, invalid governance file,
non-mergeable section) raises :class:`ResolutionError`, whose
``reason()`` matches one of the reserved ``runtime_error:resolution_*``
strings defined in ``SPECIFICATION.md`` §16.
"""

from .build import resolve_manifest
from .discover import discover_policies
from .errors import ResolutionError, ResolutionReason
from .merge import merge_documents
from .scope import filter_by_scope

__all__ = [
    "ResolutionError",
    "ResolutionReason",
    "discover_policies",
    "filter_by_scope",
    "merge_documents",
    "resolve_manifest",
]
