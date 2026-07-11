# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""Private one-way governance folder migration resolver.

Implements the adjacent ``AGT-RESOLUTION-1.0.md`` migration contract. The
migration command calls :func:`resolve_manifest` with a workspace ``root`` and
an ``action_path``; the function discovers governance files, filters by scope,
merges them, and emits a flat ACS manifest with ``extends: []``.

A resolution failure (path traversal, cycle, invalid governance file,
non-mergeable section) raises :class:`ResolutionError`. Its ``reason``
attribute is a stable migration-report diagnostic and is not an ACS runtime
reason.
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
