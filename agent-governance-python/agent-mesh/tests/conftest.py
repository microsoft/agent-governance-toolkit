# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""Shared pytest fixtures and markers for agent-mesh tests."""

from __future__ import annotations

import shutil

import pytest

# Detect external policy engine availability once per session.
_HAS_OPA_CLI = shutil.which("opa") is not None

try:
    import cedarpy  # noqa: F401
    _HAS_CEDARPY = True
except ImportError:
    _HAS_CEDARPY = False

_HAS_CEDAR_CLI = shutil.which("cedar") is not None
_HAS_CEDAR = _HAS_CEDARPY or _HAS_CEDAR_CLI

requires_opa = pytest.mark.skipif(
    not _HAS_OPA_CLI, reason="opa CLI not installed"
)
requires_cedar = pytest.mark.skipif(
    not _HAS_CEDAR, reason="cedarpy and cedar CLI not installed"
)
