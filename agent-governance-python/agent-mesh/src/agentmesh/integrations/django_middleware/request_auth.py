# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""Canonical request authentication payloads for the Django integration.

The canonical envelope now lives in :mod:`agentmesh.integrations.request_auth`
so the Django, Flask, and FastAPI middlewares all verify byte-identical
payloads. This module is retained as a stable re-export for existing imports.
"""

from __future__ import annotations

from agentmesh.integrations.request_auth import (
    REQUEST_SIGNATURE_VERSION,
    build_request_signature_payload,
    replay_key,
)

__all__ = ["REQUEST_SIGNATURE_VERSION", "build_request_signature_payload", "replay_key"]
