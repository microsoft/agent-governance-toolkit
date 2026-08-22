# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""Canonical request authentication payloads for the Django integration."""

from __future__ import annotations

import hashlib
import json

REQUEST_SIGNATURE_VERSION = "agentmesh-http-request-v1"


def build_request_signature_payload(
    *,
    agent_did: str,
    audience: str,
    timestamp: str,
    nonce: str,
    method: str,
    request_target: str,
    body: bytes,
    content_type: str = "",
) -> bytes:
    """Build the canonical bytes covered by an AgentMesh HTTP signature."""
    envelope = {
        "agent_did": agent_did,
        "audience": audience,
        "body_sha256": hashlib.sha256(body).hexdigest(),
        "content_type": content_type,
        "method": method.upper(),
        "nonce": nonce,
        "request_target": request_target,
        "timestamp": timestamp,
    }
    canonical_json = json.dumps(envelope, sort_keys=True, separators=(",", ":"))
    return f"{REQUEST_SIGNATURE_VERSION}\n{canonical_json}".encode()
