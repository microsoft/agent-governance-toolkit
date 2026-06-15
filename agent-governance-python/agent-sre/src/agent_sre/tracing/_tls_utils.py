# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""Shared TLS / endpoint-locality utilities for agent-sre OTLP exporters.

Centralised here so that ``agent_sre.tracing.exporters`` and any future
sre tracing helpers stay in sync without copy-pasting.
"""

from __future__ import annotations

import urllib.parse

_LOCAL_HOSTS: frozenset[str] = frozenset({"localhost", "127.0.0.1", "::1", "[::1]"})


def is_local_endpoint(endpoint: str) -> bool:
    """Return True if *endpoint* resolves to a loopback address.

    Handles bare ``host:port`` strings (no scheme) by injecting a
    dummy ``grpc://`` prefix so :func:`urllib.parse.urlparse` can
    extract the hostname correctly.
    """
    if not endpoint:
        return False
    if "://" not in endpoint:
        endpoint = "grpc://" + endpoint
    try:
        hostname = urllib.parse.urlparse(endpoint).hostname or ""
    except Exception:
        return False
    return hostname in _LOCAL_HOSTS
