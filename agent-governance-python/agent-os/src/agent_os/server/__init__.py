# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""Agent OS Governance API Server.

Provides a REST API for governance operations, enabling language-agnostic
access to Agent OS capabilities.
"""

try:
    from agent_os.server.app import GovServer, create_app
except ImportError:  # pragma: no cover
    GovServer = None  # type: ignore[assignment,misc]
    create_app = None  # type: ignore[assignment]

__all__ = ["create_app", "GovServer"]
