# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""OCI runtime isolation levels for Docker containers."""

from __future__ import annotations

from enum import Enum


class IsolationRuntime(str, Enum):
    """OCI runtime selector for container-level isolation."""

    RUNC = "runc"
    GVISOR = "runsc"
    KATA = "kata-runtime"
    AUTO = "auto"
