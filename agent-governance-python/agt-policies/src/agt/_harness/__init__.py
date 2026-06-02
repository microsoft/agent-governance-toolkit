# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""Test harness for scenario-based AGT 5.0 evaluation.

This is a thin scaffold used by tests in ``tests/scenarios/``. It is
not part of the public API. When the Python SDK over the Rust core
lands in M3.S3 the harness will swap its dispatcher implementation,
but the scenario tests themselves will not need to change.
"""

from . import opa_runner, snapshot

__all__ = ["opa_runner", "snapshot"]
