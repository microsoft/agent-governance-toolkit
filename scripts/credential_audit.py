#!/usr/bin/env python3
# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""Compatibility entry point for the packaged credential auditor."""

from __future__ import annotations

import importlib
import sys
from pathlib import Path

_PACKAGE_SRC = (
    Path(__file__).resolve().parents[1]
    / "agent-governance-python"
    / "agent-compliance"
    / "src"
)
sys.path.insert(0, str(_PACKAGE_SRC))

_implementation = importlib.import_module("agent_compliance.cli.credential_audit")

if __name__ == "__main__":
    raise SystemExit(_implementation.main())

# Preserve imports used by repository tooling and tests while keeping all
# implementation code in the packaged module.
sys.modules[__name__] = _implementation
