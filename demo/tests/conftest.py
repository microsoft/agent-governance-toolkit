# conftest.py — shared pytest configuration for the demo tests
# Ensures sys.path is bootstrapped before any test module is imported.

from __future__ import annotations

import sys
from pathlib import Path

_REPO = Path(__file__).resolve().parent.parent.parent
for _p in [
    _REPO / "demo",
    _REPO / "packages" / "agent-os"      / "src",
    _REPO / "packages" / "agent-mesh"     / "src",
    _REPO / "packages" / "agent-sre"      / "src",
    _REPO / "packages" / "agent-runtime"  / "src",
]:
    if str(_p) not in sys.path:
        sys.path.insert(0, str(_p))
