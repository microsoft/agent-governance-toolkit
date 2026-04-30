# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""
Tests for Agent OS unified package.

Run with: pytest tests/ -v
"""

import sys
import types


def _stub_module(dotted_name: str) -> types.ModuleType:
    """Ensure *dotted_name* exists in sys.modules as a stub module tree."""
    parts = dotted_name.split(".")
    for i in range(len(parts)):
        key = ".".join(parts[: i + 1])
        if key not in sys.modules:
            mod = types.ModuleType(key)
            if i > 0:
                setattr(sys.modules[".".join(parts[:i])], parts[i], mod)
            sys.modules[key] = mod
    return sys.modules[dotted_name]


# Stub llama_index and submodules that use Python 3.10+ union-type syntax
# (the '|' operator on types), which crashes on Python 3.9 during import.
for _stub in [
    "llama_index",
    "llama_index.core",
    "llama_index.core.bridge",
    "llama_index.core.bridge.pydantic",
    "llama_index.core.instrumentation",
    "llama_index.core.instrumentation.events",
    "llama_index.core.base",
    "llama_index.core.base.base_query_engine",
    "llama_index.core.query_engine",
]:
    _stub_module(_stub)
from pathlib import Path

# Add modules to path for testing
REPO_ROOT = Path(__file__).parent.parent
sys.path.insert(0, str(REPO_ROOT / "src"))
sys.path.insert(0, str(REPO_ROOT / "modules" / "control-plane" / "src"))
sys.path.insert(0, str(REPO_ROOT / "modules" / "iatp"))
sys.path.insert(0, str(REPO_ROOT / "modules" / "cmvk" / "src"))
sys.path.insert(0, str(REPO_ROOT / "modules" / "caas" / "src"))
sys.path.insert(0, str(REPO_ROOT / "modules" / "emk"))
sys.path.insert(0, str(REPO_ROOT / "modules" / "amb"))
sys.path.insert(0, str(REPO_ROOT / "modules" / "atr"))
sys.path.insert(0, str(REPO_ROOT / "modules" / "scak"))
sys.path.insert(0, str(REPO_ROOT / "modules" / "scak" / "src"))
sys.path.insert(0, str(REPO_ROOT / "modules" / "mute-agent" / "src"))
sys.path.insert(0, str(REPO_ROOT / "modules" / "mute-agent"))
sys.path.insert(0, str(REPO_ROOT / "modules" / "observability"))
sys.path.insert(0, str(REPO_ROOT / "modules"))
sys.path.insert(0, str(REPO_ROOT / "modules" / "mcp-kernel-server"))
