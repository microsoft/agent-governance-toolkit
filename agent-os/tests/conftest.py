# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""
Tests for Agent OS unified package.

Run with: pytest tests/ -v
"""

import sys
from pathlib import Path

# Add modules to path for testing
REPO_ROOT = Path(__file__).parent.parent
sys.path.insert(0, str(REPO_ROOT / "src"))
sys.path.insert(0, str(REPO_ROOT / "modules" / "primitives"))
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
