from __future__ import annotations

import sys
from pathlib import Path

import pytest

HARNESS_DIR = Path(__file__).resolve().parent
if str(HARNESS_DIR) not in sys.path:
    sys.path.insert(0, str(HARNESS_DIR))


def test_harness_imports_and_environment_gate() -> None:
    from acs_agentdojo_bench import runner

    reason = runner.skip_reason_for_environment("openai")
    if reason:
        pytest.skip(reason)

    pytest.importorskip("agentdojo")
