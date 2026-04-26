# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""Tests for agent dataclasses and importable components.

The external `mute_agent` library is NOT installed, so tests that require it
are skipped gracefully.
"""

import sys
import os

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'src'))

import pytest
from datetime import datetime


# ---------------------------------------------------------------------------
# MuteAgentResult (importable without external deps)
# ---------------------------------------------------------------------------

def _import_mute_agent_result():
    """Try to import MuteAgentResult; skip if external deps missing."""
    try:
        from agents.mute_agent import MuteAgentResult
        return MuteAgentResult
    except ImportError:
        # External `mute_agent` library is imported at module level —
        # we can still test the dataclass by extracting it manually.
        pass

    # Fallback: load only the dataclass via AST / source manipulation
    import importlib.util
    import types

    src_path = os.path.join(os.path.dirname(__file__), '..', 'src', 'agents', 'mute_agent.py')
    source = open(src_path).read()

    # Build a minimal module that only defines the dataclass
    stub = (
        "from dataclasses import dataclass, field\n"
        "from typing import Dict, Any, List, Optional\n"
        "from datetime import datetime\n"
    )

    # Extract the MuteAgentResult dataclass source
    import re
    match = re.search(
        r"(@dataclass\s+class MuteAgentResult:.*?)(?=\nclass |\Z)",
        source, re.DOTALL,
    )
    if not match:
        pytest.skip("Could not extract MuteAgentResult dataclass")

    stub += match.group(1)
    mod = types.ModuleType("_mute_agent_stub")
    exec(compile(stub, "<mute_agent_stub>", "exec"), mod.__dict__)
    return mod.MuteAgentResult


def _import_baseline_classes():
    """Try to import BaselineAgentResult and ReflectionStep."""
    try:
        from agents.baseline_agent import BaselineAgentResult, ReflectionStep
        return BaselineAgentResult, ReflectionStep
    except ImportError:
        pytest.skip("Could not import baseline_agent (external deps missing)")


# ---------------------------------------------------------------------------
# MuteAgentResult tests
# ---------------------------------------------------------------------------

class TestMuteAgentResult:
    @pytest.fixture(autouse=True)
    def _load(self):
        self.MuteAgentResult = _import_mute_agent_result()
        if self.MuteAgentResult is None:
            pytest.skip("MuteAgentResult not available")

    def test_create_success_result(self):
        r = self.MuteAgentResult(
            success=True, action_taken="restart_service",
            parameters_used={"service_id": "svc-1"},
            final_result={"ok": True},
            constraint_violation=None, blocked_by_graph=False,
            safety_violation=False, state_misalignment=False,
            token_count=350, graph_traversals=2, latency_ms=12.5,
        )
        assert r.success is True
        assert r.needed_clarification is False

    def test_create_failure_result(self):
        r = self.MuteAgentResult(
            success=False, action_taken="restart_service",
            parameters_used=None, final_result=None,
            constraint_violation="no permission",
            blocked_by_graph=True, safety_violation=True,
            state_misalignment=False,
            token_count=250, graph_traversals=1, latency_ms=5.0,
        )
        assert r.success is False
        assert r.blocked_by_graph is True
        assert r.safety_violation is True

    def test_default_needed_clarification_is_false(self):
        r = self.MuteAgentResult(
            success=True, action_taken="x", parameters_used=None,
            final_result=None, constraint_violation=None,
            blocked_by_graph=False, safety_violation=False,
            state_misalignment=False,
            token_count=0, graph_traversals=0, latency_ms=0,
        )
        assert r.needed_clarification is False


# ---------------------------------------------------------------------------
# BaselineAgentResult & ReflectionStep tests
# ---------------------------------------------------------------------------

class TestBaselineAgentResult:
    @pytest.fixture(autouse=True)
    def _load(self):
        self.BaselineAgentResult, self.ReflectionStep = _import_baseline_classes()

    def test_create_baseline_result(self):
        r = self.BaselineAgentResult(
            success=True, action_taken="restart_service",
            parameters_used={"service_id": "svc-1"},
            final_result={"ok": True},
            hallucinated=False, hallucination_details=None,
            safety_violation=False, state_misalignment=False,
            token_count=1300, reflection_steps=[], turns_used=1,
            latency_ms=50.0, needed_clarification=False,
            clarification_question=None,
        )
        assert r.success is True
        assert r.hallucinated is False

    def test_baseline_result_with_hallucination(self):
        r = self.BaselineAgentResult(
            success=False, action_taken="restart_service",
            parameters_used={"service_id": "wrong-svc"},
            final_result=None,
            hallucinated=True, hallucination_details="used stale context",
            safety_violation=False, state_misalignment=True,
            token_count=2000, reflection_steps=[], turns_used=3,
            latency_ms=120.0, needed_clarification=False,
            clarification_question=None,
        )
        assert r.hallucinated is True
        assert r.state_misalignment is True

    def test_reflection_step_creation(self):
        step = self.ReflectionStep(
            turn=1, thought="Permission denied", action="restart_service",
            parameters={"service_id": "svc-1"},
            result={"error": "Permission denied"}, error="Permission denied",
        )
        assert step.turn == 1
        assert step.timestamp is not None

    def test_baseline_result_with_clarification(self):
        r = self.BaselineAgentResult(
            success=False, action_taken=None,
            parameters_used=None, final_result=None,
            hallucinated=False, hallucination_details=None,
            safety_violation=False, state_misalignment=False,
            token_count=800, reflection_steps=[], turns_used=1,
            latency_ms=10.0, needed_clarification=True,
            clarification_question="Which service?",
        )
        assert r.needed_clarification is True
        assert r.clarification_question == "Which service?"


# ---------------------------------------------------------------------------
# InteractiveAgent import test
# ---------------------------------------------------------------------------

class TestInteractiveAgentImport:
    def test_interactive_agent_extends_baseline(self):
        try:
            from agents.interactive_agent import InteractiveAgent
            # Check via MRO class names to avoid duplicate-module identity issues
            base_names = [cls.__name__ for cls in InteractiveAgent.__mro__]
            assert "BaselineAgent" in base_names
        except ImportError:
            pytest.skip("Could not import InteractiveAgent")
