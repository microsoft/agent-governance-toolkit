# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""
Unit tests for continuity verification.
"""
import pytest
from agent_os.continuity import ContinuityVerifier
from agent_os.sandbox import ExecutionSandbox, SandboxConfig
from agent_os.exceptions import SecurityError


def test_continuity_verifier_no_drift():
    verifier = ContinuityVerifier("test")
    verifier.capture_pre_state(
        agent_id="a", session_id="s", memory_state={"x": 1},
        policy_version="v1", delegation_chain=["root"], evidence_state={"fresh": True},
    )
    trace = verifier.capture_post_state(
        agent_id="a", session_id="s", memory_state={"x": 1},
        policy_version="v1", delegation_chain=["root"], evidence_state={"fresh": True},
    )
    assert trace.admissible is True
    assert trace.decision == "ALLOW"


def test_continuity_verifier_policy_drift():
    verifier = ContinuityVerifier("test")
    verifier.capture_pre_state(
        agent_id="a", session_id="s", memory_state={"x": 1},
        policy_version="v1", delegation_chain=["root"], evidence_state={"fresh": True},
    )
    trace = verifier.capture_post_state(
        agent_id="a", session_id="s", memory_state={"x": 1},
        policy_version="v2", delegation_chain=["root"], evidence_state={"fresh": True},
    )
    assert trace.admissible is False
    assert trace.decision == "DENY"
    assert "policy" in trace.diff


def test_continuity_verifier_delegation_drift():
    verifier = ContinuityVerifier("test")
    verifier.capture_pre_state(
        agent_id="a", session_id="s", memory_state={"x": 1},
        policy_version="v1", delegation_chain=["root", "alice"], evidence_state={"fresh": True},
    )
    trace = verifier.capture_post_state(
        agent_id="a", session_id="s", memory_state={"x": 1},
        policy_version="v1", delegation_chain=["root"], evidence_state={"fresh": True},
    )
    assert trace.admissible is False
    assert "delegation" in trace.diff


def test_sandbox_continuity_enabled():
    config = SandboxConfig(enable_continuity=True, enforcement_mode="enforce")
    sandbox = ExecutionSandbox(config)
    context = {
        "agent_id": "test",
        "session_id": "sess",
        "memory_state": {},
        "policy_version": "v1",
        "delegation_chain": ["root"],
        "evidence_state": {"fresh": True},
    }
    user_globals = {"context": context}

    code_no_drift = "x = 1"
    sandbox.execute_code_sandboxed(code_no_drift, user_globals=user_globals, continuity_context=context)

    code_with_drift = "context['policy_version'] = 'v2'"
    with pytest.raises(SecurityError, match="Continuity drift"):
        sandbox.execute_code_sandboxed(code_with_drift, user_globals=user_globals, continuity_context=context)