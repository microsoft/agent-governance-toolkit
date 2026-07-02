# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""Smoke test for the ACS -> AGT kernel wiring example.

Runs the real subsystems (agentmesh trust, agent_os audit, hypervisor rings)
through KernelBridge and asserts the ACS-decision-to-kernel repro flips: one
apply() call lowers trust, emits a governance event, and gates the ring.
"""
from __future__ import annotations

import pytest

pytest.importorskip("agentmesh")
pytest.importorskip("agent_os")
pytest.importorskip("hypervisor")
pytest.importorskip("agent_control_specification")

from agt.policies.kernel import AuditEmissionResult  # noqa: E402
from hypervisor.models import ExecutionRing  # noqa: E402

from wire_acs_into_kernel import (  # noqa: E402
    build_wired_kernel,
    run_demo,
    _acs_decision,
    _reversible_tool,
)


def test_run_demo_flips_the_repro():
    outcomes = run_demo()

    deny = outcomes["deny"]
    assert deny.effective_decision == "deny"
    assert deny.proceeds is False
    assert deny.trust_delta < 0  # trust lowered by the ACS deny
    assert deny.demoted is True  # ring tripped down
    assert deny.audit is AuditEmissionResult.ACCEPTED
    assert deny.event.kind == "policy_violation"

    blocked = outcomes["allow_ring_blocked"]
    assert blocked.effective_decision == "allow"
    assert blocked.ring_allowed is False
    assert blocked.proceeds is False  # ACS allow is not sufficient

    ok = outcomes["allow_ok"]
    assert ok.proceeds is True
    assert ok.trust_delta > 0
    assert ok.event.kind == "policy_check"


def test_single_apply_drives_all_three_subsystems():
    wired = build_wired_kernel()
    before = wired.trust.get_score("agent-x")

    out = wired.bridge.apply(
        _acs_decision("deny", reason="blocked_pattern_input"),
        agent_id="agent-x",
        peer_id="orchestrator",
        action=_reversible_tool("send_email"),
        current_ring=ExecutionRing.RING_2_STANDARD,
    )

    # trust moved
    assert wired.trust.get_score("agent-x") < before
    # audit delivered synchronously to the sink
    assert wired.sink.count == 1
    assert wired.sink.events[0].agent_id == "agent-x"
    # ring evaluated
    assert out.demoted is True
