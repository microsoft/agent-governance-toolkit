#!/usr/bin/env python3
# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""
Hypervisor Demo -- Agent Governance in 60 Seconds

Demonstrates the full lifecycle of the Agent Hypervisor:
  1. Session creation with configurable governance
  2. Agent admission via trust scoring (eff_score -> ring assignment)
  3. Saga orchestration with reversibility tracking
  4. Audit trail with a hash-chained delta log
  5. Optional integration adapters

Run:
    cd modules/hypervisor
    pip install -r examples/requirements.txt
    python examples/demo.py
"""

from __future__ import annotations

import asyncio
import sys

# Add src to path for demo
sys.path.insert(0, str(__import__("pathlib").Path(__file__).resolve().parent.parent / "src"))

from hypervisor.audit.delta import VFSChange
from hypervisor.core import Hypervisor
from hypervisor.models import (
    ConsistencyMode,
    SessionConfig,
)

CYAN = "\033[96m"
GREEN = "\033[92m"
YELLOW = "\033[93m"
RED = "\033[91m"
BOLD = "\033[1m"
RESET = "\033[0m"


def banner(title: str) -> None:
    print(f"\n{BOLD}{CYAN}{'=' * 60}")
    print(f"  {title}")
    print(f"{'=' * 60}{RESET}\n")


def step(msg: str) -> None:
    print(f"  {GREEN}+{RESET} {msg}")


def warn(msg: str) -> None:
    print(f"  {YELLOW}!{RESET} {msg}")


def fail(msg: str) -> None:
    print(f"  {RED}x{RESET} {msg}")


# ── Demo 1: Session Lifecycle ───────────────────────────────────────


async def demo_session_lifecycle() -> None:
    banner("Demo 1: Session Lifecycle -- Create -> Join -> Activate -> Terminate")

    hv = Hypervisor()

    # Create a session with audit enabled
    config = SessionConfig(
        enable_audit=True,
        consistency_mode=ConsistencyMode.EVENTUAL,
    )
    session = await hv.create_session(config, creator_did="did:mesh:admin")
    step(f"Session created: {session.sso.session_id[:16]}...")

    # Join agents with different trust scores
    ring_high = await hv.join_session(
        session.sso.session_id,
        "did:mesh:trusted-agent",
        sigma_raw=0.95,
    )
    step(f"Trusted agent -> {ring_high.name} (sigma=0.95)")

    ring_mid = await hv.join_session(
        session.sso.session_id,
        "did:mesh:standard-agent",
        sigma_raw=0.65,
    )
    step(f"Standard agent -> {ring_mid.name} (sigma=0.65)")

    ring_low = await hv.join_session(
        session.sso.session_id,
        "did:mesh:sandbox-agent",
        sigma_raw=0.20,
    )
    step(f"Sandbox agent -> {ring_low.name} (sigma=0.20)")

    # Activate
    await hv.activate_session(session.sso.session_id)
    step(f"Session activated -- {len(session.sso.participants)} participants")

    # Capture some deltas for the audit trail
    session.delta_engine.capture(
        "did:mesh:trusted-agent",
        [
            VFSChange(
                path="/workspace/report.md",
                operation="create",
                content_hash="abc123",
                previous_hash="",
                agent_did="did:mesh:trusted-agent",
            )
        ],
    )
    step("Delta captured: /workspace/report.md")

    # Terminate and get the audit hash root
    hash_chain_root = await hv.terminate_session(session.sso.session_id)
    step(f"Session terminated -- audit log root: {hash_chain_root[:16]}...")

    print(f"\n  {BOLD}Ring assignments show trust-based isolation:{RESET}")
    print("    Ring 1 (High Trust):  sigma >= 0.95 + consensus")
    print("    Ring 2 (Standard):    sigma >= 0.60")
    print("    Ring 3 (Sandbox):     sigma < 0.60")


# ── Demo 2: Saga Orchestration ──────────────────────────────────────


async def demo_saga() -> None:
    banner("Demo 2: Saga Orchestration -- Multi-Step with Compensation")

    hv = Hypervisor()
    config = SessionConfig(enable_audit=True)
    session = await hv.create_session(config, creator_did="did:mesh:admin")
    await hv.join_session(session.sso.session_id, "did:mesh:worker", sigma_raw=0.85)
    await hv.activate_session(session.sso.session_id)

    saga_orch = session.saga

    # Create a saga for a multi-step workflow
    saga = saga_orch.create_saga(session.sso.session_id)
    step(f"Saga created: {saga.saga_id[:24]}...")

    # Add steps
    s1 = saga_orch.add_step(
        saga.saga_id, "provision", "did:mesh:worker", "/api/provision", undo_api="/api/deprovision"
    )
    s2 = saga_orch.add_step(
        saga.saga_id, "deploy", "did:mesh:worker", "/api/deploy", undo_api="/api/rollback"
    )
    s3 = saga_orch.add_step(saga.saga_id, "evaluate", "did:mesh:worker", "/api/evaluate")
    step("Steps defined: provision -> deploy -> evaluate")

    # Execute steps (simulating success for first two)
    async def success_exec():
        return "completed"

    async def fail_exec():
        raise RuntimeError("evaluation failed")

    r1 = await saga_orch.execute_step(saga.saga_id, s1.step_id, executor=success_exec)
    step(f"  provision: + {r1}")

    r2 = await saga_orch.execute_step(saga.saga_id, s2.step_id, executor=success_exec)
    step(f"  deploy: + {r2}")

    # Step 3 fails
    try:
        await saga_orch.execute_step(saga.saga_id, s3.step_id, executor=fail_exec)
    except RuntimeError:
        fail("  evaluate: x RuntimeError -- triggering compensation")

    # Compensate completed steps
    compensated = await saga_orch.compensate(
        saga.saga_id,
        lambda step_obj: f"compensated:{step_obj.action_id}",
    )
    for c in compensated:
        warn(f"  {c.action_id}: <- compensated (rolled back)")

    print(f"\n  {BOLD}Saga ensures atomicity:{RESET}")
    print("    Failed steps trigger automatic compensation")
    print("    All-or-nothing semantics for multi-agent workflows")


# ── Demo 3: Audit Trail ────────────────────────────────────────────


async def demo_audit() -> None:
    banner("Demo 3: Audit Trail -- Hash-Chained Delta Log")

    hv = Hypervisor()
    config = SessionConfig(enable_audit=True)
    session = await hv.create_session(config, creator_did="did:mesh:admin")
    await hv.join_session(session.sso.session_id, "did:mesh:agent-a", sigma_raw=0.80)
    await hv.join_session(session.sso.session_id, "did:mesh:agent-b", sigma_raw=0.75)
    await hv.activate_session(session.sso.session_id)

    # Agents make changes
    changes = [
        ("did:mesh:agent-a", "/data/input.csv", "create"),
        ("did:mesh:agent-a", "/data/output.json", "create"),
        ("did:mesh:agent-b", "/data/input.csv", "modify"),
    ]

    for agent, path, op in changes:
        session.delta_engine.capture(
            agent,
            [
                VFSChange(
                    path=path,
                    operation=op,
                    content_hash=f"hash-{path.split('/')[-1]}",
                    previous_hash="" if op == "create" else "prev-hash",
                    agent_did=agent,
                )
            ],
        )
        step(f"Delta: {agent.split(':')[-1]} -> {op} {path}")

    step(f"Total deltas: {session.delta_engine.turn_count}")

    audit_log = await hv.terminate_session(session.sso.session_id)
    step(f"audit log root: {audit_log}")

    print(f"\n  {BOLD}Audit guarantees:{RESET}")
    print("    Every agent action is delta-captured")
    print("    The delta hash chain provides a tamper-evident root")
    print("    The returned root can be stored by the caller")


# ── Demo 4: Integration Adapters ────────────────────────────────────


async def demo_integrations() -> None:
    banner("Demo 4: Integration Adapters -- Nexus + Verification + IATP")

    from hypervisor.integrations.iatp_adapter import IATPAdapter
    from hypervisor.integrations.nexus_adapter import NexusAdapter
    from hypervisor.integrations.verification_adapter import VerificationAdapter

    # Mock reputation engine matching NexusTrustScorer protocol
    class MockReputationEngine:
        def calculate_trust_score(
            self, verification_level=None, history=None, capabilities=None, privacy=None
        ):
            scores = {
                920: type(
                    "Score", (), {"total_score": 920, "successful_tasks": 500, "failed_tasks": 0}
                ),
                650: type(
                    "Score", (), {"total_score": 650, "successful_tasks": 50, "failed_tasks": 2}
                ),
                200: type(
                    "Score", (), {"total_score": 200, "successful_tasks": 5, "failed_tasks": 10}
                ),
            }
            # Use history to differentiate agents
            if history and history.get("tasks_completed", 0) > 100:
                return scores[920]()
            elif history and history.get("tasks_completed", 0) > 10:
                return scores[650]()
            return scores[200]()

        def record_task_outcome(self, agent_did, outcome):
            pass

    # Mock behavioral verifier
    class MockVerificationBackend:
        def check_drift(self, agent_did: str, claimed, observed):
            import random

            drift = random.uniform(0.0, 0.3)
            return {"drift_score": drift, "agent_did": agent_did}

    nexus = NexusAdapter(scorer=MockReputationEngine())
    policy_check = VerificationAdapter(verifier=MockVerificationBackend())
    iatp = IATPAdapter()

    hv = Hypervisor(nexus=nexus, policy_check=policy_check, iatp=iatp)

    config = SessionConfig(enable_audit=True)
    session = await hv.create_session(config, creator_did="did:mesh:admin")

    # Join with Nexus auto-resolution
    ring_verified = await hv.join_session(
        session.sso.session_id,
        "did:mesh:verified",
        agent_history={"tasks_completed": 500, "violations": 0},
    )
    step(f"Verified partner -> {ring_verified.name} (Nexus score: 920)")

    ring_standard = await hv.join_session(
        session.sso.session_id,
        "did:mesh:standard",
        agent_history={"tasks_completed": 50, "violations": 2},
    )
    step(f"Standard agent -> {ring_standard.name} (Nexus score: 650)")

    ring_unknown = await hv.join_session(
        session.sso.session_id,
        "did:mesh:unknown",
    )
    step(f"Unknown agent -> {ring_unknown.name} (Nexus score: 200)")

    # IATP manifest parsing
    manifest = {
        "agent_did": "did:mesh:manifest-agent",
        "capabilities": ["read_file", "write_file", "execute_code"],
        "trust_level": "standard",
        "reversibility": {"write_file": "reversible", "execute_code": "non_reversible"},
    }
    ring_manifest = await hv.join_session(
        session.sso.session_id,
        "did:mesh:manifest-agent",
        manifest=manifest,
    )
    step(f"Manifest agent -> {ring_manifest.name} (IATP-parsed)")

    print(f"\n  {BOLD}Integration adapters:{RESET}")
    print("    Nexus:  Trust scoring from reputation network")
    print("    Verification:   Behavioral drift detection")
    print("    IATP:   Capability manifest parsing")
    print("    All adapters are protocol-based and pluggable")


# ── Main ────────────────────────────────────────────────────────────


async def main() -> None:
    print(f"\n{BOLD}{'=' * 60}")
    print("  Agent Hypervisor -- Governance Runtime Demo")
    print("  Multi-agent session management with formal safety")
    print(f"{'=' * 60}{RESET}")

    await demo_session_lifecycle()
    await demo_saga()
    await demo_audit()
    await demo_integrations()

    banner("Demo Complete!")
    print("  The Agent Hypervisor provides:")
    print("    - Ring-based execution isolation (4 trust tiers)")
    print("    - Saga orchestration with automatic compensation")
    print("    - Hash-chained audit trails")
    print("    - Pluggable integrations (Nexus, Verification, IATP)")
    print(f"\n  {BOLD}644 tests passing | 268us full pipeline | Zero dependencies{RESET}")
    print("\n  Learn more: https://github.com/microsoft/agent-governance-toolkit")
    print()


if __name__ == "__main__":
    asyncio.run(main())
