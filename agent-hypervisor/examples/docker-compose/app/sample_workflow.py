# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""
Sample multi-agent workflow — registers agents and runs a saga.

Waits for the hypervisor API to be ready, then:
  1. Registers three agents at different reputation levels
  2. Shows their ring assignments
  3. Triggers a kill switch on a low-trust agent
  4. Prints the audit log
"""

from __future__ import annotations

import os
import sys
import time

import httpx

API = os.getenv("HYPERVISOR_API", "http://localhost:8000")

AGENTS = [
    {"agent_did": "did:mesh:planner-01", "sigma_raw": 0.97},
    {"agent_did": "did:mesh:executor-02", "sigma_raw": 0.75},
    {"agent_did": "did:mesh:researcher-03", "sigma_raw": 0.40},
]


def wait_for_api(timeout: int = 60) -> None:
    """Block until the API health endpoint responds."""
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            r = httpx.get(f"{API}/health", timeout=3)
            if r.status_code == 200:
                print("[✓] API is ready")
                return
        except httpx.ConnectError:
            pass
        time.sleep(2)
    print("[✗] API did not become ready in time")
    sys.exit(1)


def register_agents() -> None:
    print("\n── Registering agents ─────────────────────────")
    for agent in AGENTS:
        r = httpx.post(f"{API}/agents", json=agent, timeout=10)
        data = r.json()
        print(f"  {data['agent_did']:30s}  →  {data['ring_name']} (σ={data['eff_score']:.2f})")


def list_agents() -> None:
    print("\n── Agent roster ───────────────────────────────")
    r = httpx.get(f"{API}/agents", timeout=10)
    for a in r.json():
        print(f"  {a['agent_did']:30s}  ring={a['ring']} ({a['ring_name']})")


def kill_rogue_agent() -> None:
    print("\n── Kill switch: researcher-03 ─────────────────")
    r = httpx.post(
        f"{API}/kill",
        json={"agent_did": "did:mesh:researcher-03", "reason": "manual"},
        timeout=10,
    )
    data = r.json()
    print(f"  kill_id={data['kill_id']}  compensation={data['compensation_triggered']}")


def show_audit() -> None:
    print("\n── Audit log ──────────────────────────────────")
    r = httpx.get(f"{API}/audit", timeout=10)
    for entry in r.json():
        print(f"  [{entry['timestamp']}] {entry['event']:20s} {entry['agent_did']}  {entry['detail']}")


def main() -> None:
    print(f"Agent Hypervisor — sample workflow (API={API})")
    wait_for_api()
    register_agents()
    list_agents()
    kill_rogue_agent()
    show_audit()
    print("\n[✓] Workflow complete")


if __name__ == "__main__":
    main()
