# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""
AgentMesh Trust Dashboard — Interactive Demo
=============================================
Creates sample agents, starts the dashboard server, and simulates
trust-score changes every few seconds so you can watch the charts
update in real time.

Usage:
    python demo.py [--port PORT]

No external dependencies required — uses only the Python standard library.
"""

from __future__ import annotations

import argparse
import datetime as dt
import random
import time

from dashboard import start_server, update_data

# ---------------------------------------------------------------------------
# Demo agents
# ---------------------------------------------------------------------------

DEMO_AGENTS: dict[str, dict] = {
    "payment-agent":     {"score": 920, "protocol": "A2A",  "did": "did:web:payments.mesh.io"},
    "customer-service":  {"score": 870, "protocol": "A2A",  "did": "did:web:cs.mesh.io"},
    "data-analyst":      {"score": 810, "protocol": "MCP",  "did": "did:web:analytics.mesh.io"},
    "fraud-detector":    {"score": 940, "protocol": "IATP", "did": "did:web:fraud.mesh.io"},
    "inventory-manager": {"score": 720, "protocol": "MCP",  "did": "did:web:inventory.mesh.io"},
    "email-dispatcher":  {"score": 650, "protocol": "A2A",  "did": "did:web:email.mesh.io"},
    "auth-gateway":      {"score": 950, "protocol": "IATP", "did": "did:web:auth.mesh.io"},
    "report-generator":  {"score": 580, "protocol": "MCP",  "did": "did:web:reports.mesh.io"},
    "scheduler":         {"score": 780, "protocol": "A2A",  "did": "did:web:scheduler.mesh.io"},
    "compliance-bot":    {"score": 890, "protocol": "IATP", "did": "did:web:compliance.mesh.io"},
}


def _build_initial_history(
    agents: dict[str, dict],
    points: int = 48,
) -> dict[str, list]:
    """Generate synthetic history (12 hours at 15-min intervals)."""
    random.seed(42)
    now = dt.datetime.now(dt.timezone.utc)
    history: dict[str, list] = {}
    for name, info in agents.items():
        pts = []
        score = info["score"]
        for i in range(points):
            t = now - dt.timedelta(minutes=15 * (points - 1 - i))
            score = max(0, min(1000, score + random.randint(-15, 15)))
            pts.append((t.strftime("%H:%M"), score))
        pts[-1] = (pts[-1][0], info["score"])
        history[name] = pts
    return history


def main() -> None:
    parser = argparse.ArgumentParser(description="Trust Dashboard Demo")
    parser.add_argument("--port", type=int, default=8050)
    args = parser.parse_args()

    agents = {k: dict(v) for k, v in DEMO_AGENTS.items()}
    history = _build_initial_history(agents)

    update_data(agents=agents, history=history)

    server = start_server(args.port)

    print("Simulating trust-score changes (Ctrl+C to stop) …\n")

    random.seed()
    try:
        while True:
            time.sleep(5)

            # Pick 2-4 agents and nudge their scores
            names = random.sample(list(agents.keys()), k=random.randint(2, 4))
            now_str = dt.datetime.now(dt.timezone.utc).strftime("%H:%M")

            for name in names:
                delta = random.randint(-25, 25)
                old = agents[name]["score"]
                agents[name]["score"] = max(0, min(1000, old + delta))

                history[name].append((now_str, agents[name]["score"]))
                # Keep last 100 data points per agent
                if len(history[name]) > 100:
                    history[name] = history[name][-100:]

                arrow = "↑" if delta > 0 else ("↓" if delta < 0 else "→")
                print(f"  {name}: {old} {arrow} {agents[name]['score']}  ({delta:+d})")

            update_data(agents=agents, history=history)
    except KeyboardInterrupt:
        print("\nStopping demo.")
        server.shutdown()


if __name__ == "__main__":
    main()
