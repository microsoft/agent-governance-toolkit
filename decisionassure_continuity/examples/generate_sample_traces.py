#!/usr/bin/env python3
"""
Generate a large set of synthetic traces for testing the batch witness processor.
"""

import json
import random
import os

def generate_traces(num_traces: int = 100, output_dir: str = "sample_traces_large"):
    os.makedirs(output_dir, exist_ok=True)

    # Define patterns
    patterns = [
        # Capability: Credential Exfiltration (critical)
        (["alice", "charlie"], ["read_credentials", "export_data"]),
        # Capability: Data Export (medium)
        (["bob", "dave"], ["read_database", "export_data"]),
        # Capability: Privilege Escalation (critical)
        (["eve", "frank", "grace"], ["grant_permission", "write_config", "delete_logs"]),
        # Capability: Model Exfiltration (critical)
        (["heidi", "ivan"], ["read_model", "export_model"]),
        # Noise
        (["jack", "karen"], ["read_database", "read_database"]),
    ]

    for i in range(num_traces):
        agents, actions = random.choice(patterns)
        messages = []
        for agent, action in zip(agents, actions):
            messages.append({
                "sender": agent,
                "tool_calls": [{"name": action, "arguments": {}}]
            })
        trace = {"messages": messages}
        filename = os.path.join(output_dir, f"trace_{i:03d}.json")
        with open(filename, 'w') as f:
            json.dump(trace, f, indent=2)

    print(f"✅ Generated {num_traces} synthetic traces in {output_dir}/")

if __name__ == "__main__":
    generate_traces(150)  # Generate 150 traces