# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""Runnable companion for the MXC quickstart tutorial.

Demonstrates the ``MxcSandboxProvider`` end to end:

1. Probe MXC availability.
2. Render an MXC JSON config from a sandbox policy (works without a binary).
3. If a binary is present, create a session, run code, and tear it down.

Run::

    export MXC_BINARY=/path/to/lxc-exec   # or put it on PATH
    python quickstart.py

The config-rendering step runs even when MXC is not installed, so you can
see exactly what the provider would hand the native binary.
"""

from __future__ import annotations

import json
import tempfile
from pathlib import Path

from agent_sandbox import MxcSandboxProvider, SandboxConfig
from agent_sandbox.mxc_sandbox_provider import policy_yaml_to_mxc_json

# A sandbox policy: read-only input mount, read-write output mount, a
# fail-closed egress allowlist, and a timeout. MXC has no tool concept, so a
# ``tool_allowlist`` is intentionally omitted — a policy carrying one is
# rejected at session creation (use Docker/Hyperlight for tool gating).
POLICY_YAML = """
version: "1.0"
name: mxc-quickstart
defaults:
  timeout_seconds: 20
  network_default: deny
network_allowlist:
  - pypi.org
  - "*.github.com"
sandbox_mounts:
  input_dir: /data/user-input
  output_dir: /data/agent-output
"""


def show_rendered_config() -> None:
    """Render the policy to MXC JSON — no binary or sandbox required."""
    with tempfile.TemporaryDirectory() as tmp:
        policy_path = Path(tmp) / "sandbox_policy.yaml"
        policy_path.write_text(POLICY_YAML, encoding="utf-8")
        doc = policy_yaml_to_mxc_json(str(policy_path), "python /scripts/run.py")
    print("=== Rendered MXC config (policy -> JSON) ===")
    print(json.dumps(doc, indent=2))
    print()


def run_in_sandbox() -> None:
    """Run code in a one-shot sandbox — needs a real binary."""
    provider = MxcSandboxProvider(backend="bubblewrap")
    if not provider.is_available():
        print(
            "MXC binary not found — skipping live execution.\n"
            "Build it per https://github.com/microsoft/mxc#building and set "
            "MXC_BINARY to run this section."
        )
        return

    print("=== Live sandbox execution ===")
    print("MXC binary:", provider.binary_path)

    execution = provider.run_once(
        "mxc-quickstart",
        "print('hello from the MXC sandbox')",
        config=SandboxConfig(timeout_seconds=20, network_enabled=False),
    )
    result = execution.result
    print(f"exit={result.exit_code} success={result.success}")
    print((result.stdout or result.stderr).rstrip())


def main() -> None:
    show_rendered_config()
    run_in_sandbox()


if __name__ == "__main__":
    main()
