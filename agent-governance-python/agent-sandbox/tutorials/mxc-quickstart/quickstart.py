# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""Runnable companion for the MXC quickstart tutorial.

Demonstrates the ``MxcSandboxProvider`` end to end:

1. Probe MXC availability.
2. Render MXC JSON from explicit host configuration.
3. If a binary is present, create a session, run code, and tear it down.

Run::

    export MXC_BINARY=/path/to/lxc-exec   # or put it on PATH
    python quickstart.py

The config-rendering step runs even when MXC is not installed, so you can
see exactly what the provider would hand the native binary.
"""

from __future__ import annotations

import json
from agent_sandbox import MxcSandboxProvider, SandboxConfig
from agent_sandbox.mxc_sandbox_provider import MxcConfig


HOST_CONFIG = SandboxConfig(
    timeout_seconds=20,
    input_dir="/data/user-input",
    output_dir="/data/agent-output",
    network_enabled=True,
    network_allowlist=["pypi.org", "*.github.com"],
)


def show_rendered_config() -> None:
    """Render host configuration to MXC JSON without starting a sandbox."""
    doc = MxcConfig.from_sandbox_config(HOST_CONFIG).to_mxc_json(
        "python /scripts/run.py"
    )
    print("=== Rendered MXC config ===")
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
        config=HOST_CONFIG,
    )
    result = execution.result
    print(f"exit={result.exit_code} success={result.success}")
    print((result.stdout or result.stderr).rstrip())


def main() -> None:
    show_rendered_config()
    run_in_sandbox()


if __name__ == "__main__":
    main()
