#!/usr/bin/env python3
# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""End-to-end Agent Governance Toolkit run on the nono sandbox.

This is the nono counterpart to ``aca_sandbox_test.py``: it drives the
full governance flow — load a ``PolicyDocument``, create a sandbox session
with that policy, and execute code — but the isolation is enforced by
``nono`` (Landlock on Linux, Seatbelt on macOS) instead of a cloud
sandbox. No daemon, hypervisor, or cloud account is required.

Governance layers (policy-driven session):

1. **Host-side policy gate** — denies before the sandbox is forked.
2. **Static AST scan** — blocks real ``subprocess`` use in submitted code.
3. **Kernel filesystem isolation** — reads outside granted paths fail.
4. **Kernel network policy** — non-allowlisted egress blocked; allowlisted
   hosts reachable via the filtering proxy.
5. **Happy path** — allowed code runs and persists in ``output/``.

Configuration surfaces (additional probes):

* **Policy-derived** — ``timeout_seconds``, ``network_allowlist``, proxy egress.
* **``SandboxConfig``** — ``env_vars``, ``input_dir``, ``output_dir``,
  ``timeout_seconds``, ``network_enabled`` (unrestricted egress opt-in).
* **API helpers** — ``run_once``, ``get_session_status``.

Not exercised here (need a bespoke setup): ``include_system_paths=False``
(breaks normal Python without a self-contained interpreter tree), custom
``interpreter``, and ``run()`` with a non-Python shell command.

Requirements (Linux or macOS only — nono has no Windows support)::

    pip install "agt-sandbox[nono,policy]"
    # or, from a monorepo checkout:
    #   pip install -e agent-governance-python/agent-governance-toolkit-core
    #   pip install -e "agent-governance-python/agent-sandbox[nono]"

Run::

    python examples/quickstart/nono_sandbox_test.py
"""

from __future__ import annotations

import sys
import tempfile
from pathlib import Path

from agent_os.policies import PolicyDocument

from agent_sandbox import NonoSandboxProvider
from agent_sandbox.sandbox_provider import SandboxConfig, SessionStatus

POLICY_PATH = (
    Path(__file__).resolve().parent / "policies" / "nono_research_agent.yaml"
)

AGENT_ID = "nono-research-agent"


def _hr(title: str) -> None:
    print(f"\n{'=' * 70}\n{title}\n{'=' * 70}")


def main() -> int:
    provider = NonoSandboxProvider()
    if not provider.is_available():
        print(
            "nono is not available on this host. It requires Linux "
            "(kernel 5.13+ with Landlock) or macOS, with "
            "'pip install agt-sandbox[nono]'."
        )
        return 1

    policy = PolicyDocument.from_yaml(str(POLICY_PATH))
    print(f"Loaded policy '{policy.name}' v{policy.version}")
    print(f"  network_allowlist: {policy.network_allowlist}")
    print(f"  default action:    {policy.defaults.action}")
    print(f"  timeout_seconds:   {policy.defaults.timeout_seconds}")

    handle = provider.create_session(AGENT_ID, policy=policy)
    print(f"Session ready: {handle.session_id}")
    print(
        f"  get_session_status: "
        f"{provider.get_session_status(handle.agent_id, handle.session_id)}"
    )

    try:
        # 1. Happy path: allowed code, writes to persistent output/
        _hr("1. Allowed execution (writes to session output/)")
        execution = provider.execute_code(
            handle.agent_id,
            handle.session_id,
            "data = sum(range(100))\n"
            "open('result.txt', 'w').write(str(data))\n"
            "print(f'computed {data}, wrote result.txt')",
            context={"tool_name": "search_index"},
        )
        print(f"stdout:  {execution.result.stdout.strip()}")
        print(
            f"success: {execution.result.success}  "
            f"exit: {execution.result.exit_code}"
        )

        followup = provider.execute_code(
            handle.agent_id,
            handle.session_id,
            "print('previous run left:', open('result.txt').read())",
            context={"tool_name": "search_index"},
        )
        print(f"persisted: {followup.result.stdout.strip()}")

        # 2. Host-side policy gate: disallowed tool
        _hr("2. Policy gate — tool not in allowlist (denied pre-sandbox)")
        try:
            provider.execute_code(
                handle.agent_id,
                handle.session_id,
                "print('should never run')",
                context={"tool_name": "delete_everything"},
            )
            print("UNEXPECTED: execution was allowed")
        except PermissionError as exc:
            print(f"denied by policy: {exc}")

        # 3. Host-side policy gate: shell-out keyword
        _hr("3. Policy gate — 'subprocess' keyword (denied pre-sandbox)")
        try:
            provider.execute_code(
                handle.agent_id,
                handle.session_id,
                "# uses subprocess to shell out\nprint('hi')",
                context={"tool_name": "search_index"},
            )
            print("UNEXPECTED: execution was allowed")
        except PermissionError as exc:
            print(f"denied by policy: {exc}")

        # 4. Static AST scan: real subprocess call
        _hr("4. AST scan — real subprocess call is blocked")
        try:
            provider.execute_code(
                handle.agent_id,
                handle.session_id,
                "import os\nos.system('id')",
                context={"tool_name": "search_index"},
            )
            print("UNEXPECTED: execution was allowed")
        except Exception as exc:  # SandboxCodeViolation
            print(f"blocked by scanner: {type(exc).__name__}: {exc}")

        # 5. Kernel filesystem isolation
        _hr("5. Kernel FS isolation — reading /etc/shadow is blocked")
        fs = provider.execute_code(
            handle.agent_id,
            handle.session_id,
            "try:\n"
            "    print(open('/etc/shadow').read())\n"
            "except Exception as e:\n"
            "    print('blocked:', type(e).__name__)",
            context={"tool_name": "search_index"},
        )
        print(f"stdout:  {fs.result.stdout.strip()}")
        print(f"success: {fs.result.success}")

        # 6. Kernel network policy — blocked host
        _hr("6. Kernel network — egress to a non-allowlisted host is blocked")
        net = provider.execute_code(
            handle.agent_id,
            handle.session_id,
            "import socket\n"
            "try:\n"
            "    socket.create_connection(('1.1.1.1', 443), timeout=3)\n"
            "    print('CONNECTED (unexpected)')\n"
            "except Exception as e:\n"
            "    print('blocked:', type(e).__name__)",
            context={"tool_name": "search_index"},
        )
        print(f"stdout:  {net.result.stdout.strip()}")

        # 7. Allowlisted egress via policy network_allowlist + proxy
        _hr("7. Allowlisted egress — HTTPS to pypi.org (policy proxy)")
        allowed = provider.execute_code(
            handle.agent_id,
            handle.session_id,
            "from urllib.request import urlopen\n"
            "try:\n"
            "    with urlopen('https://pypi.org', timeout=10) as r:\n"
            "        print('status:', r.status)\n"
            "except Exception as e:\n"
            "    print('failed:', type(e).__name__, e)",
            context={"tool_name": "search_index"},
        )
        print(f"stdout:  {allowed.result.stdout.strip()}")
        print(f"success: {allowed.result.success}")

        # 8. NONO_CONTEXT env from execute_code context dict
        _hr("8. Execution context — NONO_CONTEXT JSON in child env")
        ctx = provider.execute_code(
            handle.agent_id,
            handle.session_id,
            "import json, os\n"
            "raw = os.environ.get('NONO_CONTEXT', '{}')\n"
            "print('tool:', json.loads(raw).get('tool_name'))",
            context={"tool_name": "fetch_arxiv", "run_tag": "quickstart"},
        )
        print(f"stdout:  {ctx.result.stdout.strip()}")
    finally:
        provider.destroy_session(handle.agent_id, handle.session_id)
        destroyed = provider.get_session_status(handle.agent_id, handle.session_id)
        _hr(
            f"Session destroyed — workspace and proxy cleaned up "
            f"(status={destroyed})"
        )
        if destroyed != SessionStatus.DESTROYED:
            print("UNEXPECTED: session status after destroy")

    # 9. SandboxConfig.env_vars
    _hr("9. SandboxConfig.env_vars — custom child environment")
    env_handle = provider.create_session(
        f"{AGENT_ID}-env",
        config=SandboxConfig(
            env_vars={"QUICKSTART_MARKER": "agt-nono"},
            network_enabled=False,
        ),
    )
    try:
        env_run = provider.execute_code(
            env_handle.agent_id,
            env_handle.session_id,
            "import os\n"
            "print(os.environ.get('QUICKSTART_MARKER', '<missing>'))",
        )
        print(f"stdout:  {env_run.result.stdout.strip()}")
    finally:
        provider.destroy_session(env_handle.agent_id, env_handle.session_id)

    # 10. SandboxConfig.input_dir — read-only mount
    _hr("10. SandboxConfig.input_dir — read-only host file visible in sandbox")
    with tempfile.TemporaryDirectory(prefix="nono-input-") as input_dir:
        input_path = Path(input_dir) / "seed.txt"
        input_path.write_text("hello from input_dir", encoding="utf-8")
        mount_handle = provider.create_session(
            f"{AGENT_ID}-mount",
            config=SandboxConfig(input_dir=input_dir, network_enabled=False),
        )
        try:
            mount_run = provider.execute_code(
                mount_handle.agent_id,
                mount_handle.session_id,
                f"print(open({str(input_path)!r}).read())",
            )
            print(f"stdout:  {mount_run.result.stdout.strip()}")
        finally:
            provider.destroy_session(mount_handle.agent_id, mount_handle.session_id)

    # 11. SandboxConfig.output_dir — extra read-write mount
    _hr("11. SandboxConfig.output_dir — write via absolute path to host mount")
    with tempfile.TemporaryDirectory(prefix="nono-out-") as custom_out:
        out_file = Path(custom_out) / "extra.txt"
        out_handle = provider.create_session(
            f"{AGENT_ID}-out",
            config=SandboxConfig(output_dir=custom_out, network_enabled=False),
        )
        try:
            out_run = provider.execute_code(
                out_handle.agent_id,
                out_handle.session_id,
                f"open({str(out_file)!r}, 'w').write('rw ok')\nprint('wrote')",
            )
            print(f"stdout:  {out_run.result.stdout.strip()}")
            print(f"on host: {out_file.read_text(encoding='utf-8')}")
        finally:
            provider.destroy_session(out_handle.agent_id, out_handle.session_id)

    # 12. SandboxConfig.timeout_seconds — wall-clock kill
    _hr("12. SandboxConfig.timeout_seconds — overrun is killed")
    timeout_run = provider.run_once(
        f"{AGENT_ID}-timeout",
        "import time\ntime.sleep(5)\nprint('finished (unexpected)')",
        config=SandboxConfig(timeout_seconds=1.0, network_enabled=False),
    )
    print(f"stdout:      {timeout_run.result.stdout.strip()!r}")
    print(f"killed:      {timeout_run.result.killed}")
    print(f"kill_reason: {timeout_run.result.kill_reason}")
    print(f"exit_code:   {timeout_run.result.exit_code}")

    # 13. SandboxConfig.network_enabled — unrestricted egress opt-in
    _hr("13. SandboxConfig.network_enabled — unrestricted egress to 1.1.1.1")
    open_net = provider.run_once(
        f"{AGENT_ID}-open-net",
        "import socket\n"
        "try:\n"
        "    socket.create_connection(('1.1.1.1', 443), timeout=5)\n"
        "    print('CONNECTED')\n"
        "except Exception as e:\n"
        "    print('failed:', type(e).__name__)",
        config=SandboxConfig(network_enabled=True),
    )
    print(f"stdout:  {open_net.result.stdout.strip()}")
    print(f"success: {open_net.result.success}")

    # 14. run_once — one-shot session (no manual destroy)
    _hr("14. run_once — ephemeral session cleaned up automatically")
    once = provider.run_once(
        f"{AGENT_ID}-once",
        "print('one-shot ok')",
        config=SandboxConfig(network_enabled=False),
    )
    print(f"stdout:  {once.result.stdout.strip()}")
    print(f"success: {once.result.success}")

    return 0


if __name__ == "__main__":
    sys.exit(main())
