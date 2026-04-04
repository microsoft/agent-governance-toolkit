# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""``agentos init`` command implementation."""

from __future__ import annotations

import argparse
import json
from pathlib import Path

from .output import (
    AVAILABLE_POLICIES,
    Colors,
    format_error,
    get_output_format,
)


def cmd_init(args: argparse.Namespace) -> int:
    """Initialize .agents/ directory with Agent OS support."""
    root = Path(args.path or ".")
    agents_dir = root / ".agents"
    output_format = get_output_format(args)

    if agents_dir.exists() and not args.force:
        if output_format == "json":
            print(json.dumps({
                "status": "error",
                "message": f"{agents_dir} already exists",
                "suggestion": "Use --force to overwrite"
            }, indent=2))
        else:
            print(format_error(
                f"{agents_dir} already exists",
                suggestion="Use --force to overwrite: agentos init --force",
                docs_path="getting-started.md",
            ))
        return 1

    agents_dir.mkdir(parents=True, exist_ok=True)

    # Create agents.md (OpenAI/Anthropic standard)
    agents_md = agents_dir / "agents.md"
    agents_md.write_text("""# Agent Configuration

You are an AI agent governed by Agent OS kernel.

## Capabilities

You can:
- Query databases (read-only by default)
- Call approved APIs
- Generate reports

## Constraints

You must:
- Follow all policies in security.md
- Request approval for write operations
- Log all actions to the flight recorder

## Context

This agent is part of the Agent OS ecosystem.
For more information: https://github.com/microsoft/agent-governance-toolkit
""")

    # Create security.md (Agent OS extension)
    security_md = agents_dir / "security.md"
    policy_template = args.template or "strict"

    policies = {
        "strict": {
            "mode": "strict",
            "signals": ["SIGSTOP", "SIGKILL", "SIGINT"],
            "rules": [
                {"action": "database_query", "mode": "read_only"},
                {"action": "file_write", "requires_approval": True},
                {"action": "api_call", "rate_limit": "100/hour"},
                {"action": "send_email", "requires_approval": True},
            ]
        },
        "permissive": {
            "mode": "permissive",
            "signals": ["SIGSTOP", "SIGKILL"],
            "rules": [
                {"action": "*", "effect": "allow"},
            ]
        },
        "audit": {
            "mode": "audit",
            "signals": ["SIGSTOP"],
            "rules": [
                {"action": "*", "effect": "allow", "log": True},
            ]
        }
    }

    policy = policies.get(policy_template, policies["strict"])

    security_content = f"""# Agent OS Security Configuration

kernel:
  version: "1.0"
  mode: {policy["mode"]}

signals:
"""
    for s in policy["signals"]:
        security_content += f"  - {s}\n"

    security_content += "\npolicies:\n"
    for r in policy["rules"]:
        security_content += f'  - action: {r["action"]}\n'
        if "mode" in r:
            security_content += f'    mode: {r["mode"]}\n'
        if r.get("requires_approval"):
            security_content += '    requires_approval: true\n'
        if "rate_limit" in r:
            security_content += f'    rate_limit: "{r["rate_limit"]}"\n'
        if "effect" in r:
            security_content += f'    effect: {r["effect"]}\n'

    security_content += """
observability:
  metrics: true
  traces: true
  flight_recorder: true

# For more options, see:
# https://github.com/microsoft/agent-governance-toolkit/blob/main/docs/security-spec.md
"""

    security_md.write_text(security_content)

    if output_format == "json":
        print(json.dumps({
            "status": "success",
            "directory": str(agents_dir),
            "template": policy_template,
            "files": ["agents.md", "security.md"]
        }, indent=2))
    else:
        print(f"Initialized Agent OS in {agents_dir}")
        print("  - agents.md: Agent instructions (OpenAI/Anthropic standard)")
        print("  - security.md: Kernel policies (Agent OS extension)")
        print(f"  - Template: {policy_template}")
        print()
        print("Next steps:")
        print("  1. Edit .agents/agents.md with your agent's capabilities")
        print("  2. Customize .agents/security.md policies")
        print("  3. Run: agentos secure --verify")

    return 0
