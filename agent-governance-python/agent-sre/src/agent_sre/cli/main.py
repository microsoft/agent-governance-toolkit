# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""
agent-sre CLI — command-line interface for Agent SRE.

Usage:
    python -m agent_sre.cli slo status
    python -m agent_sre.cli slo list
    python -m agent_sre.cli cost summary
    python -m agent_sre.cli version
"""

import argparse
import json
from typing import Any


def cli(args: list[str] | None = None) -> int:
    """Main CLI entry point. Returns exit code."""
    parser = argparse.ArgumentParser(
        prog="agent-sre",
        description="Reliability Engineering for AI Agent Systems",
    )
    subparsers = parser.add_subparsers(dest="command")

    # slo subcommand
    slo_parser = subparsers.add_parser("slo", help="SLO management")
    slo_sub = slo_parser.add_subparsers(dest="slo_command")
    slo_sub.add_parser("status", help="Show SLO health status")
    slo_sub.add_parser("list", help="List all SLOs")

    # cost subcommand
    cost_parser = subparsers.add_parser("cost", help="Cost management")
    cost_sub = cost_parser.add_subparsers(dest="cost_command")
    cost_sub.add_parser("summary", help="Show cost summary")

    # version subcommand
    subparsers.add_parser("version", help="Show version")

    # info subcommand
    subparsers.add_parser("info", help="Show system info")

    parsed = parser.parse_args(args)

    if parsed.command == "version":
        print("agent-sre 0.1.0")
        return 0

    if parsed.command == "info":
        info: dict[str, Any] = {
            "name": "agent-sre",
            "version": "0.1.0",
            "engines": ["slo", "cost", "chaos", "delivery", "replay", "incidents"],
            "integrations": [
                "agent_os", "agent_mesh", "otel", "langchain", "llamaindex",
                "langfuse", "arize", "braintrust", "helicone", "datadog",
                "langsmith", "mcp", "prometheus",
            ],
            "adapters": ["langgraph", "crewai", "autogen", "openai_agents",
                         "semantic_kernel", "dify"],
        }
        print(json.dumps(info, indent=2))
        return 0

    if parsed.command == "slo":
        if parsed.slo_command == "status":
            print("No SLOs configured. Use the Python API to register SLOs.")
            return 0
        if parsed.slo_command == "list":
            print("No SLOs registered.")
            return 0
        slo_parser.print_help()
        return 1

    if parsed.command == "cost":
        if parsed.cost_command == "summary":
            print("No cost data available. Use the Python API to record costs.")
            return 0
        cost_parser.print_help()
        return 1

    parser.print_help()
    return 1
