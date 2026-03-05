#!/usr/bin/env python3
# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""
Agent Control Plane CLI

Command-line interface for managing agents, policies, and workflows.

Usage:
    acp-cli agent create <agent_id> [--role ROLE]
    acp-cli agent list
    acp-cli agent inspect <agent_id>
    acp-cli policy add <name> [--severity LEVEL]
    acp-cli policy list
    acp-cli workflow create <name> [--type TYPE]
    acp-cli workflow run <workflow_id>
    acp-cli audit show [--limit N]
    acp-cli benchmark run
"""

import sys
import argparse
import json
from typing import Optional
from pathlib import Path


def create_parser() -> argparse.ArgumentParser:
    """Create the CLI argument parser"""
    parser = argparse.ArgumentParser(
        prog="acp-cli",
        description="Agent Control Plane Command Line Interface"
    )
    
    subparsers = parser.add_subparsers(dest="command", help="Command to execute")
    
    # Agent commands
    agent_parser = subparsers.add_parser("agent", help="Manage agents")
    agent_sub = agent_parser.add_subparsers(dest="agent_command")
    
    agent_create = agent_sub.add_parser("create", help="Create a new agent")
    agent_create.add_argument("agent_id", help="Agent identifier")
    agent_create.add_argument("--role", default="worker", help="Agent role")
    agent_create.add_argument("--permissions", help="JSON file with permissions")
    
    agent_sub.add_parser("list", help="List all agents")
    
    agent_inspect = agent_sub.add_parser("inspect", help="Inspect an agent")
    agent_inspect.add_argument("agent_id", help="Agent identifier")
    
    # Policy commands
    policy_parser = subparsers.add_parser("policy", help="Manage policies")
    policy_sub = policy_parser.add_subparsers(dest="policy_command")
    
    policy_add = policy_sub.add_parser("add", help="Add a policy rule")
    policy_add.add_argument("name", help="Policy name")
    policy_add.add_argument("--severity", type=float, default=1.0, help="Severity (0.0-1.0)")
    policy_add.add_argument("--description", help="Policy description")
    
    policy_sub.add_parser("list", help="List all policies")
    
    # Workflow commands
    workflow_parser = subparsers.add_parser("workflow", help="Manage workflows")
    workflow_sub = workflow_parser.add_subparsers(dest="workflow_command")
    
    workflow_create = workflow_sub.add_parser("create", help="Create a workflow")
    workflow_create.add_argument("name", help="Workflow name")
    workflow_create.add_argument("--type", default="sequential", help="Workflow type")
    
    workflow_run = workflow_sub.add_parser("run", help="Run a workflow")
    workflow_run.add_argument("workflow_id", help="Workflow identifier")
    workflow_run.add_argument("--input", help="JSON input file")
    
    workflow_sub.add_parser("list", help="List all workflows")
    
    # Audit commands
    audit_parser = subparsers.add_parser("audit", help="View audit logs")
    audit_sub = audit_parser.add_subparsers(dest="audit_command")
    
    audit_show = audit_sub.add_parser("show", help="Show audit log")
    audit_show.add_argument("--limit", type=int, help="Limit number of entries")
    audit_show.add_argument("--format", default="text", choices=["text", "json"], help="Output format")
    
    # Benchmark commands
    benchmark_parser = subparsers.add_parser("benchmark", help="Run benchmarks")
    benchmark_sub = benchmark_parser.add_subparsers(dest="benchmark_command")
    
    benchmark_sub.add_parser("run", help="Run safety benchmark")
    benchmark_sub.add_parser("report", help="Show benchmark report")
    
    return parser


def cmd_agent_create(args, control_plane):
    """Create a new agent"""
    from agent_control_plane import PermissionLevel, ActionType
    
    permissions = {}
    if args.permissions:
        with open(args.permissions) as f:
            perm_data = json.load(f)
            # Convert string action types to enums
            for action_str, level_str in perm_data.items():
                action = ActionType[action_str]
                level = PermissionLevel[level_str]
                permissions[action] = level
    else:
        # Default read-only permissions
        permissions = {
            ActionType.FILE_READ: PermissionLevel.READ_ONLY,
            ActionType.API_CALL: PermissionLevel.READ_ONLY,
        }
    
    agent = control_plane.create_agent(args.agent_id, permissions)
    print(f"✓ Created agent: {args.agent_id}")
    print(f"  Session: {agent.session_id}")
    print(f"  Permissions: {len(permissions)} action types")


def cmd_agent_list(args, control_plane):
    """List all agents"""
    # This would query the control plane's agent registry
    print("Registered Agents:")
    print("  (Implementation would list agents from control plane)")


def cmd_agent_inspect(args, control_plane):
    """Inspect an agent"""
    print(f"Agent: {args.agent_id}")
    print("  (Implementation would show agent details)")


def cmd_policy_list(args, control_plane):
    """List policies"""
    print("Active Policies:")
    print("  (Implementation would list policies from policy engine)")


def cmd_audit_show(args, control_plane):
    """Show audit log"""
    try:
        recorder = control_plane.flight_recorder
        events = recorder.get_recent_events(limit=args.limit or 10)
        
        if args.format == "json":
            print(json.dumps(events, indent=2))
        else:
            print(f"Recent Audit Events (last {len(events)}):")
            for event in events:
                print(f"  [{event.get('timestamp')}] {event.get('event_type')}: {event.get('agent_id')}")
    except Exception as e:
        print(f"Error: {e}")


def cmd_benchmark_run(args):
    """Run safety benchmark"""
    print("Running safety benchmark...")
    print("This would execute benchmark/red_team_dataset.py")
    print("(Implementation in progress)")


def main():
    """Main CLI entry point"""
    parser = create_parser()
    args = parser.parse_args()
    
    if not args.command:
        parser.print_help()
        return 1
    
    # Initialize control plane
    try:
        from agent_control_plane import AgentControlPlane
        control_plane = AgentControlPlane()
    except ImportError:
        print("Error: agent_control_plane package not installed")
        print("Install with: pip install -e .")
        return 1
    
    # Route to appropriate command handler
    try:
        if args.command == "agent":
            if args.agent_command == "create":
                cmd_agent_create(args, control_plane)
            elif args.agent_command == "list":
                cmd_agent_list(args, control_plane)
            elif args.agent_command == "inspect":
                cmd_agent_inspect(args, control_plane)
        
        elif args.command == "policy":
            if args.policy_command == "list":
                cmd_policy_list(args, control_plane)
        
        elif args.command == "audit":
            if args.audit_command == "show":
                cmd_audit_show(args, control_plane)
        
        elif args.command == "benchmark":
            if args.benchmark_command == "run":
                cmd_benchmark_run(args)
        
        else:
            print(f"Command not implemented: {args.command}")
            return 1
            
    except Exception as e:
        print(f"Error: {e}")
        return 1
    
    return 0


if __name__ == "__main__":
    sys.exit(main())
