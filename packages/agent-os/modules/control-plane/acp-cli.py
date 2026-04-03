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
import re
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
    agent_create.add_argument("--json", action="store_true", help="Output in JSON format")
    
    agent_list = agent_sub.add_parser("list", help="List all agents")
    agent_list.add_argument("--json", action="store_true", help="Output in JSON format")
    
    agent_inspect = agent_sub.add_parser("inspect", help="Inspect an agent")
    agent_inspect.add_argument("agent_id", help="Agent identifier")
    agent_inspect.add_argument("--json", action="store_true", help="Output in JSON format")
    
    # Policy commands
    policy_parser = subparsers.add_parser("policy", help="Manage policies")
    policy_sub = policy_parser.add_subparsers(dest="policy_command")
    
    policy_add = policy_sub.add_parser("add", help="Add a policy rule")
    policy_add.add_argument("name", help="Policy name")
    policy_add.add_argument("--severity", type=float, default=1.0, help="Severity (0.0-1.0)")
    policy_add.add_argument("--description", help="Policy description")
    policy_add.add_argument("--json", action="store_true", help="Output in JSON format")
    
    policy_sub.add_parser("list", help="List all policies").add_argument("--json", action="store_true", help="Output in JSON format")
    
    # Workflow commands
    workflow_parser = subparsers.add_parser("workflow", help="Manage workflows")
    workflow_sub = workflow_parser.add_subparsers(dest="workflow_command")
    
    workflow_create = workflow_sub.add_parser("create", help="Create a workflow")
    workflow_create.add_argument("name", help="Workflow name")
    workflow_create.add_argument("--type", default="sequential", help="Workflow type")
    workflow_create.add_argument("--json", action="store_true", help="Output in JSON format")
    
    workflow_run = workflow_sub.add_parser("run", help="Run a workflow")
    workflow_run.add_argument("workflow_id", help="Workflow identifier")
    workflow_run.add_argument("--input", help="JSON input file")
    workflow_run.add_argument("--json", action="store_true", help="Output in JSON format")
    
    workflow_sub.add_parser("list", help="List all workflows").add_argument("--json", action="store_true", help="Output in JSON format")
    
    # Audit commands
    audit_parser = subparsers.add_parser("audit", help="View audit logs")
    audit_sub = audit_parser.add_subparsers(dest="audit_command")
    
    audit_show = audit_sub.add_parser("show", help="Show audit log")
    audit_show.add_argument("--limit", type=int, help="Limit number of entries")
    audit_show.add_argument("--format", default="text", choices=["text", "json"], help="Output format")
    audit_show.add_argument("--json", action="store_true", help="Output in JSON format")
    
    # Benchmark commands
    benchmark_parser = subparsers.add_parser("benchmark", help="Run benchmarks")
    benchmark_sub = benchmark_parser.add_subparsers(dest="benchmark_command")
    
    benchmark_run = benchmark_sub.add_parser("run", help="Run safety benchmark")
    benchmark_run.add_argument("--json", action="store_true", help="Output in JSON format")
    
    benchmark_report = benchmark_sub.add_parser("report", help="Show benchmark report")
    benchmark_report.add_argument("--json", action="store_true", help="Output in JSON format")
    
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
    
    try:
        # Standardize and strictly validate agent_id
        agent_id = args.agent_id.lower().strip()
        if not re.fullmatch(r"^[a-zA-Z0-9]+(?:-[a-zA-Z0-9]+)*$", agent_id) or len(agent_id) > 64:
            raise ValueError(f"Invalid agent_id format: {agent_id}")
            
        agent = control_plane.create_agent(agent_id, permissions)
        
        if getattr(args, "json", False):
            print(json.dumps({
                "status": "success",
                "agent_id": str(agent_id),
                "session_id": str(agent.session_id),
                "permissions_count": int(len(permissions))
            }, indent=2))
        else:
            print(f"✓ Created agent: {args.agent_id}")
            print(f"  Session: {agent.session_id}")
            print(f"  Permissions: {len(permissions)} action types")
    except (ValueError, KeyError, PermissionError) as e:
        err_msg = "An error occurred during agent creation due to invalid input or permissions."
        if getattr(args, "json", False):
            print(json.dumps({"status": "error", "message": err_msg, "type": "ValidationError"}, indent=2))
        else:
            print(f"Error: {err_msg}")
    except Exception:
        err_msg = "An unexpected error occurred during agent creation."
        if getattr(args, "json", False):
            print(json.dumps({"status": "error", "message": err_msg, "type": "InternalError"}, indent=2))
        else:
            print(f"Error: {err_msg}")


def cmd_agent_list(args, control_plane):
    """List all agents"""
    if getattr(args, "json", False):
        print(json.dumps([], indent=2))
    else:
        print("Registered Agents:")
        print("  (Implementation would list agents from control plane)")


def cmd_agent_inspect(args, control_plane):
    """Inspect an agent"""
    if getattr(args, "json", False):
        print(json.dumps({"agent_id": args.agent_id, "status": "active"}, indent=2))
    else:
        print(f"Agent: {args.agent_id}")
        print("  (Implementation would show agent details)")


def cmd_policy_list(args, control_plane):
    """List policies"""
    if getattr(args, "json", False):
        print(json.dumps([], indent=2))
    else:
        print("Active Policies:")
        print("  (Implementation would list policies from policy engine)")


def cmd_audit_show(args, control_plane):
    """Show audit log"""
    try:
        recorder = control_plane.flight_recorder
        events = recorder.get_recent_events(limit=args.limit or 10)
        
        if args.format == "json" or getattr(args, "json", False):
            # Strict sanitization to prevent information leakage
            allowed_keys = {"timestamp", "event_type", "agent_id", "status"}
            sanitized_events = []
            for event in events:
                # Ensure all values are strings and keys are whitelisted
                item = {str(k): str(v) for k, v in event.items() if k in allowed_keys}
                if all(k in item for k in allowed_keys):
                    sanitized_events.append(item)
            print(json.dumps(sanitized_events, indent=2))
        else:
            print(f"Recent Audit Events (last {len(events)}):")
            for event in events:
                print(f"  [{event.get('timestamp')}] {event.get('event_type')}: {event.get('agent_id')}")
    except Exception as e:
        is_known = isinstance(e, (ValueError, PermissionError))
        msg = "A validation or permission error occurred." if is_known else "Failed to retrieve audit logs"
        if getattr(args, "json", False):
            print(json.dumps({"error": msg, "type": "ValidationError" if is_known else "InternalError"}, indent=2))
        else:
            print(f"Error: {msg}")


def cmd_benchmark_run(args):
    """Run safety benchmark"""
    if getattr(args, "json", False):
        print(json.dumps({"status": "running", "benchmark": "safety"}, indent=2))
    else:
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
        err_msg = "Required dependency 'agent_control_plane' is missing."
        if getattr(args, "json", False):
            print(json.dumps({"status": "error", "message": err_msg, "type": "MissingDependency"}, indent=2))
        else:
            print(f"Error: {err_msg}")
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
            if getattr(args, "json", False):
                print(json.dumps({"error": f"Command not implemented: {args.command}"}, indent=2))
            else:
                print(f"Command not implemented: {args.command}")
            return 1
            
    except Exception as e:
        is_known = isinstance(e, (ValueError, PermissionError, FileNotFoundError))
        msg = "An error occurred matching input validation or file permission." if is_known else "An internal error occurred"
        if getattr(args, "json", False):
            print(json.dumps({"error": msg, "type": "ValidationError" if is_known else "InternalError"}, indent=2))
        else:
            print(f"Error: {msg}")
        return 1
    
    return 0


if __name__ == "__main__":
    sys.exit(main())
