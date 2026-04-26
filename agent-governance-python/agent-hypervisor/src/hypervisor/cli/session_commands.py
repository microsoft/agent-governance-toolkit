# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""Session inspection CLI commands."""

from __future__ import annotations

import argparse
import sys
from typing import Any

from hypervisor.cli.formatters import format_output
from hypervisor.core import Hypervisor, ManagedSession
from hypervisor.security.kill_switch import KillReason, KillSwitch


def _build_session_summary(managed: ManagedSession) -> dict[str, Any]:
    """Build a summary dict for a single session."""
    sso = managed.sso
    return {
        "session_id": sso.session_id,
        "state": sso.state.value,
        "participants": sso.participant_count,
        "consistency": sso.consistency_mode.value,
        "created_at": sso.created_at.isoformat(),
    }


def _build_session_detail(managed: ManagedSession) -> dict[str, Any]:
    """Build a detailed inspection dict for a session."""
    sso = managed.sso

    participants = [
        {
            "agent_did": p.agent_did,
            "ring": p.ring.value,
            "eff_score": round(p.eff_score, 4),
            "sigma_raw": round(p.sigma_raw, 4),
            "is_active": p.is_active,
        }
        for p in sso.participants
    ]

    # Saga steps
    saga_steps: list[dict[str, Any]] = []
    for saga in managed.saga._sagas.values():
        for step in saga.steps:
            saga_steps.append({
                "saga_id": saga.saga_id,
                "step_id": step.step_id,
                "action_id": step.action_id,
                "agent_did": step.agent_did,
                "state": step.state.value,
                "error": step.error,
            })

    # Audit deltas
    audit_entries = [
        {
            "delta_id": d.delta_id,
            "turn_id": d.turn_id,
            "agent_did": d.agent_did,
            "timestamp": d.timestamp.isoformat(),
            "changes": len(d.changes),
        }
        for d in managed.delta_engine.deltas
    ]

    # Resource usage
    resource_usage = {
        "vfs_files": sso.vfs.file_count,
        "vfs_snapshots": sso.vfs.snapshot_count,
        "audit_turns": managed.delta_engine.turn_count,
    }

    return {
        "session_id": sso.session_id,
        "state": sso.state.value,
        "consistency_mode": sso.consistency_mode.value,
        "created_at": sso.created_at.isoformat(),
        "terminated_at": sso.terminated_at.isoformat() if sso.terminated_at else None,
        "participants": participants,
        "saga_steps": saga_steps,
        "resource_usage": resource_usage,
        "audit_log": audit_entries,
    }


def cmd_list(hv: Hypervisor, fmt: str) -> str:
    """List all active sessions."""
    sessions = hv.active_sessions
    if not sessions:
        return "No active sessions."
    rows = [_build_session_summary(m) for m in sessions]
    return format_output(rows, fmt)


def cmd_inspect(hv: Hypervisor, session_id: str, fmt: str) -> str:
    """Inspect a single session in detail."""
    managed = hv.get_session(session_id)
    if managed is None:
        return f"Error: session '{session_id}' not found."
    detail = _build_session_detail(managed)
    return format_output(detail, fmt)


def cmd_kill(
    hv: Hypervisor,
    session_id: str,
    fmt: str,
    kill_switch: KillSwitch | None = None,
) -> str:
    """Trigger kill switch on all agents in a session."""
    managed = hv.get_session(session_id)
    if managed is None:
        return f"Error: session '{session_id}' not found."

    ks = kill_switch or KillSwitch()
    results = []
    for p in managed.sso.participants:
        result = ks.kill(
            agent_did=p.agent_did,
            session_id=session_id,
            reason=KillReason.MANUAL,
            details="Killed via CLI",
        )
        managed.sso.leave(p.agent_did)
        results.append({
            "kill_id": result.kill_id,
            "agent_did": result.agent_did,
            "reason": result.reason.value,
            "timestamp": result.timestamp.isoformat(),
        })

    return format_output(results, fmt)


def build_parser(
    parent: argparse._SubParsersAction | None = None,
) -> argparse.ArgumentParser:
    """Build the 'session' sub-command parser."""
    if parent is not None:
        parser = parent.add_parser("session", help="Inspect session state")
    else:
        parser = argparse.ArgumentParser(prog="hypervisor session")

    parser.add_argument(
        "--format",
        choices=["table", "json", "yaml"],
        default="table",
        dest="output_format",
        help="Output format (default: table)",
    )

    sub = parser.add_subparsers(dest="session_command")

    sub.add_parser("list", help="List all active sessions")

    inspect_p = sub.add_parser("inspect", help="Show detailed session state")
    inspect_p.add_argument("session_id", help="Session ID to inspect")

    kill_p = sub.add_parser("kill", help="Trigger kill switch on a session")
    kill_p.add_argument("session_id", help="Session ID to kill")

    return parser


def dispatch(
    args: argparse.Namespace,
    hv: Hypervisor,
    kill_switch: KillSwitch | None = None,
) -> str:
    """Dispatch a parsed session command to the appropriate handler."""
    fmt = getattr(args, "output_format", "table")
    cmd = args.session_command

    if cmd == "list":
        return cmd_list(hv, fmt)
    elif cmd == "inspect":
        return cmd_inspect(hv, args.session_id, fmt)
    elif cmd == "kill":
        return cmd_kill(hv, args.session_id, fmt, kill_switch)
    else:
        return "Error: specify a sub-command (list, inspect, kill)."


def main(argv: list[str] | None = None) -> None:
    """Entry point for the CLI."""
    top = argparse.ArgumentParser(prog="hypervisor")
    sub = top.add_subparsers(dest="command")
    build_parser(sub)

    args = top.parse_args(argv)
    if args.command != "session" or not args.session_command:
        top.print_help()
        sys.exit(1)

    # In standalone mode, create an empty hypervisor (useful for testing the parser).
    hv = Hypervisor()
    output = dispatch(args, hv)
    print(output)
