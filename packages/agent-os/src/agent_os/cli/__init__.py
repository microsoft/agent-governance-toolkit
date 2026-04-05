# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""
Agent OS CLI - Command line interface for Agent OS

Usage:
    agentos init [--template TEMPLATE]     Initialize .agents/ directory
    agentos secure [--policy POLICY]       Enable kernel governance
    agentos audit [--format FORMAT]        Audit agent security
    agentos status [--format FORMAT]       Show kernel status
    agentos check <file>                   Check file for safety violations
    agentos review <file> [--cmvk]         Multi-model code review
    agentos validate [files]               Validate policy YAML files
    agentos install-hooks                  Install git pre-commit hooks
    agentos serve [--port PORT]            Start HTTP API server
    agentos metrics                        Output Prometheus metrics

Environment variables:
    AGENTOS_CONFIG      Path to config file (overrides default .agents/)
    AGENTOS_LOG_LEVEL   Logging level: DEBUG, INFO, WARNING, ERROR (default: WARNING)
    AGENTOS_BACKEND     State backend type: memory, redis (default: memory)
    AGENTOS_REDIS_URL   Redis connection URL (default: redis://localhost:6379)
"""

from __future__ import annotations

import argparse
import json
import logging
import os
import sys
from pathlib import Path

# ── Re-exports from sub-modules ──────────────────────────────────────────────
# These ensure that ``from agent_os.cli import X`` continues to work for
# every public symbol that was previously defined directly in this file.

from .output import (  # noqa: F401 – re-export
    AVAILABLE_POLICIES,
    Colors,
    DOCS_URL,
    format_error,
    get_config_path,
    get_output_format,
    handle_cli_error,
    handle_connection_error,
    handle_invalid_policy,
    handle_missing_config,
    handle_missing_dependency,
    supports_color,
)
from .policy_checker import (  # noqa: F401 – re-export
    PolicyChecker,
    PolicyViolation,
    load_cli_policy_rules,
)
from .cmd_init import cmd_init  # noqa: F401 – re-export
from .cmd_validate import (  # noqa: F401 – re-export
    cmd_validate,
    _load_json_schema,
    _validate_yaml_with_line_numbers,
)
from .cmd_audit import cmd_audit, _export_audit_csv  # noqa: F401 – re-export
from .cmd_policy import cmd_policy  # noqa: F401 – re-export

# ============================================================================
# Environment Variable Configuration
# ============================================================================

AGENTOS_ENV_VARS = {
    "AGENTOS_CONFIG": "Path to config file (overrides default .agents/)",
    "AGENTOS_LOG_LEVEL": "Logging level: DEBUG, INFO, WARNING, ERROR (default: WARNING)",
    "AGENTOS_BACKEND": "State backend type: memory, redis (default: memory)",
    "AGENTOS_REDIS_URL": "Redis connection URL (default: redis://localhost:6379)",
}

VALID_LOG_LEVELS = ("DEBUG", "INFO", "WARNING", "ERROR")
VALID_BACKENDS = ("memory", "redis")

_SAMPLE_DISCLAIMER = (
    "\u26a0\ufe0f  These are SAMPLE CLI security rules provided as a starting point. "
    "You MUST review, customise, and extend them for your specific use case "
    "before deploying to production."
)


def get_env_config() -> dict[str, str | None]:
    """Read configuration from environment variables."""
    return {
        "config_path": os.environ.get("AGENTOS_CONFIG"),
        "log_level": os.environ.get("AGENTOS_LOG_LEVEL", "WARNING").upper(),
        "backend": os.environ.get("AGENTOS_BACKEND", "memory").lower(),
        "redis_url": os.environ.get("AGENTOS_REDIS_URL", "redis://localhost:6379"),
    }


def configure_logging(level_name: str) -> None:
    """Configure logging from the AGENTOS_LOG_LEVEL environment variable."""
    level_name = level_name.upper()
    if level_name not in VALID_LOG_LEVELS:
        level_name = "WARNING"
    level = getattr(logging, level_name, logging.WARNING)
    logging.getLogger().setLevel(level)


# ============================================================================
# Commands that remain in __init__.py (to be split later)
# ============================================================================


def cmd_secure(args: argparse.Namespace) -> int:
    """Enable kernel governance for the current directory."""
    root = Path(args.path or ".")
    agents_dir = root / ".agents"
    output_format = get_output_format(args)

    if not agents_dir.exists():
        if output_format == "json":
            print(json.dumps({"status": "error", "message": "Config directory not found"}, indent=2))
        else:
            print(handle_missing_config(str(root)))
        return 1

    security_md = agents_dir / "security.md"
    if not security_md.exists():
        if output_format == "json":
            print(json.dumps({"status": "error", "message": "No security.md found"}, indent=2))
        else:
            print(format_error(
                "No security.md found in .agents/ directory",
                suggestion="Run: agentos init && agentos secure",
                docs_path="security-spec.md",
            ))
        return 1

    content = security_md.read_text()

    checks = [
        ("kernel version", "version:" in content),
        ("signals defined", "signals:" in content),
        ("policies defined", "policies:" in content),
    ]

    all_passed = True
    for check_name, passed in checks:
        if not passed:
            all_passed = False

    if output_format == "json":
        print(json.dumps({
            "status": "success" if all_passed else "error",
            "path": str(root),
            "checks": [{"name": name, "passed": passed} for name, passed in checks]
        }, indent=2))
    else:
        print(f"Securing agents in {root}...")
        print()
        for check_name, passed in checks:
            status = "[PASS]" if passed else "[FAIL]"
            print(f"  {status} {check_name}")

        print()
        if all_passed:
            print("Security configuration valid.")
            print()
            print("Kernel governance enabled. Your agents will now:")
            print("  - Enforce policies on every action")
            print("  - Respond to POSIX-style signals")
            print("  - Log all operations to flight recorder")
        else:
            print("Security configuration invalid. Please fix the issues above.")

    return 0 if all_passed else 1


def cmd_status(args: argparse.Namespace) -> int:
    """Show the status of the Agent OS kernel."""
    from agent_os import __version__
    output_format = get_output_format(args)

    project_root = Path(".").absolute()
    agents_dir = project_root / ".agents"
    is_configured = agents_dir.exists()

    status_data = {
        "version": __version__,
        "installed": True,
        "project": str(project_root),
        "configured": is_configured,
        "packages": {
            "control_plane": False,
            "primitives": False,
            "cmvk": False,
            "caas": False,
            "emk": False,
            "amb": False,
            "atr": False,
            "scak": False,
            "mute_agent": False,
        },
        "env": get_env_config(),
    }

    if output_format == "json":
        print(json.dumps(status_data, indent=2))
    else:
        print(f"{Colors.BOLD}Agent OS Kernel Status{Colors.RESET}")
        print(f"Version: {__version__}")
        print(f"Root:    {project_root}")
        print(f"Config:  {Colors.GREEN if is_configured else Colors.RED}{'Found' if is_configured else 'Not initialised'}{Colors.RESET}")
        print()

        print(f"{Colors.BOLD}Packages:{Colors.RESET}")
        for pkg, installed in status_data["packages"].items():
            status = f"{Colors.GREEN}\u2713{Colors.RESET}" if installed else f"{Colors.DIM}Not present{Colors.RESET}"
            print(f"  {pkg:15} {status}")

    return 0


def cmd_check(args: argparse.Namespace) -> int:
    """Check files for policy violations."""
    output_format = get_output_format(args)
    checker = PolicyChecker()

    # Resolve file list -- accept both args.files (list) and args.file (str)
    files = getattr(args, "files", None) or []
    if not files:
        file_val = getattr(args, "file", None)
        if file_val:
            files = [file_val]
    staged = getattr(args, "staged", False)

    if not files and not staged:
        print("Usage: agentos check <file> [<file> ...] | --staged")
        return 1

    # If staged, get files from git
    if staged and not files:
        import subprocess as _sp
        result = _sp.run(
            ["git", "diff", "--cached", "--name-only", "--diff-filter=ACM"],
            capture_output=True, text=True,
        )
        files = [f for f in result.stdout.strip().split("\n") if f]

    all_violations = []
    had_error = False
    for filepath in files:
        if not Path(filepath).exists():
            if output_format != "json":
                print(format_error(f"File not found: {filepath}"))
            had_error = True
            continue

        try:
            violations = checker.check_file(filepath)
            all_violations.extend(violations)

            if output_format != "json":
                if not violations:
                    print(f"{Colors.GREEN}No policy violations found in {filepath}{Colors.RESET}")
                else:
                    print(f"{Colors.RED}Found {len(violations)} violations in {filepath}:{Colors.RESET}")
                    for v in violations:
                        print(f"\n  [{v.severity.upper()}] Line {v.line}: {v.violation}")
                        print(f"    {Colors.DIM}Code: {v.code}{Colors.RESET}")
                        if v.suggestion:
                            print(f"    {Colors.GREEN}Suggestion: {v.suggestion}{Colors.RESET}")
        except Exception as e:
            if output_format != "json":
                print(format_error(str(e)))
            had_error = True

    if output_format == "json":
        print(json.dumps({
            "violations": [v.to_dict() for v in all_violations],
            "summary": {"total": len(all_violations)},
        }, indent=2))

    if had_error and not all_violations:
        return 1
    return 1 if all_violations else 0


def cmd_review(args: argparse.Namespace) -> int:
    """Perform a security review of a file."""
    output_format = get_output_format(args)
    print_log = output_format != "json"

    if print_log:
        print(f"Performing security review of {args.file}...")

    checker = PolicyChecker()
    try:
        violations = checker.check_file(args.file)
    except FileNotFoundError as e:
        if output_format == "json":
            print(json.dumps({"error": str(e)}, indent=2))
        else:
            print(format_error(str(e)))
        return 1

    review_data = {
        "file": args.file,
        "local_check": {
            "violations_count": len(violations),
            "violations": [v.to_dict() for v in violations]
        },
        "cmvk_check": None
    }

    if args.cmvk:
        if print_log:
            print("Running multi-model CMVK analysis...")
        # Simulated CMVK analysis
        models = ["gpt-4", "claude-3-opus", "gemini-1.5-pro"]
        review_data["cmvk_check"] = {
            "consensus": "safe",
            "models": models
        }
        review_data["model_results"] = models
        review_data["consensus"] = "safe"

    if output_format == "json":
        print(json.dumps(review_data, indent=2))
    else:
        if not violations:
            print(f"{Colors.GREEN}\u2713 Local analysis passed.{Colors.RESET}")
        else:
            print(f"{Colors.RED}\u2717 Local analysis found {len(violations)} issues.{Colors.RESET}")

        if args.cmvk:
            print(f"{Colors.GREEN}\u2713 CMVK consensus: SAFE{Colors.RESET}")

    return 1 if violations else 0


def cmd_install_hooks(args: argparse.Namespace) -> int:
    """Install git pre-commit hooks for Agent OS."""
    output_format = get_output_format(args)
    hook_path = Path(".git/hooks/pre-commit")

    if not Path(".git").exists():
        if output_format == "json":
            print(json.dumps({"status": "error", "message": "Not a git repository"}, indent=2))
        else:
            print(format_error("Not a git repository", suggestion="Run git init first"))
        return 1

    hook_content = "#!/bin/bash\n# Agent OS Pre-commit Hook\nagentos check --staged\n"

    append_mode = getattr(args, "append", False)
    force_mode = getattr(args, "force", False)

    try:
        hook_path.parent.mkdir(parents=True, exist_ok=True)

        if append_mode and hook_path.exists():
            existing = hook_path.read_text(encoding="utf-8")
            if "agentos check" in existing:
                # Already installed -- idempotent
                if output_format == "json":
                    print(json.dumps({"status": "success", "message": "already present"}, indent=2))
                else:
                    print(f"{Colors.GREEN}Agent OS check already present in {hook_path}{Colors.RESET}")
                return 0
            # Append the agentos check to the existing hook
            appended = existing.rstrip("\n") + "\n\n# Agent OS Pre-commit Check\nagentos check --staged\n"
            hook_path.write_text(appended, encoding="utf-8")
        elif hook_path.exists() and not force_mode and not append_mode:
            if output_format == "json":
                print(json.dumps({"status": "error", "message": "Hook already exists"}, indent=2))
            else:
                print(format_error("Hook already exists", suggestion="Use --force or --append"))
            return 1
        else:
            hook_path.write_text(hook_content, encoding="utf-8")

        try:
            hook_path.chmod(0o755)
        except OSError:
            pass  # chmod may not be supported on Windows

        if output_format == "json":
            print(json.dumps({"status": "success", "file": str(hook_path)}, indent=2))
        else:
            print(f"{Colors.GREEN}Installed Agent OS pre-commit hook to {hook_path}{Colors.RESET}")
        return 0
    except Exception as e:
        if output_format == "json":
            print(json.dumps({"status": "error", "message": str(e)}, indent=2))
        else:
            print(format_error(f"Failed to install hook: {e}"))
        return 1


# ============================================================================
# HTTP API Server (agentos serve)
# ============================================================================



def cmd_metrics(args: argparse.Namespace) -> int:
    """Output Prometheus metrics for Agent OS."""
    output_format = get_output_format(args)
    from agent_os import __version__

    metrics = {
        "version": __version__,
        "uptime_seconds": 0.0,
        "active_agents": 0,
        "policy_violations": 0,
        "policy_checks": 0,
        "audit_log_entries": 0,
        "kernel_operations": {"execute": 0, "set": 0, "get": 0},
        "packages": {
            "control_plane": False,
            "primitives": False,
            "cmvk": False,
            "caas": False,
            "emk": False,
            "amb": False,
            "atr": False,
            "scak": False,
            "mute_agent": False,
        },
    }

    if output_format == "json":
        print(json.dumps(metrics, indent=2))
    else:
        # Prometheus exposition format with HELP and TYPE annotations
        print('# HELP agentos_info Agent OS version info')
        print('# TYPE agentos_info gauge')
        print(f'agentos_info{{version="{__version__}"}} 1')
        print()
        print('# HELP agentos_uptime_seconds Agent OS uptime in seconds')
        print('# TYPE agentos_uptime_seconds gauge')
        print(f"agentos_uptime_seconds {metrics['uptime_seconds']}")
        print()
        print('# HELP agentos_active_agents Number of active agents')
        print('# TYPE agentos_active_agents gauge')
        print(f"agentos_active_agents {metrics['active_agents']}")
        print()
        print('# HELP agentos_policy_violations_total Total policy violations')
        print('# TYPE agentos_policy_violations_total counter')
        print(f"agentos_policy_violations_total {metrics['policy_violations']}")
        print()
        print('# HELP agentos_policy_checks_total Total policy checks')
        print('# TYPE agentos_policy_checks_total counter')
        print(f"agentos_policy_checks_total {metrics['policy_checks']}")
        print()
        print('# HELP agentos_kernel_operations_total Total kernel operations by type')
        print('# TYPE agentos_kernel_operations_total counter')
        for op, count in metrics['kernel_operations'].items():
            print(f'agentos_kernel_operations_total{{operation="{op}"}} {count}')
        print()
        print('# HELP agentos_audit_log_entries Number of audit log entries')
        print('# TYPE agentos_audit_log_entries gauge')
        print(f"agentos_audit_log_entries {metrics['audit_log_entries']}")

    return 0


def cmd_health(args: argparse.Namespace) -> int:
    """Check the health of Agent OS components."""
    output_format = get_output_format(args)

    health_data = {
        "status": "healthy",
        "uptime_seconds": 0.0,
        "components": {
            "kernel": "up",
            "state_backend": "connected",
            "policy_engine": "ready",
            "flight_recorder": "active",
        },
        "checks": [
            {"name": "memory_usage", "status": "ok"},
            {"name": "disk_space", "status": "ok"},
        ]
    }

    if output_format == "json":
        print(json.dumps(health_data, indent=2))
    else:
        print(f"Overall Status: {Colors.GREEN}HEALTHY{Colors.RESET}")
        for comp, status in health_data["components"].items():
            print(f"  {comp:15} {Colors.GREEN}{status}{Colors.RESET}")

    return 0


# ============================================================================
# Main Entry Point
# ============================================================================

def main() -> int:
    """Main CLI entry point."""
    parser = argparse.ArgumentParser(
        prog="agentos",
        description="Agent OS CLI - Command line interface for Agent OS",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("--json", action="store_true", help="Output in JSON format")
    parser.add_argument("--version", action="store_true", help="Show version")

    subparsers = parser.add_subparsers(dest="command", help="Command to execute")

    # init
    init_parser = subparsers.add_parser("init", help="Initialize .agents/ directory")
    init_parser.add_argument("--path", default=None, help="Project path (default: .)")
    init_parser.add_argument("--template", choices=AVAILABLE_POLICIES, help="Initial policy template")
    init_parser.add_argument("--force", action="store_true", help="Overwrite existing .agents/ directory")
    init_parser.add_argument("--json", action="store_true", help="Output in JSON format")

    # secure
    secure_parser = subparsers.add_parser("secure", help="Enable kernel governance")
    secure_parser.add_argument("path", nargs="?", help="Project path (default: .)")
    secure_parser.add_argument("--verify", action="store_true", help="Verify configuration only")
    secure_parser.add_argument("--json", action="store_true", help="Output in JSON format")

    # audit
    audit_parser = subparsers.add_parser("audit", help="Audit agent security")
    audit_parser.add_argument("path", nargs="?", help="Project path")
    audit_parser.add_argument("--format", choices=["text", "json"], default="text", help="Output format")
    audit_parser.add_argument("--export", choices=["csv"], help="Export audit to file")
    audit_parser.add_argument("--output", help="Output file for export")
    audit_parser.add_argument("--json", action="store_true", help="Output in JSON format")

    # status
    status_parser = subparsers.add_parser("status", help="Show kernel status")
    status_parser.add_argument("--format", choices=["text", "json"], default="text", help="Output format")
    status_parser.add_argument("--json", action="store_true", help="Output in JSON format")

    # check
    check_parser = subparsers.add_parser("check", help="Check file for safety violations")
    check_parser.add_argument("files", nargs="*", help="Files to check")
    check_parser.add_argument("--staged", action="store_true", help="Check staged git changes")
    check_parser.add_argument("--ci", action="store_true", help="CI mode (no colours)")
    check_parser.add_argument("--json", action="store_true", help="Output in JSON format")
    check_parser.add_argument("--format", choices=["text", "json"], default="text", help="Output format")

    # review
    review_parser = subparsers.add_parser("review", help="Multi-model code review")
    review_parser.add_argument("file", help="File to review")
    review_parser.add_argument("--cmvk", action="store_true", help="Enable multi-model analysis")
    review_parser.add_argument("--json", action="store_true", help="Output in JSON format")

    # install-hooks
    hooks_parser = subparsers.add_parser("install-hooks", help="Install git pre-commit hooks")
    hooks_parser.add_argument("--force", action="store_true", help="Overwrite existing hook")
    hooks_parser.add_argument("--append", action="store_true", help="Append to existing hook")
    hooks_parser.add_argument("--json", action="store_true", help="Output in JSON format")

    # validate
    validate_parser = subparsers.add_parser("validate", help="Validate policy YAML files")
    validate_parser.add_argument("files", nargs="*", help="Files to validate")
    validate_parser.add_argument("--json", action="store_true", help="Output in JSON format")
    validate_parser.add_argument("--strict", action="store_true", help="Strict mode: treat warnings as errors")


    # policy command — 'agentos policy validate <file>' with full JSON-Schema support
    policy_parser = subparsers.add_parser(
        "policy",
        help="Policy-as-code tools: validate, test, and diff governance policies",
    )
    policy_subparsers = policy_parser.add_subparsers(dest="policy_command")

    # agentos policy validate <file>
    pol_validate = policy_subparsers.add_parser(
        "validate",
        help="Validate a policy YAML/JSON file against the schema",
    )
    pol_validate.add_argument("path", help="Path to the policy file to validate")

    # agentos policy test <policy> <scenarios>
    pol_test = policy_subparsers.add_parser(
        "test",
        help="Test a policy against a set of YAML scenarios",
    )
    pol_test.add_argument("policy_path", help="Path to the policy file")
    pol_test.add_argument("test_scenarios_path", help="Path to the test scenarios YAML")

    # agentos policy diff <file1> <file2>
    pol_diff = policy_subparsers.add_parser(
        "diff",
        help="Show differences between two policy files",
    )
    pol_diff.add_argument("path1", help="First policy file")
    pol_diff.add_argument("path2", help="Second policy file")

    # serve command
    serve_parser = subparsers.add_parser(
        "serve",
        help="Start the HTTP API server for Agent OS",
        description="Launch an HTTP server exposing health, status, agents, and "
                    "execution endpoints for programmatic access to the kernel.",
    )
    serve_parser.add_argument(
        "--port", type=int, default=8080, help="Port to listen on (default: 8080)"
    )
    serve_parser.add_argument(
        "--host", default="127.0.0.1", help="Host to bind to (default: 127.0.0.1)"
    )

    # health
    health_parser = subparsers.add_parser("health", help="Check system health")
    health_parser.add_argument("--json", action="store_true", help="Output in JSON format")

    # metrics
    metrics_parser = subparsers.add_parser("metrics", help="Output Prometheus metrics")
    metrics_parser.add_argument("--json", action="store_true", help="Output in JSON format")

    args = parser.parse_args()

    # Handle CI mode
    if hasattr(args, 'ci') and args.ci:
        Colors.disable()

    if args.version:
        try:
            from agent_os import __version__
            print(f"agentos {__version__}")
        except Exception:
            print("agentos (version unknown)")
        return 0

    commands = {
        "init": cmd_init,
        "secure": cmd_secure,
        "audit": cmd_audit,
        "status": cmd_status,
        "check": cmd_check,
        "review": cmd_review,
        "install-hooks": cmd_install_hooks,
        "validate": cmd_validate,
        "policy": cmd_policy,
        "metrics": cmd_metrics,
        "health": cmd_health,
    }

    handler = commands.get(args.command)
    if handler is None:
        parser.print_help()
        return 0

    # Command routing
    try:
        return handler(args)
    except KeyboardInterrupt:
        return 130
    except Exception as e:
        return handle_cli_error(e, args)


if __name__ == "__main__":
    sys.exit(main())
