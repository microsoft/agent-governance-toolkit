# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""
Agent OS MCP Security Scanner

Analyzes MCP server configurations for potential security risks,
capability exposure, and fingerprint violations.
"""

import argparse
import json
import logging
import sys
import tempfile
from pathlib import Path
from typing import Dict, List, Optional

import yaml
from rich.console import Console
from rich.table import Table

# Configure logging
logging.basicConfig(level=logging.WARNING)
logger = logging.getLogger("mcp-scan")

console = Console()


class SecurityFinding:
    """Represents a security risk or discovery during scan."""
    def __init__(self, server: str, severity: str, message: str, category: str):
        self.server = server
        self.severity = severity
        self.message = message
        self.category = category

    def to_dict(self) -> Dict[str, str]:
        return {
            "server": self.server,
            "severity": self.severity,
            "message": self.message,
            "category": self.category
        }


def scan_config(config_path: Path, single_server: Optional[str] = None) -> List[SecurityFinding]:
    """Scan MCP configuration for potential security risks."""
    findings = []

    try:
        if config_path.suffix in [".yaml", ".yml"]:
            with open(config_path) as f:
                config = yaml.safe_load(f)
        else:
            with open(config_path) as f:
                config = json.load(f)
    except Exception as e:
        findings.append(SecurityFinding("system", "critical", f"Failed to load config: {e}", "configuration"))
        return findings

    mcp_servers = config.get("mcpServers", {})

    for name, server in mcp_servers.items():
        if single_server and name != single_server:
            continue

        # 1. Environment Variable Check
        env = server.get("env", {})
        for key in env.keys():
            if "KEY" in key.upper() or "SECRET" in key.upper() or "TOKEN" in key.upper():
                findings.append(SecurityFinding(name, "warning", f"Sensitive key '{key}' exposed in environment", "leakage"))

        # 2. Command Check
        cmd = server.get("command", "")
        if "sudo" in cmd.lower():
            findings.append(SecurityFinding(name, "critical", "Server runs with sudo privileges", "privilege"))
        if tempfile.gettempdir() in cmd.lower():
            findings.append(SecurityFinding(name, "warning", "Server binary path in /tmp is risky", "execution"))

        # 3. Arguments Check
        args = server.get("args", [])
        for arg in args:
            if "/" in arg and Path(arg).is_absolute() and not arg.startswith(("/usr/", "/bin/", "/opt/")):
                findings.append(SecurityFinding(name, "warning", f"Absolute path '{arg}' exposed in arguments", "leakage"))

    return findings


def get_fingerprints(config_path: Path) -> Dict[str, str]:
    """Generate fingerprints for all tools in the config."""
    # Simulated fingerprinting
    import hashlib

    try:
        with open(config_path) as f:
            if config_path.suffix in [".yaml", ".yml"]:
                config = yaml.safe_load(f)
            else:
                config = json.load(f)
    except (json.JSONDecodeError, yaml.YAMLError, OSError, ValueError):
        return {}

    fingerprints = {}
    mcp_servers = config.get("mcpServers", {})
    for name, server in mcp_servers.items():
        cmd = str(server.get("command", ""))
        args = str(server.get("args", []))
        h = hashlib.sha256(f"{cmd}{args}".encode()).hexdigest()[:16]
        fingerprints[name] = h

    return fingerprints


def build_parser() -> argparse.ArgumentParser:
    """Build the CLI argument parser."""
    parser = argparse.ArgumentParser(
        prog="mcp-scan",
        description="Agent OS MCP Security Scanner - Analyze MCP configs for risks"
    )

    subparsers = parser.add_subparsers(dest="command", help="Command to run")

    # -- scan ---------------------------------------------------------------
    scan_parser = subparsers.add_parser("scan", help="Scan MCP config for threats")
    scan_parser.add_argument("config", help="Path to MCP config file (JSON/YAML)")
    scan_parser.add_argument("--server", default=None, help="Scan only this server")
    scan_parser.add_argument("--format", choices=["json", "table", "markdown"], default="table", help="Output format")
    scan_parser.add_argument("--severity", choices=["warning", "critical"], default=None, help="Min severity")
    scan_parser.add_argument("--json", action="store_true", help="Output in JSON format")

    # -- fingerprint --------------------------------------------------------
    fp_parser = subparsers.add_parser("fingerprint", help="Register/compare tool fingerprints")
    fp_parser.add_argument("config", help="Path to MCP config file (JSON/YAML)")
    fp_parser.add_argument("--output", default=None, help="Save fingerprints to file")
    fp_parser.add_argument("--compare", default=None, help="Compare against saved file")
    fp_parser.add_argument("--json", action="store_true", help="Output in JSON format")

    # -- report -------------------------------------------------------------
    report_parser = subparsers.add_parser("report", help="Generate a full security report")
    report_parser.add_argument("config", help="Path to MCP config file (JSON/YAML)")
    report_parser.add_argument("--format", choices=["markdown", "json"], default="markdown", help="Report format")
    report_parser.add_argument("--json", action="store_true", help="Output in JSON format")

    return parser


def main(argv: List[str] | None = None) -> int:
    """CLI entry point."""
    parser = build_parser()
    args = parser.parse_args(argv)

    if not args.command:
        parser.print_help()
        return 0

    config_path = Path(args.config)
    if not config_path.exists():
        print(f"Error: Config file not found: {args.config}")
        return 1

    output_format = "json" if getattr(args, "json", False) or getattr(args, "format", "table") == "json" else "table"

    try:
        if args.command == "scan":
            findings = scan_config(config_path, args.server)

            if args.severity:
                findings = [f for f in findings if f.severity == args.severity or f.severity == "critical"]

            if output_format == "json":
                print(json.dumps([f.to_dict() for f in findings], indent=2))
            elif output_format == "table":
                table = Table(title=f"Security Scan: {args.config}")
                table.add_column("Server", style="cyan")
                table.add_column("Severity", style="bold")
                table.add_column("Category", style="dim")
                table.add_column("Finding")

                for f in findings:
                    sev_color = "red" if f.severity == "critical" else "yellow"
                    table.add_row(f.server, f"[{sev_color}]{f.severity.upper()}[/{sev_color}]", f.category, f.message)

                console.print(table)

            return 1 if any(f.severity == "critical" for f in findings) else 0

        elif args.command == "fingerprint":
            fingerprints = get_fingerprints(config_path)

            if args.compare:
                with open(args.compare) as f:
                    saved = json.load(f)

                diffs = {}
                for name, h in fingerprints.items():
                    if name not in saved:
                        diffs[name] = "new"
                    elif saved[name] != h:
                        diffs[name] = "changed"

                if output_format == "json":
                    print(json.dumps({"current": fingerprints, "diffs": diffs}, indent=2))
                else:
                    print(f"Comparison results for {args.config}:")
                    for name, status in diffs.items():
                        print(f"  {name}: {status}")
                    if not diffs:
                        print("  Identical fingerprints.")

            elif args.output:
                with open(args.output, "w") as f:
                    json.dump(fingerprints, f, indent=2)
                if output_format != "json":
                    print(f"Fingerprints saved to {args.output}")
                else:
                    print(json.dumps({"status": "success", "file": args.output}, indent=2))

            else:
                if output_format == "json":
                    print(json.dumps(fingerprints, indent=2))
                else:
                    for name, h in fingerprints.items():
                        print(f"{name:20} {h}")

        elif args.command == "report":
            findings = scan_config(config_path)
            fingerprints = get_fingerprints(config_path)

            report = {
                "config": str(config_path),
                "summary": {
                    "total_servers": len(fingerprints),
                    "total_findings": len(findings),
                    "critical": len([f for f in findings if f.severity == "critical"]),
                    "warning": len([f for f in findings if f.severity == "warning"])
                },
                "findings": [f.to_dict() for f in findings],
                "fingerprints": fingerprints
            }

            if output_format == "json" or getattr(args, "format", "markdown") == "json":
                print(json.dumps(report, indent=2))
            else:
                # Simple markdown report
                print(f"# Security Report: {args.config}")
                print()
                print(f"- Total Servers: {report['summary']['total_servers']}")
                print(f"- Total Findings: {report['summary']['total_findings']}")
                print()
                print("## Findings")
                for f in findings:
                    print(f"- **{f.server}** ({f.severity.upper()}): {f.message}")

        return 0
    except Exception as e:
        is_known = isinstance(e, (FileNotFoundError, ValueError, yaml.YAMLError))
        msg = "A file access or syntax error occurred." if is_known else "An error occurred during scanning"
        if output_format == "json":
            print(json.dumps({"status": "error", "message": msg, "type": "ScanError" if is_known else "InternalError"}, indent=2))
        else:
            print(f"Error: {msg}")
        return 1


if __name__ == "__main__":
    sys.exit(main())
