# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
# Entry point: mcp-scan = agent_os.cli.mcp_scan:main
"""MCP Security Scanner CLI — audit MCP configuration files for vulnerabilities.

Standalone CLI that wraps MCPSecurityScanner to detect tool poisoning,
rug pulls, and protocol attacks in MCP server configurations.

Usage::

    python -m agent_os.cli.mcp_scan scan config.json
    python -m agent_os.cli.mcp_scan fingerprint config.json --output fp.json
    python -m agent_os.cli.mcp_scan report config.json --format markdown
"""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
from pathlib import Path
from typing import Any

from agent_os.mcp_security import (
    MCPSecurityScanner,
    MCPSeverity,
    MCPThreat,
    ScanResult,
)

# ---------------------------------------------------------------------------
# Config loading & parsing
# ---------------------------------------------------------------------------

def load_config(path: str) -> dict[str, Any]:
    """Load an MCP configuration file (JSON or YAML).

    Raises:
        FileNotFoundError: If the file does not exist.
        ValueError: If the file cannot be parsed.
    """
    p = Path(path)
    if not p.exists():
        raise FileNotFoundError(f"Config file not found: {path}")

    text = p.read_text(encoding="utf-8")

    if p.suffix in (".yaml", ".yml"):
        try:
            import yaml  # type: ignore[import-untyped]
            data = yaml.safe_load(text)
        except ImportError:
            raise ImportError("PyYAML is required to load YAML config files") from None
    else:
        try:
            data = json.loads(text)
        except json.JSONDecodeError as exc:
            raise ValueError(f"Invalid JSON in {path}: {exc}") from exc

    if data is None:
        raise ValueError(f"Empty config file: {path}")
    return data


def parse_config(config: Any) -> dict[str, list[dict[str, Any]]]:
    """Parse MCP config into ``{server_name: [tool_defs]}`` mapping.

    Supports:
        1. Standard: ``{"mcpServers": {"name": {"tools": [...]}}}``
        2. Tools-only list: ``[{"name": "...", "description": "..."}]``
        3. Tools wrapper: ``{"tools": [...]}``
    """
    result: dict[str, list[dict[str, Any]]] = {}

    if isinstance(config, list):
        result["default"] = config
    elif isinstance(config, dict):
        if "mcpServers" in config:
            for server_name, server_def in config["mcpServers"].items():
                if isinstance(server_def, dict):
                    result[server_name] = server_def.get("tools", [])
        elif "tools" in config:
            result["default"] = config["tools"]
        else:
            result["default"] = []
    else:
        result["default"] = []

    return result


# ---------------------------------------------------------------------------
# Scanning
# ---------------------------------------------------------------------------

def run_scan(
    servers: dict[str, list[dict[str, Any]]],
    *,
    server_filter: str | None = None,
    min_severity: str | None = None,
) -> tuple[dict[str, ScanResult], list[MCPThreat]]:
    """Scan all servers/tools and return per-server results + flat threat list."""
    scanner = MCPSecurityScanner()
    results: dict[str, ScanResult] = {}
    all_threats: list[MCPThreat] = []

    for server_name, tools in servers.items():
        if server_filter and server_name != server_filter:
            continue
        result = scanner.scan_server(server_name, tools)
        results[server_name] = result
        all_threats.extend(result.threats)

    # Filter by severity — apply to both the flat list and per-server results
    if min_severity:
        severity_order = {"info": 0, "warning": 1, "critical": 2}
        min_level = severity_order.get(min_severity, 0)
        all_threats = [
            t for t in all_threats
            if severity_order.get(t.severity.value, 0) >= min_level
        ]
        for sname, res in results.items():
            filtered = [
                t for t in res.threats
                if severity_order.get(t.severity.value, 0) >= min_level
            ]
            results[sname] = ScanResult(
                safe=len(filtered) == 0,
                threats=filtered,
                tools_scanned=res.tools_scanned,
                tools_flagged=res.tools_flagged,
            )

    return results, all_threats


# ---------------------------------------------------------------------------
# Formatting
# ---------------------------------------------------------------------------

def _threat_icon(severity: MCPSeverity) -> str:
    if severity == MCPSeverity.CRITICAL:
        return "\u274c"  # ❌
    if severity == MCPSeverity.WARNING:
        return "\u26a0\ufe0f"   # ⚠️
    return "\u2139\ufe0f"  # ℹ️


def format_table(
    results: dict[str, ScanResult],
    all_threats: list[MCPThreat],
    servers: dict[str, list[dict[str, Any]]],
) -> str:
    """Format scan results as a human-readable table."""
    lines: list[str] = []
    lines.append("MCP Security Scan Results")
    lines.append("=" * 24)

    total_scanned = 0
    total_warnings = 0
    total_critical = 0

    for server_name, result in results.items():
        lines.append(f"Server: {server_name}")
        total_scanned += result.tools_scanned

        # Build threats-by-tool mapping
        tool_threats: dict[str, list[MCPThreat]] = {}
        for threat in result.threats:
            tool_threats.setdefault(threat.tool_name, []).append(threat)

        # Get all tool names from the original config
        tool_names = [t.get("name", "unknown") for t in servers.get(server_name, [])]

        for tool_name in tool_names:
            if tool_name in tool_threats:
                threats = tool_threats[tool_name]
                max_sev = max(threats, key=lambda t: _severity_rank(t.severity))
                icon = _threat_icon(max_sev.severity)
                label = max_sev.severity.value.upper()
                lines.append(f"  {icon} {tool_name} \u2014 {label}: {max_sev.message}")
                for t in threats:
                    if t.severity == MCPSeverity.CRITICAL:
                        total_critical += 1
                    elif t.severity == MCPSeverity.WARNING:
                        total_warnings += 1
            else:
                lines.append(f"  \u2705 {tool_name} \u2014 No threats detected")

        lines.append("")

    lines.append(
        f"Summary: {total_scanned} tools scanned, "
        f"{total_warnings} warning(s), {total_critical} critical"
    )
    return "\n".join(lines)


def _severity_rank(severity: MCPSeverity) -> int:
    return {"info": 0, "warning": 1, "critical": 2}.get(severity.value, 0)


def format_json_output(
    results: dict[str, ScanResult],
    all_threats: list[MCPThreat],
) -> str:
    """Format scan results as JSON."""
    output: dict[str, Any] = {
        "servers": {},
        "summary": {"tools_scanned": 0, "warnings": 0, "critical": 0},
    }

    for server_name, result in results.items():
        output["summary"]["tools_scanned"] += result.tools_scanned
        server_threats = []
        for threat in result.threats:
            server_threats.append({
                "tool_name": threat.tool_name,
                "threat_type": threat.threat_type.value,
                "severity": threat.severity.value,
                "message": threat.message,
                "matched_pattern": threat.matched_pattern,
            })
            if threat.severity == MCPSeverity.WARNING:
                output["summary"]["warnings"] += 1
            elif threat.severity == MCPSeverity.CRITICAL:
                output["summary"]["critical"] += 1
        output["servers"][server_name] = {
            "tools_scanned": result.tools_scanned,
            "safe": result.safe,
            "threats": server_threats,
        }

    return json.dumps(output, indent=2)


def format_markdown(
    results: dict[str, ScanResult],
    all_threats: list[MCPThreat],
) -> str:
    """Format scan results as a Markdown report."""
    lines: list[str] = []
    lines.append("# MCP Security Scan Report")
    lines.append("")

    total_scanned = 0
    total_warnings = 0
    total_critical = 0

    for server_name, result in results.items():
        total_scanned += result.tools_scanned
        lines.append(f"## Server: {server_name}")
        lines.append("")
        lines.append("| Tool | Severity | Threat | Message |")
        lines.append("|------|----------|--------|---------|")

        tool_threats: dict[str, list[MCPThreat]] = {}
        for threat in result.threats:
            tool_threats.setdefault(threat.tool_name, []).append(threat)

        if not tool_threats:
            lines.append("| \u2705 All tools | - | - | No threats detected |")
        else:
            for tool_name, threats in tool_threats.items():
                for threat in threats:
                    if threat.severity == MCPSeverity.WARNING:
                        total_warnings += 1
                    elif threat.severity == MCPSeverity.CRITICAL:
                        total_critical += 1
                    lines.append(
                        f"| {tool_name} | {threat.severity.value} "
                        f"| {threat.threat_type.value} | {threat.message} |"
                    )

        lines.append("")

    lines.append(
        f"**Summary**: {total_scanned} tools scanned, "
        f"{total_warnings} warning(s), {total_critical} critical"
    )
    return "\n".join(lines)


# ---------------------------------------------------------------------------
# Fingerprinting (rug pull detection)
# ---------------------------------------------------------------------------

def compute_fingerprints(
    servers: dict[str, list[dict[str, Any]]],
) -> dict[str, dict[str, str]]:
    """Compute SHA-256 fingerprints for every tool across all servers."""
    fingerprints: dict[str, dict[str, str]] = {}
    for server_name, tools in servers.items():
        for tool in tools:
            name = tool.get("name", "unknown")
            desc = tool.get("description", "")
            schema = tool.get("inputSchema")
            key = f"{server_name}::{name}"
            fingerprints[key] = {
                "tool_name": name,
                "server_name": server_name,
                "description_hash": hashlib.sha256(
                    desc.encode("utf-8")
                ).hexdigest(),
                "schema_hash": hashlib.sha256(
                    json.dumps(schema, sort_keys=True, default=str).encode("utf-8")
                    if schema
                    else b""
                ).hexdigest(),
            }
    return fingerprints


def compare_fingerprints(
    current: dict[str, dict[str, str]],
    saved: dict[str, dict[str, str]],
) -> list[dict[str, Any]]:
    """Compare current fingerprints against saved ones, returning changes."""
    changes: list[dict[str, Any]] = []

    for key, fp in current.items():
        if key in saved:
            old = saved[key]
            changed_fields: list[str] = []
            if old["description_hash"] != fp["description_hash"]:
                changed_fields.append("description")
            if old["schema_hash"] != fp["schema_hash"]:
                changed_fields.append("schema")
            if changed_fields:
                changes.append({
                    "key": key,
                    "tool_name": fp["tool_name"],
                    "server_name": fp["server_name"],
                    "changed_fields": changed_fields,
                })
        else:
            changes.append({
                "key": key,
                "tool_name": fp["tool_name"],
                "server_name": fp["server_name"],
                "changed_fields": ["new_tool"],
            })

    for key in saved:
        if key not in current:
            changes.append({
                "key": key,
                "tool_name": saved[key]["tool_name"],
                "server_name": saved[key]["server_name"],
                "changed_fields": ["removed"],
            })

    return changes


# ---------------------------------------------------------------------------
# CLI commands
# ---------------------------------------------------------------------------

def cmd_scan(args: argparse.Namespace) -> int:
    """Execute the ``scan`` sub-command."""
    try:
        config = load_config(args.config)
    except (FileNotFoundError, ValueError, ImportError) as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 1

    servers = parse_config(config)
    results, all_threats = run_scan(
        servers,
        server_filter=getattr(args, "server", None),
        min_severity=getattr(args, "severity", None),
    )

    fmt = getattr(args, "format", "table")
    if fmt == "json":
        print(format_json_output(results, all_threats))
    elif fmt == "markdown":
        print(format_markdown(results, all_threats))
    else:
        print(format_table(results, all_threats, servers))

    # Non-zero exit if critical threats found
    if any(t.severity == MCPSeverity.CRITICAL for t in all_threats):
        return 2
    return 0


def cmd_fingerprint(args: argparse.Namespace) -> int:
    """Execute the ``fingerprint`` sub-command."""
    try:
        config = load_config(args.config)
    except (FileNotFoundError, ValueError, ImportError) as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 1

    servers = parse_config(config)
    current_fps = compute_fingerprints(servers)

    if args.output:
        Path(args.output).write_text(
            json.dumps(current_fps, indent=2), encoding="utf-8"
        )
        print(f"Fingerprints saved to {args.output} ({len(current_fps)} tools)")
        return 0

    if args.compare:
        compare_path = Path(args.compare)
        if not compare_path.exists():
            print(f"Error: Fingerprint file not found: {args.compare}", file=sys.stderr)
            return 1
        saved_fps = json.loads(compare_path.read_text(encoding="utf-8"))
        changes = compare_fingerprints(current_fps, saved_fps)

        if not changes:
            print("No changes detected — all tool fingerprints match.")
            return 0

        print(f"Rug pull detection: {len(changes)} change(s) found!\n")
        for change in changes:
            fields = ", ".join(change["changed_fields"])
            print(
                f"  \u274c {change['server_name']}::{change['tool_name']} "
                f"\u2014 changed: {fields}"
            )
        return 2

    print("Error: Specify --output or --compare", file=sys.stderr)
    return 1


def cmd_report(args: argparse.Namespace) -> int:
    """Execute the ``report`` sub-command."""
    try:
        config = load_config(args.config)
    except (FileNotFoundError, ValueError, ImportError) as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 1

    servers = parse_config(config)
    results, all_threats = run_scan(servers)

    fmt = getattr(args, "format", "markdown")
    if fmt == "json":
        print(format_json_output(results, all_threats))
    else:
        print(format_markdown(results, all_threats))

    return 0


# ---------------------------------------------------------------------------
# Argument parser & entry point
# ---------------------------------------------------------------------------

def build_parser() -> argparse.ArgumentParser:
    """Build the CLI argument parser."""
    parser = argparse.ArgumentParser(
        prog="mcp-scan",
        description="MCP Security Scanner — audit MCP configs for vulnerabilities",
    )
    subparsers = parser.add_subparsers(dest="command", help="Available commands")

    # -- scan ---------------------------------------------------------------
    scan_parser = subparsers.add_parser("scan", help="Scan MCP config for threats")
    scan_parser.add_argument("config", help="Path to MCP config file (JSON/YAML)")
    scan_parser.add_argument(
        "--server", default=None, help="Scan only this server"
    )
    scan_parser.add_argument(
        "--format",
        choices=["json", "table", "markdown"],
        default="table",
        help="Output format (default: table)",
    )
    scan_parser.add_argument(
        "--severity",
        choices=["warning", "critical"],
        default=None,
        help="Minimum severity to report",
    )

    # -- fingerprint --------------------------------------------------------
    fp_parser = subparsers.add_parser(
        "fingerprint", help="Register/compare tool fingerprints"
    )
    fp_parser.add_argument("config", help="Path to MCP config file (JSON/YAML)")
    fp_parser.add_argument(
        "--output", default=None, help="Save fingerprints to this file"
    )
    fp_parser.add_argument(
        "--compare", default=None, help="Compare against saved fingerprint file"
    )

    # -- report -------------------------------------------------------------
    report_parser = subparsers.add_parser(
        "report", help="Generate a full security report"
    )
    report_parser.add_argument("config", help="Path to MCP config file (JSON/YAML)")
    report_parser.add_argument(
        "--format",
        choices=["markdown", "json"],
        default="markdown",
        help="Report format (default: markdown)",
    )

    return parser


def main(argv: list[str] | None = None) -> int:
    """CLI entry point."""
    parser = build_parser()
    args = parser.parse_args(argv)

    if args.command is None:
        parser.print_help()
        return 0

    dispatch = {
        "scan": cmd_scan,
        "fingerprint": cmd_fingerprint,
        "report": cmd_report,
    }
    return dispatch[args.command](args)


if __name__ == "__main__":
    sys.exit(main())
