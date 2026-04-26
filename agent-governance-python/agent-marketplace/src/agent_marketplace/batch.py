# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""
Batch Policy Evaluation

Scans a directory of plugin manifests and evaluates each against a
governance policy, producing a consolidated compliance report.

Usage (programmatic):
    >>> from agent_marketplace.batch import evaluate_batch, format_report
    >>> result = evaluate_batch(Path("./plugins"), Path("policy.yaml"))
    >>> print(format_report(result, "text"))

Integration with CLI (add to cli_commands.py):
    >>> from agent_marketplace.batch import evaluate_batch_command
    >>> plugin.add_command(evaluate_batch_command)
"""

from __future__ import annotations

import json
import logging
import sys
from pathlib import Path
from typing import Any

import click
import yaml
from pydantic import BaseModel, Field

from agent_marketplace.exceptions import MarketplaceError
from agent_marketplace.manifest import MANIFEST_FILENAME, PluginManifest, load_manifest

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Models
# ---------------------------------------------------------------------------


class Violation(BaseModel):
    """A single policy violation found during evaluation."""

    rule: str = Field(..., description="Rule identifier that was violated")
    severity: str = Field(..., description="Severity level: high, medium, low")
    message: str = Field(..., description="Human-readable violation description")
    remediation: str = Field("", description="Suggested fix for the violation")


class PluginResult(BaseModel):
    """Evaluation result for a single plugin."""

    name: str = Field(..., description="Plugin name")
    status: str = Field(..., description="compliant or non_compliant")
    violations: list[Violation] = Field(default_factory=list)


class BatchResult(BaseModel):
    """Consolidated result of batch policy evaluation."""

    total: int = Field(0, description="Total plugins evaluated")
    compliant: int = Field(0, description="Number of compliant plugins")
    non_compliant: int = Field(0, description="Number of non-compliant plugins")
    by_severity: dict[str, int] = Field(
        default_factory=dict, description="Violation counts by severity"
    )
    top_violations: list[str] = Field(
        default_factory=list, description="Most common violation rules"
    )
    plugins: list[PluginResult] = Field(
        default_factory=list, description="Per-plugin results"
    )


# ---------------------------------------------------------------------------
# Policy loading and evaluation helpers
# ---------------------------------------------------------------------------


def _load_policy(policy_path: Path) -> dict[str, Any]:
    """Load policy rules from a YAML file.

    Expected format::

        rules:
          require_signature: true
          allowed_types: [integration, agent]
          min_description_length: 10
          require_capabilities: true
          max_dependencies: 10
    """
    if not policy_path.exists():
        raise MarketplaceError(f"Policy file not found: {policy_path}")
    try:
        with open(policy_path) as f:
            data = yaml.safe_load(f)
        if not isinstance(data, dict) or "rules" not in data:
            raise MarketplaceError("Policy file must contain a 'rules' key")
        return data["rules"]
    except yaml.YAMLError as exc:
        raise MarketplaceError(f"Invalid policy YAML: {exc}") from exc


def _evaluate_manifest(
    manifest: PluginManifest, rules: dict[str, Any]
) -> list[Violation]:
    """Evaluate a single manifest against policy rules."""
    violations: list[Violation] = []

    if rules.get("require_signature") and not manifest.signature:
        violations.append(
            Violation(
                rule="require_signature",
                severity="high",
                message=f"Plugin '{manifest.name}' is not signed",
                remediation="Sign the plugin with a valid Ed25519 key before publishing",
            )
        )

    allowed = rules.get("allowed_types")
    if allowed and manifest.plugin_type.value not in allowed:
        violations.append(
            Violation(
                rule="allowed_types",
                severity="high",
                message=(
                    f"Plugin type '{manifest.plugin_type.value}' is not allowed "
                    f"(allowed: {', '.join(allowed)})"
                ),
                remediation=f"Change plugin_type to one of: {', '.join(allowed)}",
            )
        )

    min_desc = rules.get("min_description_length", 0)
    if min_desc and len(manifest.description) < min_desc:
        violations.append(
            Violation(
                rule="min_description_length",
                severity="medium",
                message=(
                    f"Description is too short "
                    f"({len(manifest.description)} chars, minimum {min_desc})"
                ),
                remediation=f"Provide a description of at least {min_desc} characters",
            )
        )

    if rules.get("require_capabilities") and not manifest.capabilities:
        violations.append(
            Violation(
                rule="require_capabilities",
                severity="medium",
                message=f"Plugin '{manifest.name}' declares no capabilities",
                remediation="Add at least one capability to the manifest",
            )
        )

    max_deps = rules.get("max_dependencies")
    if max_deps is not None and len(manifest.dependencies) > max_deps:
        violations.append(
            Violation(
                rule="max_dependencies",
                severity="low",
                message=(
                    f"Plugin has {len(manifest.dependencies)} dependencies "
                    f"(max {max_deps})"
                ),
                remediation=f"Reduce dependencies to at most {max_deps}",
            )
        )

    return violations


def _discover_manifests(directory: Path) -> list[Path]:
    """Find all plugin manifest files in immediate subdirectories."""
    if not directory.is_dir():
        raise MarketplaceError(f"Not a directory: {directory}")

    manifests: list[Path] = []

    # Check each immediate subdirectory for a manifest
    for child in sorted(directory.iterdir()):
        if child.is_dir():
            manifest_path = child / MANIFEST_FILENAME
            if manifest_path.exists():
                manifests.append(manifest_path)

    # Also check the directory root
    root_manifest = directory / MANIFEST_FILENAME
    if root_manifest.exists():
        manifests.append(root_manifest)

    return manifests


# ---------------------------------------------------------------------------
# Core API
# ---------------------------------------------------------------------------


def evaluate_batch(directory: Path, policy_path: Path) -> BatchResult:
    """Scan a directory for plugin manifests and evaluate each against a policy.

    Each immediate subdirectory containing an ``agent-plugin.yaml`` is treated
    as a plugin.  Unparseable manifests are reported as non-compliant with a
    ``manifest_parse_error`` violation.

    Args:
        directory: Path to directory containing plugin subdirectories.
        policy_path: Path to a YAML policy file.

    Returns:
        Consolidated :class:`BatchResult`.

    Raises:
        MarketplaceError: If the directory or policy file is invalid.
    """
    rules = _load_policy(policy_path)
    manifest_paths = _discover_manifests(directory)

    plugins: list[PluginResult] = []
    severity_counts: dict[str, int] = {}
    violation_counts: dict[str, int] = {}

    for manifest_path in manifest_paths:
        try:
            manifest = load_manifest(manifest_path)
        except MarketplaceError as exc:
            plugins.append(
                PluginResult(
                    name=manifest_path.parent.name,
                    status="non_compliant",
                    violations=[
                        Violation(
                            rule="manifest_parse_error",
                            severity="high",
                            message=str(exc),
                            remediation=(
                                "Fix the manifest file so it conforms to "
                                "the PluginManifest schema"
                            ),
                        )
                    ],
                )
            )
            severity_counts["high"] = severity_counts.get("high", 0) + 1
            violation_counts["manifest_parse_error"] = (
                violation_counts.get("manifest_parse_error", 0) + 1
            )
            continue

        violations = _evaluate_manifest(manifest, rules)
        status = "compliant" if not violations else "non_compliant"
        plugins.append(
            PluginResult(name=manifest.name, status=status, violations=violations)
        )

        for v in violations:
            severity_counts[v.severity] = severity_counts.get(v.severity, 0) + 1
            violation_counts[v.rule] = violation_counts.get(v.rule, 0) + 1

    total = len(plugins)
    compliant = sum(1 for p in plugins if p.status == "compliant")
    non_compliant = total - compliant

    # Top violations sorted by frequency (descending)
    top_violations = sorted(
        violation_counts, key=lambda r: violation_counts[r], reverse=True
    )

    return BatchResult(
        total=total,
        compliant=compliant,
        non_compliant=non_compliant,
        by_severity=severity_counts,
        top_violations=top_violations,
        plugins=plugins,
    )


# ---------------------------------------------------------------------------
# Report formatting
# ---------------------------------------------------------------------------


def format_report(result: BatchResult, fmt: str = "text") -> str:
    """Format a :class:`BatchResult` as JSON, markdown, or plain text.

    Args:
        result: The batch evaluation result to format.
        fmt: Output format — ``"json"``, ``"markdown"``, or ``"text"``.

    Returns:
        Formatted report string.

    Raises:
        MarketplaceError: If the format is unknown.
    """
    if fmt == "json":
        return result.model_dump_json(indent=2)
    elif fmt == "markdown":
        return _format_markdown(result)
    elif fmt == "text":
        return _format_text(result)
    else:
        raise MarketplaceError(f"Unknown report format: {fmt}")


def _format_markdown(result: BatchResult) -> str:
    """Format result as a Markdown report."""
    lines: list[str] = [
        "# Batch Policy Evaluation Report",
        "",
        f"**Total plugins:** {result.total}",
        f"**Compliant:** {result.compliant}",
        f"**Non-compliant:** {result.non_compliant}",
        "",
    ]

    if result.by_severity:
        lines.append("## Violations by Severity")
        lines.append("")
        for severity, count in sorted(result.by_severity.items()):
            lines.append(f"- **{severity}**: {count}")
        lines.append("")

    if result.top_violations:
        lines.append("## Top Violations")
        lines.append("")
        for rule in result.top_violations:
            lines.append(f"1. `{rule}`")
        lines.append("")

    lines.append("## Plugin Details")
    lines.append("")
    for plugin in result.plugins:
        icon = "\u2713" if plugin.status == "compliant" else "\u2717"
        lines.append(f"### {icon} {plugin.name}")
        lines.append("")
        lines.append(f"**Status:** {plugin.status}")
        lines.append("")
        if plugin.violations:
            lines.append("| Rule | Severity | Message |")
            lines.append("|------|----------|---------|")
            for v in plugin.violations:
                lines.append(f"| `{v.rule}` | {v.severity} | {v.message} |")
            lines.append("")

    return "\n".join(lines)


def _format_text(result: BatchResult) -> str:
    """Format result as plain text."""
    lines: list[str] = [
        "Batch Policy Evaluation Report",
        "=" * 40,
        (
            f"Total: {result.total}  "
            f"Compliant: {result.compliant}  "
            f"Non-compliant: {result.non_compliant}"
        ),
        "",
    ]

    for plugin in result.plugins:
        icon = "\u2713" if plugin.status == "compliant" else "\u2717"
        lines.append(f"  {icon} {plugin.name}: {plugin.status}")
        for v in plugin.violations:
            lines.append(f"    [{v.severity}] {v.rule}: {v.message}")
            if v.remediation:
                lines.append(f"           Remediation: {v.remediation}")

    return "\n".join(lines)


# ---------------------------------------------------------------------------
# CLI command
# ---------------------------------------------------------------------------


@click.command("evaluate-batch")
@click.argument("directory", type=click.Path(exists=True))
@click.option(
    "--policy",
    required=True,
    type=click.Path(exists=True),
    help="Path to policy YAML file",
)
@click.option(
    "--output",
    "output_file",
    default=None,
    type=click.Path(),
    help="Write report to file instead of stdout",
)
@click.option(
    "--format",
    "fmt",
    default="text",
    type=click.Choice(["json", "markdown", "text"]),
    help="Report format",
)
def evaluate_batch_command(
    directory: str, policy: str, output_file: str | None, fmt: str
) -> None:
    """Evaluate all plugins in a directory against a governance policy.

    Scans DIRECTORY for plugin subdirectories containing agent-plugin.yaml
    manifests and evaluates each against the rules in POLICY.

    Exit code 0 if all plugins are compliant, 1 if any violations exist.
    """
    try:
        result = evaluate_batch(Path(directory), Path(policy))
    except MarketplaceError as exc:
        click.echo(f"Error: {exc}", err=True)
        sys.exit(1)

    report = format_report(result, fmt)

    if output_file:
        Path(output_file).write_text(report, encoding="utf-8")
        click.echo(f"Report written to {output_file}")
    else:
        click.echo(report)

    if result.non_compliant > 0:
        sys.exit(1)
