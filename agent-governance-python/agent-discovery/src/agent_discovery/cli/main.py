# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""Agent Discovery CLI — find shadow AI agents in your organization.

Usage:
    agent-discovery scan [--scanner process,config,github] [--output json|table]
    agent-discovery inventory [--storage-path PATH]
    agent-discovery reconcile [--registry-file PATH]
"""

from __future__ import annotations

import asyncio
import json
import sys
from pathlib import Path
from typing import Any

import click
from rich.console import Console
from rich.table import Table

from ..inventory import AgentInventory
from ..models import AgentStatus
from ..reconciler import Reconciler, StaticRegistryProvider
from ..risk import RiskScorer
from ..scanners import ConfigScanner, GitHubScanner, ProcessScanner
from ..scanners.base import BaseScanner

console = Console()

DEFAULT_STORAGE = Path.home() / ".agent-discovery" / "inventory.json"

SCANNER_MAP: dict[str, type[BaseScanner]] = {
    "process": ProcessScanner,
    "config": ConfigScanner,
    "github": GitHubScanner,
}


def _run_async(coro: Any) -> Any:
    """Run an async coroutine from sync context."""
    return asyncio.run(coro)


@click.group()
@click.version_option(version="0.1.0", prog_name="agent-discovery")
def main() -> None:
    """Agent Discovery — find shadow AI agents in your organization.

    Scan local processes, filesystems, and GitHub repos to discover
    AI agents running outside governance. Reconcile against your
    registry to find shadow agents and assess risk.
    """


@main.command()
@click.option(
    "--scanner",
    "-s",
    multiple=True,
    default=["process", "config"],
    type=click.Choice(["process", "config", "github"], case_sensitive=False),
    help="Scanners to run (can specify multiple)",
)
@click.option(
    "--paths",
    "-p",
    multiple=True,
    default=["."],
    help="Directories to scan (for config scanner)",
)
@click.option(
    "--github-org",
    help="GitHub organization to scan",
)
@click.option(
    "--github-repos",
    help="Comma-separated GitHub repos (owner/repo)",
)
@click.option(
    "--output",
    "-o",
    type=click.Choice(["table", "json"], case_sensitive=False),
    default="table",
    help="Output format",
)
@click.option(
    "--storage",
    type=click.Path(),
    default=str(DEFAULT_STORAGE),
    help="Inventory storage path",
)
def scan(
    scanner: tuple[str, ...],
    paths: tuple[str, ...],
    github_org: str | None,
    github_repos: str | None,
    output: str,
    storage: str,
) -> None:
    """Scan for AI agents across your environment."""
    console.print("\n[bold blue]🔍 Agent Discovery Scan[/bold blue]\n")

    inventory = AgentInventory(storage_path=storage)
    scorer = RiskScorer()
    total_found = 0

    for scanner_name in scanner:
        scanner_cls = SCANNER_MAP.get(scanner_name)
        if not scanner_cls:
            console.print(f"[red]Unknown scanner: {scanner_name}[/red]")
            continue

        scanner_instance = scanner_cls()
        console.print(f"  Running [cyan]{scanner_name}[/cyan] scanner...")

        kwargs: dict[str, Any] = {}
        if scanner_name == "config":
            kwargs["paths"] = list(paths)
        elif scanner_name == "github":
            if github_org:
                kwargs["org"] = github_org
            if github_repos:
                kwargs["repos"] = github_repos.split(",")

        try:
            result = _run_async(scanner_instance.scan(**kwargs))
        except Exception as e:
            console.print(f"  [red]Error: {e}[/red]")
            continue

        if result.errors:
            for err in result.errors:
                console.print(f"  [yellow]⚠ {err}[/yellow]")

        # Ingest into inventory
        stats = inventory.ingest(result)
        total_found += result.agent_count
        console.print(
            f"  Found [green]{result.agent_count}[/green] agents "
            f"({stats['new']} new, {stats['updated']} updated)"
        )

    # Score all agents
    for agent in inventory.agents:
        if agent.status != AgentStatus.REGISTERED:
            risk = scorer.score(agent)
            agent.tags["risk_level"] = risk.level.value
            agent.tags["risk_score"] = str(risk.score)

    console.print(f"\n[bold]Total: {total_found} agents discovered, "
                  f"{inventory.count} in inventory[/bold]\n")

    if output == "json":
        click.echo(inventory.export_json())
    else:
        _print_agent_table(inventory)

    console.print(f"\n[dim]Inventory saved to {storage}[/dim]")


@main.command()
@click.option(
    "--storage",
    type=click.Path(),
    default=str(DEFAULT_STORAGE),
    help="Inventory storage path",
)
@click.option(
    "--output",
    "-o",
    type=click.Choice(["table", "json", "summary"], case_sensitive=False),
    default="table",
)
def inventory(storage: str, output: str) -> None:
    """View the agent inventory."""
    inv = AgentInventory(storage_path=storage)

    if inv.count == 0:
        console.print("[yellow]No agents in inventory. Run 'agent-discovery scan' first.[/yellow]")
        return

    if output == "json":
        click.echo(inv.export_json())
    elif output == "summary":
        summary = inv.summary()
        console.print(f"\n[bold]Agent Inventory Summary[/bold]")
        console.print(f"  Total agents: {summary['total_agents']}")
        console.print(f"  By type: {json.dumps(summary['by_type'], indent=2)}")
        console.print(f"  By status: {json.dumps(summary['by_status'], indent=2)}")
    else:
        _print_agent_table(inv)


@main.command()
@click.option(
    "--storage",
    type=click.Path(),
    default=str(DEFAULT_STORAGE),
    help="Inventory storage path",
)
@click.option(
    "--registry-file",
    type=click.Path(exists=True),
    help="JSON file of registered agents for reconciliation",
)
@click.option(
    "--output",
    "-o",
    type=click.Choice(["table", "json"], case_sensitive=False),
    default="table",
)
def reconcile(storage: str, registry_file: str | None, output: str) -> None:
    """Reconcile discovered agents against governance registry."""
    inv = AgentInventory(storage_path=storage)
    scorer = RiskScorer()

    if inv.count == 0:
        console.print("[yellow]No agents in inventory. Run 'agent-discovery scan' first.[/yellow]")
        return

    # Load registry
    registered: list[dict[str, Any]] = []
    if registry_file:
        try:
            registered = json.loads(Path(registry_file).read_text(encoding="utf-8"))
        except Exception as e:
            console.print(f"[red]Failed to load registry file: {e}[/red]")
            sys.exit(1)

    provider = StaticRegistryProvider(registered)
    reconciler = Reconciler(inv, provider)

    console.print("\n[bold blue]🔄 Reconciliation[/bold blue]\n")
    shadow_agents = _run_async(reconciler.reconcile())

    # Score shadow agents
    for shadow in shadow_agents:
        shadow.risk = scorer.score(shadow.agent)

    registered_count = sum(
        1 for a in inv.agents if a.status == AgentStatus.REGISTERED
    )
    console.print(f"  Registered: [green]{registered_count}[/green]")
    console.print(f"  Shadow:     [red]{len(shadow_agents)}[/red]")

    if output == "json":
        click.echo(
            json.dumps(
                [s.model_dump(mode="json") for s in shadow_agents],
                indent=2,
                default=str,
            )
        )
    elif shadow_agents:
        console.print(f"\n[bold red]⚠ Shadow Agents Detected[/bold red]\n")
        table = Table(show_header=True, header_style="bold red")
        table.add_column("Name", style="white", max_width=40)
        table.add_column("Type", style="cyan")
        table.add_column("Risk", style="bold")
        table.add_column("Score", justify="right")
        table.add_column("Actions", style="dim", max_width=50)

        for shadow in sorted(
            shadow_agents, key=lambda s: s.risk.score if s.risk else 0, reverse=True
        ):
            risk_style = {
                "critical": "bold red",
                "high": "red",
                "medium": "yellow",
                "low": "green",
                "info": "dim",
            }.get(shadow.risk.level.value if shadow.risk else "info", "dim")

            table.add_row(
                shadow.agent.name[:40],
                shadow.agent.agent_type,
                f"[{risk_style}]{shadow.risk.level.value.upper()}[/{risk_style}]"
                if shadow.risk
                else "N/A",
                f"{shadow.risk.score:.0f}" if shadow.risk else "-",
                "; ".join(shadow.recommended_actions[:2]),
            )

        console.print(table)


def _print_agent_table(inv: AgentInventory) -> None:
    """Print agent inventory as a rich table."""
    table = Table(show_header=True, header_style="bold cyan")
    table.add_column("Fingerprint", style="dim", max_width=12)
    table.add_column("Name", style="white", max_width=40)
    table.add_column("Type", style="cyan")
    table.add_column("Status", style="bold")
    table.add_column("Confidence", justify="right")
    table.add_column("Evidence", justify="right")

    for agent in sorted(inv.agents, key=lambda a: a.confidence, reverse=True):
        status_style = {
            "registered": "green",
            "shadow": "red",
            "unregistered": "yellow",
            "unknown": "dim",
        }.get(agent.status.value, "dim")

        table.add_row(
            agent.fingerprint[:12],
            agent.name[:40],
            agent.agent_type,
            f"[{status_style}]{agent.status.value}[/{status_style}]",
            f"{agent.confidence:.0%}",
            str(len(agent.evidence)),
        )

    console.print(table)
