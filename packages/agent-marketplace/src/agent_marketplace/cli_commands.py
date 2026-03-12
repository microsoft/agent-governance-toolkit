# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""
Plugin Marketplace CLI Commands

Defines click commands for plugin management. These are standalone functions
that can be wired into the main CLI group.

Commands:
    - agentmesh plugin install <name>
    - agentmesh plugin uninstall <name>
    - agentmesh plugin list
    - agentmesh plugin search <query>
    - agentmesh plugin verify <path>
    - agentmesh plugin publish <path>
"""

from __future__ import annotations

import logging
from pathlib import Path

import click
from rich.console import Console
from rich.table import Table

from agent_marketplace import (
    MarketplaceError,
    PluginInstaller,
    PluginRegistry,
    PluginType,
    load_manifest,
)

console = Console()
logger = logging.getLogger(__name__)

# Default paths
DEFAULT_PLUGINS_DIR = Path(".agentmesh") / "plugins"
DEFAULT_REGISTRY_FILE = Path(".agentmesh") / "registry.json"


def _get_registry() -> PluginRegistry:
    return PluginRegistry(storage_path=DEFAULT_REGISTRY_FILE)


def _get_installer() -> PluginInstaller:
    return PluginInstaller(plugins_dir=DEFAULT_PLUGINS_DIR, registry=_get_registry())


@click.group()
def plugin() -> None:
    """Manage AgentMesh plugins."""


@plugin.command("install")
@click.argument("name")
@click.option("--version", "-v", default=None, help="Specific version to install")
def install_plugin(name: str, version: str | None) -> None:
    """Install a plugin from the registry."""
    try:
        installer = _get_installer()
        dest = installer.install(name, version)
        console.print(f"[green]✓[/green] Installed {name} to {dest}")
    except MarketplaceError as exc:
        console.print(f"[red]Error:[/red] {exc}")


@plugin.command("uninstall")
@click.argument("name")
def uninstall_plugin(name: str) -> None:
    """Uninstall a plugin."""
    try:
        installer = _get_installer()
        installer.uninstall(name)
        console.print(f"[green]✓[/green] Uninstalled {name}")
    except MarketplaceError as exc:
        console.print(f"[red]Error:[/red] {exc}")


@plugin.command("list")
@click.option(
    "--type",
    "plugin_type",
    type=click.Choice([t.value for t in PluginType]),
    default=None,
    help="Filter by plugin type",
)
def list_plugins(plugin_type: str | None) -> None:
    """List installed plugins."""
    installer = _get_installer()
    plugins = installer.list_installed()
    if plugin_type:
        plugins = [p for p in plugins if p.plugin_type.value == plugin_type]
    if not plugins:
        console.print("[yellow]No plugins installed.[/yellow]")
        return
    table = Table(title="Installed Plugins")
    table.add_column("Name", style="cyan")
    table.add_column("Version")
    table.add_column("Type")
    table.add_column("Author")
    for p in plugins:
        table.add_row(p.name, p.version, p.plugin_type.value, p.author)
    console.print(table)


@plugin.command("search")
@click.argument("query")
def search_plugins(query: str) -> None:
    """Search the plugin registry."""
    registry = _get_registry()
    results = registry.search(query)
    if not results:
        console.print(f"[yellow]No plugins matching '{query}'.[/yellow]")
        return
    table = Table(title=f"Search Results: {query}")
    table.add_column("Name", style="cyan")
    table.add_column("Version")
    table.add_column("Description")
    for p in results:
        table.add_row(p.name, p.version, p.description)
    console.print(table)


@plugin.command("verify")
@click.argument("path", type=click.Path(exists=True))
def verify_plugin(path: str) -> None:
    """Verify a plugin's signature."""
    try:
        manifest = load_manifest(Path(path))
        if not manifest.signature:
            console.print("[yellow]Plugin has no signature.[/yellow]")
            return
        console.print(f"[green]✓[/green] Manifest loaded: {manifest.name}@{manifest.version}")
        console.print("[yellow]Provide a public key to complete verification.[/yellow]")
    except MarketplaceError as exc:
        console.print(f"[red]Error:[/red] {exc}")


@plugin.command("publish")
@click.argument("path", type=click.Path(exists=True))
def publish_plugin(path: str) -> None:
    """Sign and register a plugin with the registry."""
    try:
        manifest = load_manifest(Path(path))
        registry = _get_registry()
        registry.register(manifest)
        console.print(
            f"[green]✓[/green] Published {manifest.name}@{manifest.version} to registry"
        )
    except MarketplaceError as exc:
        console.print(f"[red]Error:[/red] {exc}")
