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
from agent_marketplace.schema_adapters import (
    adapt_to_canonical,
    detect_manifest_format,
    extract_capabilities,
    extract_mcp_servers,
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
@click.option(
    "--format",
    "manifest_format",
    type=click.Choice(["auto", "copilot-plugin", "claude-plugin", "generic"]),
    default="auto",
    help="Manifest format (auto-detected by default)",
)
def verify_plugin(path: str, manifest_format: str) -> None:
    """Verify a plugin manifest, with optional format detection for Copilot/Claude plugins."""
    import json

    import yaml

    plugin_path = Path(path)

    try:
        # For non-auto generic format or YAML files, use the existing loader
        if manifest_format == "generic":
            manifest = load_manifest(plugin_path)
            _print_verify_result(manifest)
            return

        # Load raw data for format-aware validation
        target = plugin_path
        if target.is_dir():
            # Try plugin.json first, then fall back to agent-plugin.yaml
            json_path = target / "plugin.json"
            yaml_path = target / "agent-plugin.yaml"
            if json_path.exists():
                target = json_path
            elif yaml_path.exists():
                target = yaml_path
            else:
                raise MarketplaceError(f"No manifest found in {target}")

        text = target.read_text(encoding="utf-8")
        if target.suffix == ".json":
            data = json.loads(text)
        else:
            data = yaml.safe_load(text)

        # Determine format
        if manifest_format == "auto":
            fmt = detect_manifest_format(data)
        elif manifest_format == "copilot-plugin":
            fmt = "copilot"
        elif manifest_format == "claude-plugin":
            fmt = "claude"
        else:
            fmt = "generic"

        if fmt == "generic":
            manifest = load_manifest(plugin_path)
        else:
            manifest = adapt_to_canonical(data, fmt)

        console.print(f"[dim]Detected format:[/dim] {fmt}")
        _print_verify_result(manifest)

        servers = extract_mcp_servers(data)
        if servers:
            console.print(f"[dim]MCP servers:[/dim] {', '.join(servers)}")

    except MarketplaceError as exc:
        console.print(f"[red]Error:[/red] {exc}")


def _print_verify_result(manifest: "PluginManifest") -> None:
    """Print verification summary for a loaded manifest."""
    console.print(f"[green]✓[/green] Manifest loaded: {manifest.name}@{manifest.version}")
    if manifest.capabilities:
        console.print(f"[dim]Capabilities:[/dim] {', '.join(manifest.capabilities)}")
    if manifest.signature:
        console.print("[yellow]Provide a public key to complete verification.[/yellow]")
    else:
        console.print("[yellow]Plugin has no signature.[/yellow]")


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


# Register batch evaluation command
try:
    from agent_marketplace.batch import evaluate_batch_command

    plugin.add_command(evaluate_batch_command)
except ImportError:
    pass

