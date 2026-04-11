# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""
AGT ΓÇö Unified CLI for the Agent Governance Toolkit.

Single entry point that namespaces all governance commands:
    agt verify          OWASP ASI compliance verification
    agt integrity       Module integrity checks
    agt lint-policy     Policy file linting
    agt doctor          Diagnose installation health
    agt version         Show installed package versions

Plugin subcommands from other AGT packages are discovered
via the ``agt.commands`` entry-point group.
"""

from __future__ import annotations

import sys
from typing import Any, Dict, Optional

import click

# ---------------------------------------------------------------------------
# Optional rich ΓÇö degrade gracefully if not installed
# ---------------------------------------------------------------------------

try:
    from rich.console import Console as _RichConsole
    from rich.table import Table as _RichTable
    from rich import box as _rich_box

    _console = _RichConsole()
    _console_err = _RichConsole(stderr=True)
    _HAS_RICH = True
except ImportError:  # pragma: no cover
    _HAS_RICH = False
    _console = None  # type: ignore[assignment]
    _console_err = None  # type: ignore[assignment]


def _print(msg: str, *, style: str = "", err: bool = False) -> None:
    """Print with optional rich styling; falls back to plain print."""
    if _HAS_RICH and style:
        target = _console_err if err else _console
        target.print(msg, style=style)  # type: ignore[union-attr]
    else:
        print(msg, file=sys.stderr if err else sys.stdout)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _get_package_version(package_name: str) -> Optional[str]:
    """Return installed version via importlib.metadata, or None."""
    try:
        from importlib.metadata import version

        return version(package_name)
    except Exception:
        return None


def _discover_plugins() -> Dict[str, click.Command]:
    """Discover plugin commands from the ``agt.commands`` entry-point group."""
    plugins: Dict[str, click.Command] = {}
    try:
        if sys.version_info >= (3, 10):
            from importlib.metadata import entry_points

            eps = entry_points(group="agt.commands")
        else:
            from importlib.metadata import entry_points

            all_eps = entry_points()
            eps = all_eps.get("agt.commands", [])

        for ep in eps:
            try:
                obj = ep.load()
                if isinstance(obj, click.Command):
                    plugins[ep.name] = obj
                elif callable(obj):
                    # Adapter: callable that returns a click command
                    result = obj()
                    if isinstance(result, click.Command):
                        plugins[ep.name] = result
            except Exception:
                # Plugin failed to load ΓÇö silently skip; `doctor` will report it
                pass
    except Exception:
        pass
    return plugins


# ---------------------------------------------------------------------------
# Global context object
# ---------------------------------------------------------------------------


class AgtContext:
    """Shared context passed to all subcommands via ``click.Context.obj``."""

    def __init__(
        self,
        output_json: bool = False,
        verbose: bool = False,
        quiet: bool = False,
        no_color: bool = False,
    ):
        self.output_json = output_json
        self.verbose = verbose
        self.quiet = quiet
        self.no_color = no_color


# ---------------------------------------------------------------------------
# Root group
# ---------------------------------------------------------------------------


class AgtGroup(click.Group):
    """Custom group that merges built-in and plugin commands."""

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        super().__init__(*args, **kwargs)
        self._plugins_loaded = False

    def _ensure_plugins(self) -> None:
        if self._plugins_loaded:
            return
        self._plugins_loaded = True
        for name, cmd in _discover_plugins().items():
            if name not in self.commands:
                self.add_command(cmd, name)

    def list_commands(self, ctx: click.Context) -> list[str]:
        self._ensure_plugins()
        return sorted(super().list_commands(ctx))

    def get_command(self, ctx: click.Context, cmd_name: str) -> Optional[click.Command]:
        self._ensure_plugins()
        return super().get_command(ctx, cmd_name)


@click.group(cls=AgtGroup)
@click.option("--json", "output_json", is_flag=True, default=False, help="Output in JSON format.")
@click.option("--verbose", "-v", is_flag=True, default=False, help="Increase output verbosity.")
@click.option("--quiet", "-q", is_flag=True, default=False, help="Suppress non-essential output.")
@click.option("--no-color", is_flag=True, default=False, help="Disable colored output.")
@click.version_option(
    version=_get_package_version("agent_governance_toolkit") or "unknown",
    prog_name="agt",
)
@click.pass_context
def cli(ctx: click.Context, output_json: bool, verbose: bool, quiet: bool, no_color: bool) -> None:
    """
    AGT ΓÇö Agent Governance Toolkit CLI.

    Unified command-line interface for governing AI agents.

    \b
    Quick start:
        agt verify              Check OWASP ASI compliance
        agt doctor              Diagnose installation health
        agt lint-policy ./dir   Lint policy files
        agt integrity           Verify module integrity

    \b
    Plugin commands from installed AGT packages (mesh, sre, etc.)
    are auto-discovered and appear below when installed.
    """
    ctx.ensure_object(dict)
    ctx.obj = AgtContext(
        output_json=output_json,
        verbose=verbose,
        quiet=quiet,
        no_color=no_color,
    )


# ---------------------------------------------------------------------------
# Built-in commands
# ---------------------------------------------------------------------------


@cli.command()
@click.option("--badge", is_flag=True, default=False, help="Output markdown badge only.")
@click.pass_obj
def verify(ctx_obj: AgtContext, badge: bool) -> None:
    """Run OWASP ASI 2026 governance verification."""
    try:
        from agent_compliance.verify import GovernanceVerifier

        verifier = GovernanceVerifier()
        attestation = verifier.verify()

        if ctx_obj.output_json:
            click.echo(attestation.to_json())
        elif badge:
            click.echo(attestation.badge_markdown())
        else:
            click.echo(attestation.summary())

        if not attestation.passed:
            raise SystemExit(1)
    except SystemExit:
        raise
    except Exception as e:
        _handle_error(e, ctx_obj.output_json)
        raise SystemExit(1)


@cli.command()
@click.option("--manifest", type=click.Path(), default=None, help="Path to integrity.json manifest.")
@click.option("--generate", type=click.Path(), default=None, metavar="OUTPUT_PATH", help="Generate manifest at path.")
@click.pass_obj
def integrity(ctx_obj: AgtContext, manifest: Optional[str], generate: Optional[str]) -> None:
    """Verify or generate module integrity manifest."""
    import json as json_mod

    try:
        if generate and manifest:
            _print("Error: --manifest and --generate are mutually exclusive", style="red", err=True)
            raise SystemExit(1)

        from agent_compliance.integrity import IntegrityVerifier

        if generate:
            verifier = IntegrityVerifier()
            result = verifier.generate_manifest(generate)
            if ctx_obj.output_json:
                click.echo(json_mod.dumps({"status": "ok", "path": generate, "files": len(result["files"]), "functions": len(result["functions"])}, indent=2))
            else:
                click.echo(f"Manifest written to {generate}")
                click.echo(f"  Files hashed: {len(result['files'])}")
                click.echo(f"  Functions hashed: {len(result['functions'])}")
            return

        import os

        if manifest and not os.path.exists(manifest):
            _print(f"Error: manifest file not found: {manifest}", style="red", err=True)
            raise SystemExit(1)

        verifier = IntegrityVerifier(manifest_path=manifest)
        report = verifier.verify()

        if ctx_obj.output_json:
            click.echo(json_mod.dumps(report.to_dict(), indent=2))
        else:
            click.echo(report.summary())

        if not report.passed:
            raise SystemExit(1)
    except SystemExit:
        raise
    except Exception as e:
        _handle_error(e, ctx_obj.output_json)
        raise SystemExit(1)


@cli.command("lint-policy")
@click.argument("path", type=click.Path(exists=True))
@click.option("--strict", is_flag=True, default=False, help="Treat warnings as errors.")
@click.pass_obj
def lint_policy(ctx_obj: AgtContext, path: str, strict: bool) -> None:
    """Lint YAML policy files for common mistakes."""
    import json as json_mod

    try:
        from agent_compliance.lint_policy import lint_path

        result = lint_path(path)

        if ctx_obj.output_json:
            click.echo(json_mod.dumps(result.to_dict(), indent=2))
        else:
            for msg in result.messages:
                click.echo(msg)
            if result.messages:
                click.echo()
            click.echo(result.summary())

        if strict and result.warnings:
            raise SystemExit(1)
        if not result.passed:
            raise SystemExit(1)
    except SystemExit:
        raise
    except Exception as e:
        _handle_error(e, ctx_obj.output_json)
        raise SystemExit(1)


# ---------------------------------------------------------------------------
# Doctor command
# ---------------------------------------------------------------------------

_AGT_PACKAGES = [
    ("agent_governance_toolkit", "Agent Governance Toolkit", "Meta-package & compliance CLI"),
    ("agent_os_kernel", "Agent OS Kernel", "Policy engine & framework integrations"),
    ("agentmesh_platform", "AgentMesh Platform", "Zero-trust identity & trust scoring"),
    ("agentmesh_runtime", "AgentMesh Runtime", "Execution supervisor & privilege rings"),
    ("agent_sre", "Agent SRE", "SLOs, error budgets & chaos testing"),
    ("agentmesh_marketplace", "AgentMesh Marketplace", "Plugin lifecycle management"),
    ("agentmesh_lightning", "AgentMesh Lightning", "RL training governance"),
    ("agent_hypervisor", "Agent Hypervisor", "Session management & kill switch"),
]


@cli.command()
@click.pass_obj
def doctor(ctx_obj: AgtContext) -> None:
    """Diagnose AGT installation health.

    Checks installed packages, versions, Python compatibility,
    and plugin registration status.
    """
    import json as json_mod
    import platform

    py_version = platform.python_version()
    results: list[Dict[str, Any]] = []

    for pkg_name, display_name, description in _AGT_PACKAGES:
        ver = _get_package_version(pkg_name)
        results.append({
            "package": pkg_name,
            "name": display_name,
            "description": description,
            "installed": ver is not None,
            "version": ver,
        })

    # Check for plugin registrations
    plugins = _discover_plugins()

    # Check config files
    from pathlib import Path

    config_locations = [
        Path.cwd() / "agentmesh.yaml",
        Path.cwd() / "policies",
        Path.cwd() / "integrity.json",
    ]
    config_found = {str(p): p.exists() for p in config_locations}

    if ctx_obj.output_json:
        report = {
            "python_version": py_version,
            "packages": results,
            "plugins": list(plugins.keys()),
            "config_files": config_found,
        }
        click.echo(json_mod.dumps(report, indent=2))
        return

    # Rich table output
    _print(f"\n≡ƒ⌐║ AGT Doctor ΓÇö Python {py_version}", style="bold blue")
    _print("")

    installed_count = sum(1 for r in results if r["installed"])
    total_count = len(results)

    if _HAS_RICH and _console is not None and not ctx_obj.no_color:
        table = _RichTable(
            title="Installed Packages",
            box=_rich_box.ROUNDED,
            show_lines=False,
        )
        table.add_column("Package", style="cyan", no_wrap=True)
        table.add_column("Version", style="green")
        table.add_column("Status")
        table.add_column("Description", style="dim")

        for r in results:
            status = "[green]Γ£ô installed[/green]" if r["installed"] else "[dim]┬╖ not installed[/dim]"
            ver = r["version"] or "ΓÇö"
            table.add_row(r["package"], ver, status, r["description"])

        _console.print(table)
    else:
        click.echo("Installed Packages:")
        click.echo("-" * 70)
        for r in results:
            status = "Γ£ô" if r["installed"] else "┬╖"
            ver = r["version"] or "ΓÇö"
            click.echo(f"  {status} {r['package']:30s} {ver:12s} {r['description']}")

    _print(f"\n  {installed_count}/{total_count} packages installed", style="bold")

    # Plugins
    if plugins:
        _print(f"\n  Plugin commands: {', '.join(sorted(plugins.keys()))}", style="green")
    else:
        _print("\n  No plugin commands registered (install AGT packages with [full] extras)", style="dim")

    # Config files
    _print("\n  Config files:", style="bold")
    for path_str, exists in config_found.items():
        icon = "Γ£ô" if exists else "┬╖"
        _print(f"    {icon} {path_str}")

    _print("")


# ---------------------------------------------------------------------------
# Error handling
# ---------------------------------------------------------------------------


def _handle_error(e: Exception, output_json: bool = False) -> None:
    """Centralized error handler."""
    import json as json_mod

    is_known = isinstance(
        e, (IOError, ValueError, KeyError, PermissionError, FileNotFoundError)
    )

    if output_json:
        err_type = "ValidationError" if is_known else "InternalError"
        err_msg = str(e) if is_known else "An internal error occurred"
        click.echo(json_mod.dumps({"status": "error", "message": err_msg, "type": err_type}, indent=2))
    else:
        if is_known:
            _print(f"Error: {e}", style="red", err=True)
        else:
            _print("Error: An internal error occurred", style="red", err=True)
            import os
            if os.environ.get("AGENTOS_DEBUG"):
                _print(f"  {e}", style="dim", err=True)


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------


def main() -> None:
    """Console-script entry point."""
    cli(standalone_mode=True)


if __name__ == "__main__":
    main()
