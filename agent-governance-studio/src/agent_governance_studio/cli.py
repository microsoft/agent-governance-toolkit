# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""Lightweight Click entry point: importing it never imports the API/server."""

import click


@click.command()
@click.option("--host", default="127.0.0.1", show_default=True, help="Only literal IPv4 loopback is supported.")
@click.option("--port", default=8080, type=click.IntRange(1, 65535), show_default=True)
@click.option("--policy-dir", type=click.Path(path_type=str), help="Read-only policy root; otherwise explicitly empty.")
@click.pass_context
def serve(ctx: click.Context, host: str, port: int, policy_dir: str | None) -> None:
    """Serve the proposed save-disabled Studio Engine API in the foreground."""
    from .config import ConfigurationError, configure

    try:
        config = configure(host, port, policy_dir)
        from .server import run

        run(config, quiet=bool(getattr(ctx.obj, "quiet", False)))
    except ConfigurationError as exc:
        raise click.ClickException(str(exc)) from None
    except (ImportError, AttributeError):
        raise click.ClickException(
            "Studio runtime is missing or incompatible. Install the matching Studio, core, "
            "compliance and native ACS wheels and the documented OPA executable."
        ) from None
    except (OSError, RuntimeError):
        raise click.ClickException(
            "Studio listener or owned-resource lifecycle failed. Check the documented runtime, "
            "port availability and temporary-directory permissions."
        ) from None
