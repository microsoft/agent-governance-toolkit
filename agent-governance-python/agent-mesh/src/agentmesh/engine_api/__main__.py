# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""CLI entry point for the Engine API reference adapter.

Run with ``python -m agentmesh.engine_api``. Binds to loopback (``127.0.0.1``) by default so
the reference adapter is not exposed on a public interface unless explicitly configured. The
single write endpoint (``POST /api/v1/policy/save``) is disabled unless ``--enable-policy-save``
is passed or ``AGENTMESH_ENABLE_POLICY_SAVE`` is set truthy.
"""

from __future__ import annotations

import argparse
from collections.abc import Sequence

#: Loopback-only default bind address (contract security guidance).
DEFAULT_HOST = "127.0.0.1"

#: Default listen port.
DEFAULT_PORT = 8080


def _build_arg_parser() -> argparse.ArgumentParser:
    """Construct the argument parser for the module entry point."""
    parser = argparse.ArgumentParser(
        prog="python -m agentmesh.engine_api",
        description="Run the AGT Studio Engine API reference adapter.",
    )
    parser.add_argument(
        "--host",
        default=DEFAULT_HOST,
        help=f"Bind address (default: {DEFAULT_HOST}, loopback only).",
    )
    parser.add_argument(
        "--port",
        type=int,
        default=DEFAULT_PORT,
        help=f"Listen port (default: {DEFAULT_PORT}).",
    )
    parser.add_argument(
        "--policy-dir",
        default=None,
        help="Policy directory (defaults to AGENTMESH_POLICY_DIR env var).",
    )
    parser.add_argument(
        "--enable-policy-save",
        action="store_true",
        help=(
            "Enable the POST /api/v1/policy/save write endpoint (disabled by default). "
            "Equivalent to setting AGENTMESH_ENABLE_POLICY_SAVE=1."
        ),
    )
    return parser


def main(argv: Sequence[str] | None = None) -> None:
    """Parse arguments and run the app under uvicorn."""
    import uvicorn

    from agentmesh.engine_api.app import create_app

    args = _build_arg_parser().parse_args(argv)
    # Pass ``True`` only when the flag is present, so an absent flag defers to the
    # AGENTMESH_ENABLE_POLICY_SAVE environment variable inside create_app.
    enable_save = True if args.enable_policy_save else None
    app = create_app(policy_dir=args.policy_dir, enable_policy_save=enable_save)
    uvicorn.run(app, host=args.host, port=args.port)


if __name__ == "__main__":  # pragma: no cover - exercised via the CLI, not unit tests
    main()
