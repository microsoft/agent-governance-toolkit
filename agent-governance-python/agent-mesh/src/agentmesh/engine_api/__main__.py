# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""CLI entry point for the Engine API reference adapter.

Run with ``python -m agentmesh.engine_api``. Binds to loopback (``127.0.0.1``) by default so
the reference adapter is not exposed on a public interface unless explicitly configured.
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
    return parser


def main(argv: Sequence[str] | None = None) -> None:
    """Parse arguments and run the app under uvicorn."""
    import uvicorn

    from agentmesh.engine_api.app import create_app

    args = _build_arg_parser().parse_args(argv)
    uvicorn.run(create_app(policy_dir=args.policy_dir), host=args.host, port=args.port)


if __name__ == "__main__":  # pragma: no cover - exercised via the CLI, not unit tests
    main()
