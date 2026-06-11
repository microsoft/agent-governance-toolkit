# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""``python -m agt.cli`` entry point.

Dispatches to one of the registered sub-commands. Today only
``migrate`` is wired; new verbs MUST add a subparser here so users keep
a single CLI surface.
"""

from __future__ import annotations

import argparse
import sys
from typing import Sequence

from . import migrate as migrate_cmd


def build_parser() -> argparse.ArgumentParser:
    """Build the top-level ``agt`` argparse parser."""
    parser = argparse.ArgumentParser(
        prog="agt",
        description=(
            "AGT 5.0 command-line interface. Use 'agt <verb> --help' "
            "for verb-specific options."
        ),
    )
    subparsers = parser.add_subparsers(dest="verb", required=True)

    migrate_parser = subparsers.add_parser(
        "migrate",
        help="Migrate an AGT v4 project to the v5 shape.",
        description=migrate_cmd.CLI_DESCRIPTION,
    )
    migrate_cmd.add_arguments(migrate_parser)
    migrate_parser.set_defaults(func=migrate_cmd.run_from_args)

    return parser


def main(argv: Sequence[str] | None = None) -> int:
    """Entry point invoked by ``python -m agt.cli``."""
    parser = build_parser()
    args = parser.parse_args(argv)
    return int(args.func(args) or 0)


if __name__ == "__main__":
    sys.exit(main())
