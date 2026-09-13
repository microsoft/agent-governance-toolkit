# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""Native ACS policy command aliases for ``agentos``."""

from __future__ import annotations

import argparse


def cmd_policy(args: argparse.Namespace) -> int:
    """Dispatch ``agentos policy validate`` through native ACS validation."""
    from .cmd_validate import cmd_validate

    sub = getattr(args, "policy_command", None)
    if sub == "validate":
        args.files = [args.path]
        args.strict = bool(getattr(args, "strict", False))
        return cmd_validate(args)

    print("Usage: agentos policy validate <manifest>")
    print()
    print("Use `agt test` for native policy replay.")
    return 0
