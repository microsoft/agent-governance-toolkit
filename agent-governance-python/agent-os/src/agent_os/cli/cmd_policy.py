# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""``agentos policy`` command dispatcher."""

from __future__ import annotations

import argparse


def cmd_policy(args: argparse.Namespace) -> int:
    """Dispatch 'agentos policy <subcommand>' to the policies CLI.

    Routes ``agentos policy validate <file>`` and related subcommands
    to :mod:`agent_os.policies.cli`, which provides full JSON-Schema
    validation and Pydantic model validation in a single pass.

    Args:
        args: Parsed CLI arguments. Expects ``args.policy_command`` and
            any subcommand-specific attributes set by the policy subparser.

    Returns:
        Exit code from the delegated command (0 = success, 1 = failure,
        2 = runtime error).
    """
    from agent_os.policies import cli as policies_cli  # type: ignore[import]

    sub = getattr(args, "policy_command", None)
    if sub == "validate":
        return policies_cli.cmd_validate(args)
    if sub == "test":
        return policies_cli.cmd_test(args)
    if sub == "diff":
        return policies_cli.cmd_diff(args)

    # No subcommand given — print help
    print("Usage: agentos policy <validate|test|diff>")
    print()
    print("  validate <file>                  Validate a policy YAML/JSON file")
    print("  test <policy> <scenarios>         Run scenario tests against a policy")
    print("  diff <file1> <file2>             Show differences between two policies")
    return 0
