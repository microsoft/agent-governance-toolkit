# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""AGT 5.0 command-line entry points.

This subpackage hosts the user-facing CLIs for the agt-policies package.
The current surface is intentionally small:

- :mod:`agt.cli.migrate` implements ``agt migrate v4-to-v5``, the
  one-shot migration tool described in
  ``plan-v3.md`` §5 / milestone M6.S1.

The package may grow additional sub-commands (lint, validate, render)
in subsequent milestones; new sub-commands MUST register themselves
through :func:`agt.cli.__main__.build_parser` so a single
``python -m agt.cli <verb>`` entry point keeps working.
"""

from . import migrate

__all__ = ["migrate"]
