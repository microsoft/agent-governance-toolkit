# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""AGT 5.0 top-level package.

Policy evaluation lives in ``agent_control_specification``. This package now
ships the one-way tool that migrates a v4 project to an ACS manifest.
"""

from . import cli

__all__ = ["cli"]
