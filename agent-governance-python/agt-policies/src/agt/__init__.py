# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""AGT 5.0 top-level package.

``policies`` is the native runtime surface. ``cli`` ships the one-way tool
that migrates a v4 project to an ACS manifest.

``cli`` is resolved lazily. Importing it eagerly pulls in the migrator, which
imports the native SDK at module scope, and that made ``from agt.policies
import AdapterRuntimeSession`` fail on a host that has not installed the
native extension.
"""

from typing import TYPE_CHECKING

from . import policies

if TYPE_CHECKING:  # pragma: no cover - import shape only
    from . import cli

__all__ = ["cli", "policies"]


def __getattr__(name: str):
    if name == "cli":
        from . import cli as _cli

        return _cli
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
