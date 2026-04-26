# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
# Public Preview — basic implementation
"""YAML config loader for chaos schedules."""

from __future__ import annotations

from pathlib import Path
from typing import Any

import yaml

from agent_sre.chaos.scheduler import ChaosSchedule


def load_schedules(path: str | Path) -> list[ChaosSchedule]:
    """Load chaos schedules from a YAML file.

    Args:
        path: Path to the YAML configuration file.

    Returns:
        List of validated ChaosSchedule objects.
    """
    raw: dict[str, Any] = yaml.safe_load(Path(path).read_text())
    entries = raw.get("schedules", [])
    return [ChaosSchedule(**entry) for entry in entries]
