# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
# Public Preview — basic implementation
"""Golden trace models and YAML persistence for regression testing."""

from __future__ import annotations

import uuid
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path
from typing import Any

import yaml
from pydantic import BaseModel, Field

from agent_sre.replay.capture import Trace


class TraceSource(str, Enum):
    """Origin of a golden trace."""

    PRODUCTION = "production"
    SYNTHETIC = "synthetic"


class GoldenTrace(BaseModel):
    """A captured trace marked as the expected-correct 'golden' reference."""

    id: str = Field(default_factory=lambda: uuid.uuid4().hex[:16])
    name: str
    description: str = ""
    trace: dict[str, Any]  # Trace.to_dict() serialized form
    expected_output: str
    tolerance: float = 0.0
    labels: list[str] = Field(default_factory=list)
    created_at: str = Field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )
    source: TraceSource = TraceSource.PRODUCTION

    def to_trace(self) -> Trace:
        """Reconstruct the Trace dataclass from stored dict."""
        return Trace.from_dict(self.trace)


class GoldenTraceResult(BaseModel):
    """Outcome of running a single golden trace against an agent function."""

    trace_id: str
    passed: bool
    diffs: list[str] = Field(default_factory=list)
    execution_time: float = 0.0
    actual_output: str = ""


class GoldenSuiteResult(BaseModel):
    """Aggregate outcome of running an entire golden-trace suite."""

    suite_name: str
    total: int
    passed: int
    failed: int
    pass_rate: float
    results: list[GoldenTraceResult] = Field(default_factory=list)
    ci_passed: bool = False


class GoldenTraceSuite(BaseModel):
    """A named collection of golden traces with a CI pass threshold."""

    name: str
    traces: list[GoldenTrace] = Field(default_factory=list)
    pass_threshold: float = 0.95

    # -- YAML persistence ---------------------------------------------------

    def to_yaml(self, path: str | Path) -> None:
        """Serialize the suite to a YAML file."""
        Path(path).write_text(
            yaml.dump(
                self.model_dump(mode="json"),
                default_flow_style=False,
                sort_keys=False,
            ),
            encoding="utf-8",
        )

    @classmethod
    def from_yaml(cls, path: str | Path) -> GoldenTraceSuite:
        """Deserialize a suite from a YAML file."""
        data = yaml.safe_load(Path(path).read_text(encoding="utf-8"))
        return cls.model_validate(data)


def load_golden_suites(directory: str | Path) -> list[GoldenTraceSuite]:
    """Load all golden-trace suites from YAML files in *directory*."""
    suites: list[GoldenTraceSuite] = []
    dir_path = Path(directory)
    if not dir_path.is_dir():
        return suites
    for yml in sorted(dir_path.glob("*.y*ml")):
        suites.append(GoldenTraceSuite.from_yaml(yml))
    return suites
