# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""
MCP Tool Drift Detection for Agent-SRE.

Detects when MCP (Model Context Protocol) server tool schemas change,
new tools appear, or tools disappear — creating reliability risks.

Components:
- ToolSnapshot: Point-in-time record of an MCP server's tool manifest
- DriftDetector: Compares snapshots to detect schema drift
- DriftAlert: Categorized alerts for different drift types
"""

from __future__ import annotations

import hashlib
import json
import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional, Set


class DriftType(Enum):
    """Types of MCP tool drift."""

    TOOL_ADDED = "tool_added"
    TOOL_REMOVED = "tool_removed"
    SCHEMA_CHANGED = "schema_changed"
    PARAMETER_ADDED = "parameter_added"
    PARAMETER_REMOVED = "parameter_removed"
    TYPE_CHANGED = "type_changed"
    DESCRIPTION_CHANGED = "description_changed"
    REQUIRED_CHANGED = "required_changed"


class DriftSeverity(Enum):
    """Severity of a drift event."""

    INFO = "info"  # Description changes, new optional params
    WARNING = "warning"  # New tools, new required params
    CRITICAL = "critical"  # Tool removed, type changed, required param removed


@dataclass
class ToolSchema:
    """Schema of a single MCP tool."""

    name: str
    description: str = ""
    parameters: dict[str, Any] = field(default_factory=dict)
    required: list[str] = field(default_factory=list)

    def fingerprint(self) -> str:
        """Content hash for change detection."""
        content = json.dumps({
            "name": self.name,
            "description": self.description,
            "parameters": self.parameters,
            "required": sorted(self.required),
        }, sort_keys=True)
        return hashlib.sha256(content.encode()).hexdigest()[:16]

    def to_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "description": self.description,
            "parameters": self.parameters,
            "required": self.required,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> ToolSchema:
        return cls(
            name=data.get("name", ""),
            description=data.get("description", ""),
            parameters=data.get("parameters", {}),
            required=data.get("required", []),
        )


@dataclass
class ToolSnapshot:
    """Point-in-time snapshot of an MCP server's tool manifest."""

    server_id: str
    tools: list[ToolSchema] = field(default_factory=list)
    timestamp: float = field(default_factory=time.time)
    metadata: dict[str, Any] = field(default_factory=dict)

    @property
    def tool_names(self) -> set[str]:
        return {t.name for t in self.tools}

    def get_tool(self, name: str) -> ToolSchema | None:
        for t in self.tools:
            if t.name == name:
                return t
        return None

    def fingerprint(self) -> str:
        """Combined fingerprint of all tools."""
        parts = sorted(t.fingerprint() for t in self.tools)
        return hashlib.sha256("|".join(parts).encode()).hexdigest()[:16]

    def to_dict(self) -> dict[str, Any]:
        return {
            "server_id": self.server_id,
            "tools": [t.to_dict() for t in self.tools],
            "timestamp": self.timestamp,
            "fingerprint": self.fingerprint(),
        }


@dataclass
class DriftAlert:
    """A single drift event detected between snapshots."""

    drift_type: DriftType
    severity: DriftSeverity
    tool_name: str
    message: str
    details: dict[str, Any] = field(default_factory=dict)
    timestamp: float = field(default_factory=time.time)

    def to_dict(self) -> dict[str, Any]:
        return {
            "drift_type": self.drift_type.value,
            "severity": self.severity.value,
            "tool_name": self.tool_name,
            "message": self.message,
            "details": self.details,
        }


@dataclass
class DriftReport:
    """Complete drift analysis between two snapshots."""

    server_id: str
    baseline_fingerprint: str
    current_fingerprint: str
    alerts: list[DriftAlert] = field(default_factory=list)
    has_drift: bool = False
    timestamp: float = field(default_factory=time.time)

    @property
    def critical_count(self) -> int:
        return sum(1 for a in self.alerts if a.severity == DriftSeverity.CRITICAL)

    @property
    def warning_count(self) -> int:
        return sum(1 for a in self.alerts if a.severity == DriftSeverity.WARNING)

    def to_dict(self) -> dict[str, Any]:
        return {
            "server_id": self.server_id,
            "has_drift": self.has_drift,
            "baseline_fingerprint": self.baseline_fingerprint,
            "current_fingerprint": self.current_fingerprint,
            "critical": self.critical_count,
            "warnings": self.warning_count,
            "total_alerts": len(self.alerts),
            "alerts": [a.to_dict() for a in self.alerts],
        }


class DriftDetector:
    """
    Detects drift between MCP tool snapshots.

    Usage:
        detector = DriftDetector()

        # Record baseline
        detector.set_baseline(snapshot_v1)

        # Later, check for drift
        report = detector.compare(snapshot_v2)
        if report.has_drift:
            for alert in report.alerts:
                print(f"[{alert.severity.value}] {alert.message}")
    """

    def __init__(self) -> None:
        self._baselines: dict[str, ToolSnapshot] = {}
        self._history: list[DriftReport] = []

    def set_baseline(self, snapshot: ToolSnapshot) -> None:
        """Set the baseline snapshot for a server."""
        self._baselines[snapshot.server_id] = snapshot

    def get_baseline(self, server_id: str) -> ToolSnapshot | None:
        return self._baselines.get(server_id)

    def compare(self, current: ToolSnapshot) -> DriftReport:
        """Compare current snapshot against baseline."""
        baseline = self._baselines.get(current.server_id)

        if baseline is None:
            # No baseline — set this as baseline, no drift
            self._baselines[current.server_id] = current
            report = DriftReport(
                server_id=current.server_id,
                baseline_fingerprint="",
                current_fingerprint=current.fingerprint(),
                has_drift=False,
            )
            self._history.append(report)
            return report

        alerts: list[DriftAlert] = []

        # Check for removed tools
        removed = baseline.tool_names - current.tool_names
        for name in removed:
            alerts.append(DriftAlert(
                drift_type=DriftType.TOOL_REMOVED,
                severity=DriftSeverity.CRITICAL,
                tool_name=name,
                message=f"Tool '{name}' was removed from server '{current.server_id}'",
            ))

        # Check for added tools
        added = current.tool_names - baseline.tool_names
        for name in added:
            alerts.append(DriftAlert(
                drift_type=DriftType.TOOL_ADDED,
                severity=DriftSeverity.WARNING,
                tool_name=name,
                message=f"New tool '{name}' added to server '{current.server_id}'",
            ))

        # Check for schema changes in existing tools
        common = baseline.tool_names & current.tool_names
        for name in common:
            old_tool = baseline.get_tool(name)
            new_tool = current.get_tool(name)
            if old_tool and new_tool:
                alerts.extend(self._compare_tool(name, old_tool, new_tool))

        report = DriftReport(
            server_id=current.server_id,
            baseline_fingerprint=baseline.fingerprint(),
            current_fingerprint=current.fingerprint(),
            alerts=alerts,
            has_drift=len(alerts) > 0,
        )
        self._history.append(report)
        return report

    def _compare_tool(
        self, name: str, old: ToolSchema, new: ToolSchema
    ) -> list[DriftAlert]:
        """Compare two versions of the same tool."""
        alerts: list[DriftAlert] = []

        # Description change
        if old.description != new.description:
            alerts.append(DriftAlert(
                drift_type=DriftType.DESCRIPTION_CHANGED,
                severity=DriftSeverity.INFO,
                tool_name=name,
                message=f"Tool '{name}' description changed",
                details={"old": old.description, "new": new.description},
            ))

        # Parameter changes
        old_params = set(old.parameters.keys())
        new_params = set(new.parameters.keys())

        for p in new_params - old_params:
            sev = DriftSeverity.CRITICAL if p in new.required else DriftSeverity.WARNING
            alerts.append(DriftAlert(
                drift_type=DriftType.PARAMETER_ADDED,
                severity=sev,
                tool_name=name,
                message=f"Parameter '{p}' added to tool '{name}'" + (
                    " (REQUIRED)" if p in new.required else ""
                ),
                details={"parameter": p, "schema": new.parameters.get(p)},
            ))

        for p in old_params - new_params:
            alerts.append(DriftAlert(
                drift_type=DriftType.PARAMETER_REMOVED,
                severity=DriftSeverity.CRITICAL,
                tool_name=name,
                message=f"Parameter '{p}' removed from tool '{name}'",
            ))

        # Type changes in common parameters
        for p in old_params & new_params:
            old_schema = old.parameters.get(p, {})
            new_schema = new.parameters.get(p, {})
            if isinstance(old_schema, dict) and isinstance(new_schema, dict):
                old_type = old_schema.get("type")
                new_type = new_schema.get("type")
                if old_type and new_type and old_type != new_type:
                    alerts.append(DriftAlert(
                        drift_type=DriftType.TYPE_CHANGED,
                        severity=DriftSeverity.CRITICAL,
                        tool_name=name,
                        message=f"Parameter '{p}' in tool '{name}' type changed: {old_type} → {new_type}",
                        details={"parameter": p, "old_type": old_type, "new_type": new_type},
                    ))

        # Required field changes
        old_required = set(old.required)
        new_required = set(new.required)
        if old_required != new_required:
            added_req = new_required - old_required
            removed_req = old_required - new_required
            if added_req or removed_req:
                alerts.append(DriftAlert(
                    drift_type=DriftType.REQUIRED_CHANGED,
                    severity=DriftSeverity.CRITICAL if removed_req else DriftSeverity.WARNING,
                    tool_name=name,
                    message=f"Required fields changed for tool '{name}'",
                    details={
                        "added_required": list(added_req),
                        "removed_required": list(removed_req),
                    },
                ))

        return alerts

    def update_baseline(self, snapshot: ToolSnapshot) -> None:
        """Update baseline after acknowledging drift."""
        self._baselines[snapshot.server_id] = snapshot

    @property
    def history(self) -> list[DriftReport]:
        return list(self._history)

    def get_stats(self) -> dict[str, Any]:
        return {
            "servers_tracked": len(self._baselines),
            "total_comparisons": len(self._history),
            "drift_detected": sum(1 for r in self._history if r.has_drift),
        }
