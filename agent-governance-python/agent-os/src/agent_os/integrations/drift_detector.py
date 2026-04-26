# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""Drift Detector — detects configuration and behavioral drift across agents.

Compares agent configurations, policies, and trust states across
repositories or environments to identify inconsistencies.

Usage::

    from agent_os.integrations.drift_detector import (
        DriftDetector, DriftType,
    )

    detector = DriftDetector()
    findings = detector.compare_configs(
        source_config={"max_tokens": 4096, "timeout": 300},
        target_config={"max_tokens": 2048, "timeout": 300},
        label="staging-vs-prod",
    )
    for f in findings:
        print(f"{f.drift_type.value}: {f.field} — {f.message}")
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any

logger = logging.getLogger(__name__)


# ── Enums & value objects ──────────────────────────────────────


class DriftType(Enum):
    """Categories of drift that can be detected."""

    CONFIG_DRIFT = "config_drift"
    POLICY_DRIFT = "policy_drift"
    TRUST_DRIFT = "trust_drift"
    VERSION_DRIFT = "version_drift"
    CAPABILITY_DRIFT = "capability_drift"


@dataclass
class DriftFinding:
    """A single drift finding.

    Attributes:
        drift_type: Category of drift.
        severity: ``"info"``, ``"warning"``, or ``"critical"``.
        source: Label for the source side.
        target: Label for the target side.
        field: Configuration or policy field that drifted.
        expected: Value on the source side.
        actual: Value on the target side.
        message: Human-readable description.
    """

    drift_type: DriftType
    severity: str
    source: str
    target: str
    field: str
    expected: Any
    actual: Any
    message: str


@dataclass
class DriftReport:
    """Aggregate drift report.

    Attributes:
        findings: All drift findings.
        scanned_at: UTC timestamp of the scan.
        sources_scanned: Number of sources compared.
        summary: Brief textual summary.
    """

    findings: list[DriftFinding] = field(default_factory=list)
    scanned_at: str = ""
    sources_scanned: int = 0
    summary: str = ""


# ── Drift Detector ─────────────────────────────────────────────


class DriftDetector:
    """Detects configuration and behavioral drift across agents or environments.

    All comparison methods return lists of :class:`DriftFinding`; the
    high-level :meth:`scan` method accepts a list of source dicts and
    produces a :class:`DriftReport`.
    """

    # ── public comparison methods ───────────────────────────

    def compare_configs(
        self,
        source_config: dict[str, Any],
        target_config: dict[str, Any],
        label: str = "",
    ) -> list[DriftFinding]:
        """Compare two configuration dicts and return findings for each diff.

        Args:
            source_config: Reference configuration.
            target_config: Configuration to compare against.
            label: Optional human-readable label for this comparison.

        Returns:
            List of :class:`DriftFinding` for every key that differs.
        """
        source_label = f"{label}/source" if label else "source"
        target_label = f"{label}/target" if label else "target"
        findings: list[DriftFinding] = []

        all_keys = set(source_config) | set(target_config)
        for key in sorted(all_keys):
            src_val = source_config.get(key)
            tgt_val = target_config.get(key)
            if src_val != tgt_val:
                severity = self._config_severity(key, src_val, tgt_val)
                findings.append(
                    DriftFinding(
                        drift_type=DriftType.CONFIG_DRIFT,
                        severity=severity,
                        source=source_label,
                        target=target_label,
                        field=key,
                        expected=src_val,
                        actual=tgt_val,
                        message=self._config_message(key, src_val, tgt_val),
                    )
                )
        return findings

    def compare_policies(
        self,
        source_policies: dict[str, Any],
        target_policies: dict[str, Any],
    ) -> list[DriftFinding]:
        """Compare two policy dicts and return drift findings.

        Missing keys on either side are flagged as *critical* drift.

        Args:
            source_policies: Reference policy set.
            target_policies: Policy set to compare.

        Returns:
            List of :class:`DriftFinding`.
        """
        findings: list[DriftFinding] = []
        all_keys = set(source_policies) | set(target_policies)

        for key in sorted(all_keys):
            src = source_policies.get(key)
            tgt = target_policies.get(key)
            if src == tgt:
                continue

            if src is None:
                severity = "critical"
                message = f"Policy '{key}' exists only in target"
            elif tgt is None:
                severity = "critical"
                message = f"Policy '{key}' missing in target"
            else:
                severity = "warning"
                message = f"Policy '{key}' differs: {src!r} vs {tgt!r}"

            findings.append(
                DriftFinding(
                    drift_type=DriftType.POLICY_DRIFT,
                    severity=severity,
                    source="source_policies",
                    target="target_policies",
                    field=key,
                    expected=src,
                    actual=tgt,
                    message=message,
                )
            )
        return findings

    def compare_trust_scores(
        self,
        source_scores: dict[str, float],
        target_scores: dict[str, float],
        tolerance: float = 0.1,
    ) -> list[DriftFinding]:
        """Compare trust scores, flagging differences beyond *tolerance*.

        Args:
            source_scores: Reference trust scores keyed by agent id.
            target_scores: Trust scores to compare.
            tolerance: Maximum allowed absolute difference before flagging.

        Returns:
            List of :class:`DriftFinding` for scores that drifted.
        """
        findings: list[DriftFinding] = []
        all_agents = set(source_scores) | set(target_scores)

        for agent in sorted(all_agents):
            src = source_scores.get(agent)
            tgt = target_scores.get(agent)

            if src is None or tgt is None:
                findings.append(
                    DriftFinding(
                        drift_type=DriftType.TRUST_DRIFT,
                        severity="warning",
                        source="source_scores",
                        target="target_scores",
                        field=agent,
                        expected=src,
                        actual=tgt,
                        message=(
                            f"Trust score for '{agent}' missing on "
                            f"{'source' if src is None else 'target'} side"
                        ),
                    )
                )
                continue

            diff = abs(src - tgt)
            if diff > tolerance:
                severity = "critical" if diff > tolerance * 3 else "warning"
                findings.append(
                    DriftFinding(
                        drift_type=DriftType.TRUST_DRIFT,
                        severity=severity,
                        source="source_scores",
                        target="target_scores",
                        field=agent,
                        expected=src,
                        actual=tgt,
                        message=(
                            f"Trust score for '{agent}' drifted by "
                            f"{diff:.3f} (tolerance={tolerance})"
                        ),
                    )
                )
        return findings

    def detect_version_drift(
        self, components: dict[str, str]
    ) -> list[DriftFinding]:
        """Find out-of-sync versions among components.

        Expects a dict mapping component names to version strings.  When
        two or more distinct versions exist among *all* components that
        share a common prefix (before the first ``-`` or ``/``), drift is
        flagged.

        For simpler use, the method also detects mixed version patterns
        among *all* supplied components.

        Args:
            components: Mapping of ``component_name → version_string``.

        Returns:
            List of :class:`DriftFinding` for version mismatches.
        """
        findings: list[DriftFinding] = []
        if not components:
            return findings

        # Group by prefix (e.g. "agent-governance-python/agent-os/kernel" → "agent-os")
        groups: dict[str, dict[str, str]] = {}
        for name, version in components.items():
            prefix = name.split("-")[0].split("/")[0]
            groups.setdefault(prefix, {})[name] = version

        for prefix, members in sorted(groups.items()):
            versions = set(members.values())
            if len(versions) <= 1:
                continue

            for name, version in sorted(members.items()):
                majority = max(versions, key=lambda v: list(members.values()).count(v))
                if version != majority:
                    findings.append(
                        DriftFinding(
                            drift_type=DriftType.VERSION_DRIFT,
                            severity="warning",
                            source=prefix,
                            target=name,
                            field="version",
                            expected=majority,
                            actual=version,
                            message=(
                                f"Component '{name}' at version {version} "
                                f"differs from majority {majority}"
                            ),
                        )
                    )
        return findings

    def scan(self, sources: list[dict[str, Any]]) -> DriftReport:
        """Run a comprehensive scan over multiple source dicts.

        Each source dict must contain a ``"label"`` key and at least one of:
            - ``"config"`` — configuration dict
            - ``"policies"`` — policy dict
            - ``"trust_scores"`` — agent trust score dict
            - ``"components"`` — version component dict

        Pairwise comparisons are performed between successive sources.

        Args:
            sources: List of source dicts to compare.

        Returns:
            A :class:`DriftReport`.
        """
        all_findings: list[DriftFinding] = []

        for i in range(len(sources) - 1):
            src = sources[i]
            tgt = sources[i + 1]
            label = f"{src.get('label', f'src-{i}')}-vs-{tgt.get('label', f'src-{i+1}')}"

            if "config" in src and "config" in tgt:
                all_findings.extend(
                    self.compare_configs(src["config"], tgt["config"], label)
                )

            if "policies" in src and "policies" in tgt:
                all_findings.extend(
                    self.compare_policies(src["policies"], tgt["policies"])
                )

            if "trust_scores" in src and "trust_scores" in tgt:
                tolerance = src.get("trust_tolerance", tgt.get("trust_tolerance", 0.1))
                all_findings.extend(
                    self.compare_trust_scores(
                        src["trust_scores"], tgt["trust_scores"], tolerance
                    )
                )

        # Version drift across all sources that have components
        all_components: dict[str, str] = {}
        for src in sources:
            all_components.update(src.get("components", {}))
        if all_components:
            all_findings.extend(self.detect_version_drift(all_components))

        critical = sum(1 for f in all_findings if f.severity == "critical")
        warnings = sum(1 for f in all_findings if f.severity == "warning")
        info = sum(1 for f in all_findings if f.severity == "info")

        report = DriftReport(
            findings=all_findings,
            scanned_at=datetime.now(timezone.utc).isoformat(),
            sources_scanned=len(sources),
            summary=(
                f"{len(all_findings)} finding(s): "
                f"{critical} critical, {warnings} warning, {info} info"
            ),
        )
        return report

    def to_markdown(self, report: DriftReport) -> str:
        """Render a :class:`DriftReport` as a Markdown string.

        Args:
            report: The report to render.

        Returns:
            Markdown-formatted string.
        """
        lines = [
            "# Drift Detection Report",
            "",
            f"**Scanned at:** {report.scanned_at}  ",
            f"**Sources scanned:** {report.sources_scanned}  ",
            f"**Summary:** {report.summary}",
            "",
        ]

        if not report.findings:
            lines.append("✅ No drift detected.")
            return "\n".join(lines)

        lines.append("| Severity | Type | Field | Expected | Actual | Message |")
        lines.append("|----------|------|-------|----------|--------|---------|")

        for f in report.findings:
            lines.append(
                f"| {f.severity} | {f.drift_type.value} | {f.field} "
                f"| {f.expected} | {f.actual} | {f.message} |"
            )

        return "\n".join(lines)

    # ── internal helpers ────────────────────────────────────

    @staticmethod
    def _config_severity(
        key: str, src_val: Any, tgt_val: Any
    ) -> str:
        """Determine severity of a config difference."""
        if src_val is None or tgt_val is None:
            return "critical"
        if isinstance(src_val, (int, float)) and isinstance(tgt_val, (int, float)):
            if src_val != 0 and abs(src_val - tgt_val) / abs(src_val) > 0.5:
                return "warning"
        return "info"

    @staticmethod
    def _config_message(key: str, src_val: Any, tgt_val: Any) -> str:
        """Build human-readable config diff message."""
        if src_val is None:
            return f"Key '{key}' only in target (value={tgt_val!r})"
        if tgt_val is None:
            return f"Key '{key}' missing in target (source={src_val!r})"
        return f"Key '{key}' differs: {src_val!r} → {tgt_val!r}"
