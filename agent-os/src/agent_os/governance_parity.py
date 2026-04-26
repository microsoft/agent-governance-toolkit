# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""
CLI vs IDE governance parity detection.

Detects enforcement gaps between CLI-based and IDE-based agent execution
contexts. Reports which governance controls are active in each surface
so operators can identify policy drift.

Usage::

    from agent_os.governance_parity import GovernanceParityChecker

    checker = GovernanceParityChecker()
    checker.register_surface("cli", capabilities=["policy", "audit", "trust", "kill_switch"])
    checker.register_surface("vscode", capabilities=["policy", "audit"])

    report = checker.check_parity()
    for gap in report.gaps:
        print(f"  {gap.surface} missing: {gap.capability}")
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from typing import Optional

logger = logging.getLogger(__name__)

# Standard governance capabilities that should be present in every surface
STANDARD_CAPABILITIES = [
    "policy_enforcement",       # PolicyEngine evaluation
    "audit_logging",            # Tamper-evident audit trail
    "trust_verification",       # Ed25519 identity + trust scoring
    "kill_switch",              # Emergency agent termination
    "rate_limiting",            # Per-agent call budgets
    "prompt_injection_detection",  # Input security scanning
    "mcp_gateway",              # MCP tool call interception
    "approval_workflows",       # Human-in-the-loop
    "session_state",            # Attribute ratchets
    "otel_observability",       # OTel spans and metrics
]


@dataclass
class ParityGap:
    """A governance capability missing from a surface."""

    surface: str
    capability: str
    severity: str  # critical, high, medium, low
    recommendation: str


@dataclass
class SurfaceRegistration:
    """A registered execution surface with its governance capabilities."""

    name: str
    capabilities: set[str] = field(default_factory=set)
    context: str = ""  # e.g., "VS Code extension", "CLI agent", "Jupyter notebook"


@dataclass
class ParityReport:
    """Result of a governance parity check across surfaces."""

    surfaces: list[str]
    gaps: list[ParityGap]
    parity_score: float  # 0.0 (no parity) to 1.0 (full parity)
    missing_by_surface: dict[str, list[str]]
    universal_capabilities: list[str]  # present in ALL surfaces

    @property
    def has_critical_gaps(self) -> bool:
        return any(g.severity == "critical" for g in self.gaps)


# Severity mapping for missing capabilities
CAPABILITY_SEVERITY = {
    "policy_enforcement": "critical",
    "audit_logging": "critical",
    "trust_verification": "high",
    "kill_switch": "high",
    "rate_limiting": "medium",
    "prompt_injection_detection": "high",
    "mcp_gateway": "high",
    "approval_workflows": "medium",
    "session_state": "medium",
    "otel_observability": "low",
}

CAPABILITY_RECOMMENDATIONS = {
    "policy_enforcement": "Add PolicyEngine.evaluate() to the execution path",
    "audit_logging": "Wire AuditLog to capture all tool calls",
    "trust_verification": "Add TrustHandshake before cross-agent communication",
    "kill_switch": "Implement emergency termination capability",
    "rate_limiting": "Add per-agent call budget enforcement",
    "prompt_injection_detection": "Add PromptInjectionDetector to input pipeline",
    "mcp_gateway": "Route MCP tool calls through MCPGateway",
    "approval_workflows": "Wire ApprovalHandler for sensitive actions",
    "session_state": "Track SessionState for DLP attribute ratchets",
    "otel_observability": "Call enable_otel() at startup",
}


class GovernanceParityChecker:
    """Detect governance enforcement gaps between execution surfaces.

    Register each surface (CLI, IDE, notebook, etc.) with its active
    governance capabilities, then check for parity gaps.
    """

    def __init__(self, required_capabilities: list[str] | None = None):
        self._surfaces: dict[str, SurfaceRegistration] = {}
        self._required = set(required_capabilities or STANDARD_CAPABILITIES)

    def register_surface(
        self,
        name: str,
        capabilities: list[str],
        context: str = "",
    ) -> None:
        """Register an execution surface with its active capabilities."""
        self._surfaces[name] = SurfaceRegistration(
            name=name,
            capabilities=set(capabilities),
            context=context,
        )

    def check_parity(self) -> ParityReport:
        """Check governance parity across all registered surfaces.

        Returns a report with gaps, parity score, and recommendations.
        """
        if not self._surfaces:
            return ParityReport(
                surfaces=[], gaps=[], parity_score=1.0,
                missing_by_surface={}, universal_capabilities=[],
            )

        surfaces = list(self._surfaces.keys())
        all_caps = set()
        for s in self._surfaces.values():
            all_caps |= s.capabilities

        # Find universal (present in ALL surfaces)
        universal = set(self._required)
        for s in self._surfaces.values():
            universal &= s.capabilities

        # Find gaps per surface
        gaps: list[ParityGap] = []
        missing_by_surface: dict[str, list[str]] = {}

        for name, surface in self._surfaces.items():
            missing = self._required - surface.capabilities
            if missing:
                missing_by_surface[name] = sorted(missing)
                for cap in sorted(missing):
                    gaps.append(ParityGap(
                        surface=name,
                        capability=cap,
                        severity=CAPABILITY_SEVERITY.get(cap, "medium"),
                        recommendation=CAPABILITY_RECOMMENDATIONS.get(cap, f"Add {cap} support"),
                    ))

        # Parity score: % of (surface × capability) cells that are filled
        total_cells = len(self._surfaces) * len(self._required)
        filled = sum(len(s.capabilities & self._required) for s in self._surfaces.values())
        score = filled / total_cells if total_cells > 0 else 1.0

        return ParityReport(
            surfaces=surfaces,
            gaps=gaps,
            parity_score=round(score, 3),
            missing_by_surface=missing_by_surface,
            universal_capabilities=sorted(universal),
        )

    def print_report(self, report: Optional[ParityReport] = None) -> str:
        """Generate a human-readable parity report."""
        if report is None:
            report = self.check_parity()

        lines = [
            "Governance Parity Report",
            "=" * 50,
            f"Surfaces: {', '.join(report.surfaces)}",
            f"Parity Score: {report.parity_score:.0%}",
            f"Universal capabilities: {len(report.universal_capabilities)}/{len(self._required)}",
            "",
        ]

        if report.gaps:
            lines.append(f"Gaps found: {len(report.gaps)}")
            for gap in report.gaps:
                lines.append(f"  [{gap.severity.upper()}] {gap.surface}: missing {gap.capability}")
                lines.append(f"          → {gap.recommendation}")
        else:
            lines.append("No gaps — full parity across all surfaces.")

        return "\n".join(lines)
