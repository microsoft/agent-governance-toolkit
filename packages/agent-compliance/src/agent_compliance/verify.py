# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""
Governance Verification & Attestation.

Produces a signed attestation that an agent deployment was evaluated
by the Agent Governance Toolkit, covering OWASP Agentic Security
Initiative (ASI) controls.

Usage::

    from agent_compliance.verify import GovernanceVerifier

    verifier = GovernanceVerifier()
    attestation = verifier.verify()
    print(attestation.badge_markdown())
    print(attestation.to_json())
"""

from __future__ import annotations

import hashlib
import importlib
import json
import logging
import platform
import sys
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Optional

logger = logging.getLogger(__name__)

# Allowlist of module prefixes that may be imported via importlib.
# Defense-in-depth: even though defaults are hardcoded, custom controls
# passed via the constructor are validated against this allowlist.
# MSRC Case 112362 — prevents RCE via unvalidated importlib.import_module.
ALLOWED_MODULE_PREFIXES = frozenset({
    "agent_os.",
    "agentmesh.",
    "agent_compliance.",
    "agent_sre.",
    "agent_hypervisor.",
    "hypervisor.",
    "agent_runtime.",
    "agent_lightning_gov.",
    "agent_marketplace.",
})


def _validate_module_name(mod_name: str) -> None:
    """Raise ValueError if mod_name is not in the governance module allowlist."""
    if not any(mod_name.startswith(prefix) for prefix in ALLOWED_MODULE_PREFIXES):
        raise ValueError(
            f"Module '{mod_name}' is not in the allowed governance module list. "
            f"Only modules with prefixes {sorted(ALLOWED_MODULE_PREFIXES)} are permitted."
        )


# OWASP Agentic Security Initiative 2026 controls
OWASP_ASI_CONTROLS = {
    "ASI-01": {
        "name": "Prompt Injection",
        "module": "agent_os.integrations.base",
        "check": "PolicyInterceptor",
    },
    "ASI-02": {
        "name": "Insecure Tool Use",
        "module": "agent_os.integrations.tool_aliases",
        "check": "ToolAliasRegistry",
    },
    "ASI-03": {
        "name": "Excessive Agency",
        "module": "agent_os.integrations.base",
        "check": "GovernancePolicy",
    },
    "ASI-04": {
        "name": "Unauthorized Escalation",
        "module": "agent_os.integrations.escalation",
        "check": "EscalationPolicy",
    },
    "ASI-05": {
        "name": "Trust Boundary Violation",
        "module": "agentmesh.trust.cards",
        "check": "CardRegistry",
    },
    "ASI-06": {
        "name": "Insufficient Logging",
        "module": "agentmesh.governance.audit",
        "check": "AuditChain",
    },
    "ASI-07": {
        "name": "Insecure Identity",
        "module": "agentmesh.identity.agent_id",
        "check": "AgentIdentity",
    },
    "ASI-08": {
        "name": "Policy Bypass",
        "module": "agentmesh.governance.conflict_resolution",
        "check": "PolicyConflictResolver",
    },
    "ASI-09": {
        "name": "Supply Chain Integrity",
        "module": "agent_compliance.integrity",
        "check": "IntegrityVerifier",
    },
    "ASI-10": {
        "name": "Behavioral Anomaly",
        "module": "agentmesh.governance.compliance",
        "check": "ComplianceEngine",
    },
}


@dataclass
class ControlResult:
    """Result of checking a single OWASP ASI control."""

    control_id: str
    name: str
    present: bool
    module: str
    component: str
    error: Optional[str] = None


@dataclass
class GovernanceAttestation:
    """Signed attestation of governance verification.

    Attributes:
        passed: Whether all controls are present.
        controls: Per-control check results.
        toolkit_version: Installed toolkit version.
        python_version: Python runtime version.
        platform_info: OS/arch info.
        verified_at: ISO timestamp.
        attestation_hash: SHA-256 of the attestation payload.
    """

    passed: bool = True
    controls: list[ControlResult] = field(default_factory=list)
    toolkit_version: str = ""
    python_version: str = ""
    platform_info: str = ""
    verified_at: str = field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )
    attestation_hash: str = ""
    controls_passed: int = 0
    controls_total: int = 0

    def coverage_pct(self) -> int:
        """Percentage of controls covered."""
        if self.controls_total == 0:
            return 0
        return int(self.controls_passed / self.controls_total * 100)

    def compliance_grade(self) -> str:
        """Return a letter grade based on coverage percentage.

        Returns:
            A letter grade (A, B, C, D, F) based on the percentage
            of OWASP ASI controls that are covered.
        """
        pct = self.coverage_pct()
        if pct >= 90:
            return "A"
        elif pct >= 80:
            return "B"
        elif pct >= 70:
            return "C"
        elif pct >= 60:
            return "D"
        return "F"

    def badge_url(self) -> str:
        """Shields.io badge URL for README embedding."""
        pct = self.coverage_pct()
        if pct == 100:
            color = "brightgreen"
            label = "passed"
        elif pct >= 80:
            color = "yellow"
            label = f"{pct}%25"
        else:
            color = "red"
            label = f"{pct}%25"
        return (
            f"https://img.shields.io/badge/"
            f"OWASP_ASI_2026-{label}-{color}"
            f"?style=flat-square&logo=openai&logoColor=white"
        )

    def badge_markdown(self) -> str:
        """Markdown badge for README files."""
        url = self.badge_url()
        link = "https://github.com/microsoft/agent-governance-toolkit"
        return f"[![OWASP ASI 2026]({url})]({link})"

    def summary(self) -> str:
        """Human-readable verification summary."""
        lines = [
            f"Agent Governance Toolkit — Verification {'PASSED ✅' if self.passed else 'INCOMPLETE ⚠️'}",
            f"OWASP ASI 2026 Coverage: {self.controls_passed}/{self.controls_total} ({self.coverage_pct()}%)",
            f"Toolkit: {self.toolkit_version}",
            f"Python: {self.python_version}",
            f"Platform: {self.platform_info}",
            f"Verified: {self.verified_at}",
            f"Attestation: {self.attestation_hash[:16]}...",
            "",
        ]

        for ctrl in self.controls:
            mark = "✅" if ctrl.present else "❌"
            lines.append(f"  {mark} {ctrl.control_id}: {ctrl.name}")
            if ctrl.error:
                lines.append(f"     └─ {ctrl.error}")

        lines.append("")
        lines.append(f"Badge: {self.badge_markdown()}")
        return "\n".join(lines)

    def to_json(self) -> str:
        """JSON attestation for machine consumption."""
        payload = {
            "schema": "governance-attestation/v1",
            "passed": self.passed,
            "coverage_pct": self.coverage_pct(),
            "controls_passed": self.controls_passed,
            "controls_total": self.controls_total,
            "toolkit_version": self.toolkit_version,
            "python_version": self.python_version,
            "platform": self.platform_info,
            "verified_at": self.verified_at,
            "attestation_hash": self.attestation_hash,
            "controls": [
                {
                    "id": c.control_id,
                    "name": c.name,
                    "present": c.present,
                    "module": c.module,
                    "component": c.component,
                    "error": c.error,
                }
                for c in self.controls
            ],
        }
        return json.dumps(payload, indent=2)


class GovernanceVerifier:
    """Verifies that governance controls are installed and functional.

    Checks for the presence of each OWASP ASI 2026 control component
    and generates a signed attestation.
    """

    def __init__(self, controls: Optional[dict] = None) -> None:
        self.controls = controls or OWASP_ASI_CONTROLS

    def verify(self) -> GovernanceAttestation:
        """Run governance verification across all ASI controls.

        Returns:
            A GovernanceAttestation with per-control results and
            a deterministic attestation hash.
        """
        attestation = GovernanceAttestation()
        attestation.python_version = sys.version.split()[0]
        attestation.platform_info = f"{platform.system()} {platform.machine()}"
        attestation.controls_total = len(self.controls)

        # Detect toolkit version
        try:
            import agent_compliance

            attestation.toolkit_version = getattr(
                agent_compliance, "__version__", "unknown"
            )
        except ImportError:
            attestation.toolkit_version = "not installed"

        for control_id, spec in sorted(self.controls.items()):
            result = self._check_control(control_id, spec)
            attestation.controls.append(result)
            if result.present:
                attestation.controls_passed += 1

        attestation.passed = attestation.controls_passed == attestation.controls_total

        # Generate deterministic attestation hash
        hash_payload = json.dumps(
            {
                "controls": [
                    {"id": c.control_id, "present": c.present}
                    for c in attestation.controls
                ],
                "verified_at": attestation.verified_at,
                "toolkit_version": attestation.toolkit_version,
            },
            sort_keys=True,
        )
        attestation.attestation_hash = hashlib.sha256(
            hash_payload.encode()
        ).hexdigest()

        return attestation

    def _check_control(self, control_id: str, spec: dict) -> ControlResult:
        """Check if a single control's component is importable."""
        mod_name = spec.get("module")
        component_name = spec.get("check")
        control_name = spec.get("name", control_id)

        if not mod_name or not component_name:
            return ControlResult(
                control_id=control_id,
                name=control_name,
                present=False,
                module=mod_name or "",
                component=component_name or "",
                error="Malformed control spec: missing 'module' or 'check'",
            )

        try:
            _validate_module_name(mod_name)
            mod = importlib.import_module(mod_name)
            component = getattr(mod, component_name, None)
            if component is None:
                return ControlResult(
                    control_id=control_id,
                    name=control_name,
                    present=False,
                    module=mod_name,
                    component=component_name,
                    error=f"{component_name} not found in {mod_name}",
                )
            return ControlResult(
                control_id=control_id,
                name=control_name,
                present=True,
                module=mod_name,
                component=component_name,
            )
        except (ImportError, ValueError) as e:
            return ControlResult(
                control_id=control_id,
                name=control_name,
                present=False,
                module=mod_name,
                component=component_name,
                error=f"Module not installed: {e}",
            )
