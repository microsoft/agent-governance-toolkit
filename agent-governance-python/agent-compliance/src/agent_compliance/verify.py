# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

"""
Governance Verification & Attestation.

Produces signed attestations for governance control verification.
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
from pathlib import Path
from typing import Any, Optional

import yaml

logger = logging.getLogger(__name__)

# MSRC Case 112362:
# Dynamic imports used by verification must stay constrained to AGT-owned
# module namespaces. Do not widen this allowlist without a security review.

ALLOWED_MODULE_PREFIXES = frozenset(
    {
        "agent_os.",
        "agentmesh.",
        "agent_compliance.",
        "agent_sre.",
        "agent_hypervisor.",
        "hypervisor.",
        "agent_runtime.",
        "agent_lightning_gov.",
        "agent_marketplace.",
    }
)

EVIDENCE_SCHEMA = "agt-runtime-evidence/v1"
MAX_POLICY_FILE_BYTES = 10 * 1024 * 1024


def _validate_module_name(mod_name: str) -> None:
    """Raise ValueError if mod_name is not in the governance module allowlist."""
    if not any(mod_name.startswith(prefix) for prefix in ALLOWED_MODULE_PREFIXES):
        raise ValueError(
            f"Module '{mod_name}' is not in the allowed governance module list. "
            f"Only modules with prefixes {sorted(ALLOWED_MODULE_PREFIXES)} are permitted."
        )


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
class EvidenceCheck:
    """Result of checking a single runtime evidence condition."""

    check_id: str
    title: str
    status: str
    message: str
    observed: dict[str, Any] = field(default_factory=dict)


@dataclass
class RuntimeEvidence:
    """Runtime evidence manifest emitted by a deployment."""

    source_path: str
    schema: str
    generated_at: str
    toolkit_version: str
    deployment: dict[str, Any]

    @classmethod
    def load(cls, path: str | Path) -> "RuntimeEvidence":
        evidence_path = Path(path).expanduser().resolve()
        raw = evidence_path.read_text(encoding="utf-8")

        if evidence_path.suffix.lower() in {".yaml", ".yml"}:
            data = yaml.safe_load(raw)
        else:
            data = json.loads(raw)

        if not isinstance(data, dict):
            raise ValueError("Evidence file must contain an object at the top level.")

        schema = data.get("schema")
        if schema != EVIDENCE_SCHEMA:
            raise ValueError(
                f"Unsupported evidence schema {schema!r}. "
                f"Expected {EVIDENCE_SCHEMA!r}."
            )

        deployment = data.get("deployment")
        if not isinstance(deployment, dict):
            raise ValueError("Evidence file missing required 'deployment' object.")

        return cls(
            source_path=str(evidence_path),
            schema=schema,
            generated_at=str(data.get("generated_at", "")),
            toolkit_version=str(data.get("toolkit_version", "")),
            deployment=deployment,
        )


@dataclass
class GovernanceAttestation:
    """Signed attestation of governance verification."""

    passed: bool = True
    controls: list[ControlResult] = field(default_factory=list)
    toolkit_version: str = ""
    python_version: str = ""
    platform_info: str = ""
    verified_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    attestation_hash: str = ""
    controls_passed: int = 0
    controls_total: int = 0

    mode: str = "components"
    strict: bool = False
    evidence_source: str = ""
    evidence_checks: list[EvidenceCheck] = field(default_factory=list)
    failures: list[str] = field(default_factory=list)

    def coverage_pct(self) -> int:
        """Percentage of controls covered."""
        if self.controls_total == 0:
            return 0
        return int(self.controls_passed / self.controls_total * 100)

    def compliance_grade(self) -> str:
        """Return a letter grade based on coverage percentage."""
        pct = self.coverage_pct()
        if pct >= 90:
            return "A"
        if pct >= 80:
            return "B"
        if pct >= 70:
            return "C"
        if pct >= 60:
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
            "https://img.shields.io/badge/"
            f"OWASP_ASI_2026-{label}-{color}"
            "?style=flat-square&logo=openai&logoColor=white"
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
            f"Mode: {self.mode}",
            f"Attestation: {self.attestation_hash[:16]}...",
            "",
        ]

        for ctrl in self.controls:
            mark = "✅" if ctrl.present else "❌"
            lines.append(f" {mark} {ctrl.control_id}: {ctrl.name}")
            if ctrl.error:
                lines.append(f"   └─ {ctrl.error}")

        if self.evidence_checks:
            lines.append("")
            if self.evidence_source:
                lines.append(f"Evidence Source: {self.evidence_source}")

            passed_checks = sum(1 for check in self.evidence_checks if check.status == "pass")
            lines.append(
                f"Runtime Evidence: {passed_checks}/{len(self.evidence_checks)} checks passed"
            )

            for check in self.evidence_checks:
                mark = "✅" if check.status == "pass" else "❌"
                lines.append(f" {mark} {check.title}: {check.message}")

        if self.failures:
            lines.append("")
            lines.append("Failures:")
            for failure in self.failures:
                lines.append(f" - {failure}")

        lines.append("")
        lines.append(f"Badge: {self.badge_markdown()}")
        return "\n".join(lines)

    def to_json(self) -> str:
        """JSON attestation for machine consumption."""
        payload = {
            "schema": "governance-attestation/v1",
            "mode": self.mode,
            "strict": self.strict,
            "passed": self.passed,
            "coverage_pct": self.coverage_pct(),
            "controls_passed": self.controls_passed,
            "controls_total": self.controls_total,
            "toolkit_version": self.toolkit_version,
            "python_version": self.python_version,
            "platform": self.platform_info,
            "verified_at": self.verified_at,
            "attestation_hash": self.attestation_hash,
            "evidence_source": self.evidence_source,
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
            "evidence_checks": [
                {
                    "id": c.check_id,
                    "title": c.title,
                    "status": c.status,
                    "message": c.message,
                    "observed": c.observed,
                }
                for c in self.evidence_checks
            ],
            "failures": self.failures,
        }
        return json.dumps(payload, indent=2)

    def recalculate_hash(self) -> None:
        """Refresh the attestation hash."""
        payload = {
            "mode": self.mode,
            "strict": self.strict,
            "controls": [
                {
                    "id": c.control_id,
                    "present": c.present,
                }
                for c in self.controls
            ],
            "evidence_checks": [
                {
                    "id": c.check_id,
                    "status": c.status,
                    "message": c.message,
                }
                for c in self.evidence_checks
            ],
            "failures": self.failures,
            "verified_at": self.verified_at,
            "toolkit_version": self.toolkit_version,
            "evidence_source": self.evidence_source,
        }
        self.attestation_hash = hashlib.sha256(
            json.dumps(payload, sort_keys=True).encode("utf-8")
        ).hexdigest()


def _detect_toolkit_version() -> str:
    try:
        import agent_compliance

        return getattr(agent_compliance, "__version__", "unknown")
    except ImportError:
        return "not installed"


def _resolve_reported_paths(base_dir: Path, values: Any) -> list[Path]:
    if not isinstance(values, list):
        return []

    trusted_base_dir = base_dir.resolve()
    resolved: list[Path] = []

    for value in values:
        if not isinstance(value, str):
            continue

        candidate = Path(value)
        if not candidate.is_absolute():
            candidate = trusted_base_dir / candidate

        candidate = candidate.resolve()

        try:
            candidate.relative_to(trusted_base_dir)
        except ValueError as exc:
            raise ValueError(f"Policy path escapes evidence directory: {value}") from exc

        resolved.append(candidate)

    return resolved


def _iter_policy_documents(value: Any) -> list[dict[str, Any]]:
    docs: list[dict[str, Any]] = []

    if isinstance(value, dict):
        docs.append(value)
    elif isinstance(value, list):
        for item in value:
            docs.extend(_iter_policy_documents(item))

    return docs


def _load_policy_documents(policy_paths: list[Path]) -> list[dict[str, Any]]:
    documents: list[dict[str, Any]] = []

    for policy_path in policy_paths:
        file_size = policy_path.stat().st_size
        if file_size > MAX_POLICY_FILE_BYTES:
            raise ValueError(
                f"Policy file exceeds size limit ({MAX_POLICY_FILE_BYTES} bytes): {policy_path}"
            )

        with policy_path.open("r", encoding="utf-8") as handle:
            loaded = list(yaml.safe_load_all(handle))

        for item in loaded:
            documents.extend(_iter_policy_documents(item))

    return documents


def _policy_has_deny_semantics(documents: list[dict[str, Any]]) -> bool:
    for document in documents:
        if bool(document.get("deny_by_default")):
            return True

        for key in ("default_action", "action", "effect"):
            value = document.get(key)
            if isinstance(value, str) and value.lower() == "deny":
                return True

        for key in ("defaults", "default", "policy_defaults"):
            defaults = document.get(key)

            if isinstance(defaults, str) and defaults.lower() == "deny":
                return True

            if isinstance(defaults, dict):
                for nested_key in ("action", "effect", "default_action"):
                    nested_value = defaults.get(nested_key)
                    if isinstance(nested_value, str) and nested_value.lower() == "deny":
                        return True

        for key in ("rules", "policies", "statements"):
            rules = document.get(key)
            if not isinstance(rules, list):
                continue

            for rule in rules:
                if not isinstance(rule, dict):
                    continue

                for nested_key in ("action", "effect", "default_action"):
                    nested_value = rule.get(nested_key)
                    if isinstance(nested_value, str) and nested_value.lower() == "deny":
                        return True

                if bool(rule.get("deny")):
                    return True

    return False


class GovernanceVerifier:
    """Verifies governance controls and optional runtime evidence."""

    def __init__(self, controls: Optional[dict] = None) -> None:
        self.controls = controls or OWASP_ASI_CONTROLS

    def verify(self) -> GovernanceAttestation:
        """Run governance verification across all ASI controls."""
        attestation = GovernanceAttestation()
        attestation.python_version = sys.version.split()[0]
        attestation.platform_info = f"{platform.system()} {platform.machine()}"
        attestation.controls_total = len(self.controls)
        attestation.toolkit_version = _detect_toolkit_version()

        for control_id, spec in sorted(self.controls.items()):
            result = self._check_control(control_id, spec)
            attestation.controls.append(result)
            if result.present:
                attestation.controls_passed += 1

        attestation.passed = attestation.controls_passed == attestation.controls_total
        attestation.recalculate_hash()
        return attestation

    def verify_evidence(
        self,
        evidence_path: str | Path,
        *,
        strict: bool = False,
    ) -> GovernanceAttestation:
        """Run governance verification and validate runtime evidence."""
        attestation = self.verify()
        attestation.mode = "evidence"
        attestation.strict = strict

        evidence = RuntimeEvidence.load(evidence_path)
        attestation.evidence_source = evidence.source_path
        attestation.evidence_checks = self._check_runtime_evidence(evidence)
        attestation.failures = [
            check.message for check in attestation.evidence_checks if check.status == "fail"
        ]

        if strict and attestation.failures:
            attestation.passed = False

        attestation.recalculate_hash()
        return attestation

    def _check_runtime_evidence(self, evidence: RuntimeEvidence) -> list[EvidenceCheck]:
        deployment = evidence.deployment
        base_dir = Path(evidence.source_path).parent

        checks: list[EvidenceCheck] = []

        reported_policy_files = deployment.get("policy_files_loaded", [])
        if not isinstance(reported_policy_files, list):
            raise ValueError("'deployment.policy_files_loaded' must be a list.")

        policy_paths = _resolve_reported_paths(base_dir, reported_policy_files)
        missing_policy_files = [str(path) for path in policy_paths if not path.exists()]

        if not reported_policy_files:
            checks.append(
                EvidenceCheck(
                    check_id="policy-files",
                    title="Policy files loaded",
                    status="fail",
                    message="No loaded policy files were reported.",
                )
            )
        elif missing_policy_files:
            checks.append(
                EvidenceCheck(
                    check_id="policy-files",
                    title="Policy files loaded",
                    status="fail",
                    message="Some reported policy files do not exist on disk.",
                    observed={
                        "reported": reported_policy_files,
                        "missing": missing_policy_files,
                    },
                )
            )
        else:
            checks.append(
                EvidenceCheck(
                    check_id="policy-files",
                    title="Policy files loaded",
                    status="pass",
                    message=f"{len(policy_paths)} policy file(s) reported and found.",
                    observed={"files": [str(path) for path in policy_paths]},
                )
            )

        existing_policy_paths = [path for path in policy_paths if path.exists()]
        policy_documents = (
            _load_policy_documents(existing_policy_paths) if existing_policy_paths else []
        )
        has_deny_semantics = _policy_has_deny_semantics(policy_documents)

        checks.append(
            EvidenceCheck(
                check_id="deny-semantics",
                title="Deny rule or deny-by-default",
                status="pass" if has_deny_semantics else "fail",
                message=(
                    "Deny semantics found in loaded policy files."
                    if has_deny_semantics
                    else "No deny rule or deny-by-default detected in loaded policy files."
                ),
                observed={"policy_documents": len(policy_documents)},
            )
        )

        registered_tools = deployment.get("registered_tools", [])
        if not isinstance(registered_tools, list):
            raise ValueError("'deployment.registered_tools' must be a list.")

        tool_count = sum(
            1
            for item in registered_tools
            if (isinstance(item, str) and item.strip()) or isinstance(item, dict)
        )

        checks.append(
            EvidenceCheck(
                check_id="registered-tools",
                title="Registered tools",
                status="pass" if tool_count > 0 else "fail",
                message=(
                    f"{tool_count} tool(s) reported."
                    if tool_count > 0
                    else "No registered tools were reported."
                ),
                observed={"tools": registered_tools},
            )
        )

        audit_sink = deployment.get("audit_sink", {})
        if not isinstance(audit_sink, dict):
            raise ValueError("'deployment.audit_sink' must be an object.")

        audit_target = audit_sink.get("target") or audit_sink.get("path") or audit_sink.get("url")
        audit_enabled = bool(audit_sink.get("enabled"))
        audit_ok = audit_enabled and bool(audit_target)

        checks.append(
            EvidenceCheck(
                check_id="audit-sink",
                title="Audit sink configured",
                status="pass" if audit_ok else "fail",
                message=(
                    "Audit sink enabled."
                    if audit_ok
                    else "Audit sink missing, disabled, or missing target."
                ),
                observed=audit_sink,
            )
        )

        identity = deployment.get("identity", {})
        if not isinstance(identity, dict):
            raise ValueError("'deployment.identity' must be an object.")

        identity_ok = bool(identity.get("enabled"))

        checks.append(
            EvidenceCheck(
                check_id="identity",
                title="Identity enabled",
                status="pass" if identity_ok else "fail",
                message="Identity enabled." if identity_ok else "Identity missing or disabled.",
                observed=identity,
            )
        )

        packages = deployment.get("packages", [])
        if not isinstance(packages, list):
            raise ValueError("'deployment.packages' must be a list.")

        package_manifest_ok = (
            len(packages) > 0
            and all(
                isinstance(item, dict)
                and isinstance(item.get("package"), str)
                and item["package"].strip()
                and isinstance(item.get("version"), str)
                and item["version"].strip()
                for item in packages
            )
        )

        checks.append(
            EvidenceCheck(
                check_id="packages",
                title="Package/version manifest",
                status="pass" if package_manifest_ok else "fail",
                message=(
                    f"{len(packages)} package entry(ies) found."
                    if package_manifest_ok
                    else "Package/version manifest missing or incomplete."
                ),
                observed={"packages": packages},
            )
        )

        return checks

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

        except (ImportError, ValueError) as exc:
            return ControlResult(
                control_id=control_id,
                name=control_name,
                present=False,
                module=mod_name,
                component=component_name,
                error=f"Module not installed: {exc}",
            )
