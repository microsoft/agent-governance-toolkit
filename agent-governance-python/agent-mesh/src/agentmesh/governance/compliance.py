# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""
Compliance Engine

Automated compliance mapping for:
- EU AI Act
- SOC 2
- HIPAA
- GDPR

Every action is mapped to relevant controls automatically.
"""

from datetime import date, datetime, timezone
from typing import Optional, Literal
from pydantic import BaseModel, Field
from enum import Enum


class ComplianceFramework(str, Enum):
    """Supported compliance frameworks."""
    EU_AI_ACT = "eu_ai_act"
    SOC2 = "soc2"
    HIPAA = "hipaa"
    GDPR = "gdpr"


class ComplianceControl(BaseModel):
    """A specific compliance control within a framework.

    Attributes:
        control_id: Unique identifier (e.g. ``"SOC2-CC6.1"``).
        framework: The compliance framework this control belongs to.
        name: Short human-readable name.
        description: Detailed description of the control.
        category: Top-level category within the framework.
        subcategory: Optional sub-category for finer classification.
        requirements: List of requirement descriptions for this control.
        evidence_types: Types of evidence needed to demonstrate compliance.
    """

    control_id: str
    framework: ComplianceFramework
    name: str
    description: str

    # Categorization
    category: str
    subcategory: Optional[str] = None

    # Requirements
    requirements: list[str] = Field(default_factory=list)

    # Evidence required
    evidence_types: list[str] = Field(default_factory=list)


class ComplianceMapping(BaseModel):
    """Mapping of an action type to its applicable compliance controls.

    Attributes:
        action_type: The agent action (e.g. ``"data_access"``).
        controls: List of control IDs that apply to this action.
        evidence_generated: Evidence types produced automatically on action.
        evidence_required: Evidence types that must be supplied manually.
    """

    action_type: str
    controls: list[str] = Field(default_factory=list)  # Control IDs

    # Auto-generated evidence
    evidence_generated: list[str] = Field(default_factory=list)

    # Manual evidence required
    evidence_required: list[str] = Field(default_factory=list)


class ComplianceViolation(BaseModel):
    """A recorded compliance violation.

    Attributes:
        violation_id: Unique identifier for this violation.
        timestamp: When the violation was detected.
        agent_did: DID of the agent that caused the violation.
        action_type: The action that triggered the violation.
        control_id: ID of the violated compliance control.
        framework: The compliance framework of the violated control.
        severity: Violation severity (critical, high, medium, low).
        description: Human-readable description of the violation.
        evidence: Supporting evidence captured at detection time.
        remediated: Whether the violation has been remediated.
        remediated_at: Timestamp of remediation (if applicable).
        remediation_notes: Free-text notes about the remediation.
    """

    violation_id: str
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))

    # What happened
    agent_did: str
    action_type: str

    # Which control was violated
    control_id: str
    framework: ComplianceFramework

    # Severity
    severity: Literal["critical", "high", "medium", "low"] = "medium"

    # Details
    description: str
    evidence: dict = Field(default_factory=dict)

    # Remediation
    remediated: bool = False
    remediated_at: Optional[datetime] = None
    remediation_notes: Optional[str] = None


class ComplianceReport(BaseModel):
    """Compliance audit report for a given framework and time period.

    Attributes:
        report_id: Unique report identifier.
        generated_at: When the report was generated.
        framework: Target compliance framework.
        period_start: Start of the reporting period.
        period_end: End of the reporting period.
        organization_id: Optional organisation scope.
        agents_covered: Agent DIDs included in the report.
        total_controls: Number of controls defined for the framework.
        controls_met: Number of controls that were assessed during the
            period and have no recorded violation. A control that was never
            assessed is not counted as met.
        controls_partial: Number of controls partially satisfied.
        controls_failed: Number of controls with violations.
        controls_unassessed: Number of controls with no recorded assessment
            during the period (and agent scope). ``None`` means unknown, e.g.
            a report serialised before assessment tracking existed.
        unassessed_controls: IDs of the controls counted in
            ``controls_unassessed``.
        compliance_score: Overall score from 0 to 100, computed as
            ``controls_met / total_controls * 100``.
        violations: List of violations found during the period.
        evidence_items: Count of evidence artefacts collected.
        recommendations: Actionable remediation recommendations (max 10).
    """

    report_id: str
    generated_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))

    # Scope
    framework: ComplianceFramework
    period_start: datetime
    period_end: datetime

    # Organization
    organization_id: Optional[str] = None
    agents_covered: list[str] = Field(default_factory=list)

    # Summary
    total_controls: int = 0
    controls_met: int = 0
    controls_partial: int = 0
    controls_failed: int = 0
    controls_unassessed: Optional[int] = None
    unassessed_controls: list[str] = Field(default_factory=list)
    compliance_score: float = 0.0  # 0-100

    # Violations
    violations: list[ComplianceViolation] = Field(default_factory=list)

    # Evidence
    evidence_items: int = 0

    # Recommendations
    recommendations: list[str] = Field(default_factory=list)


class ComplianceEngine:
    """
    Automated compliance mapping and reporting.

    Maps every agent action to relevant compliance controls
    and generates audit-ready reports.
    """

    def __init__(self, frameworks: Optional[list[ComplianceFramework]] = None):
        """Initialise the compliance engine.

        Args:
            frameworks: Compliance frameworks to enable. Defaults to
                ``[ComplianceFramework.SOC2]`` when ``None``.
        """
        self.frameworks = frameworks or [ComplianceFramework.SOC2]
        self._controls: dict[str, ComplianceControl] = {}
        self._mappings: dict[str, ComplianceMapping] = {}
        self._violations: list[ComplianceViolation] = []

        # Assessment coverage: which controls check_compliance() actually
        # evaluated, so reports can tell "assessed and passed" apart from
        # "never assessed". Aggregated per (control_id, agent_did, UTC day)
        # as (first, last) timestamps, so memory grows with distinct triples
        # rather than with call volume.
        self._assessments: dict[tuple[str, str, date], tuple[datetime, datetime]] = {}

        # Load default controls
        self._load_default_controls()

    def _load_default_controls(self) -> None:
        """Load default compliance controls for enabled frameworks."""

        # SOC 2 Controls
        if ComplianceFramework.SOC2 in self.frameworks:
            self._add_control(ComplianceControl(
                control_id="SOC2-CC6.1",
                framework=ComplianceFramework.SOC2,
                name="Logical Access Security",
                description="Logical access security software, infrastructure, and architectures have been implemented",
                category="Common Criteria",
                requirements=[
                    "Identity verification",
                    "Access logging",
                    "Credential management",
                ],
                evidence_types=["access_logs", "identity_records"],
            ))
            self._add_control(ComplianceControl(
                control_id="SOC2-CC7.2",
                framework=ComplianceFramework.SOC2,
                name="System Monitoring",
                description="System components are monitored for anomalies",
                category="Common Criteria",
                requirements=[
                    "Activity monitoring",
                    "Anomaly detection",
                    "Alerting",
                ],
                evidence_types=["monitoring_logs", "alerts"],
            ))

        # HIPAA Controls
        if ComplianceFramework.HIPAA in self.frameworks:
            self._add_control(ComplianceControl(
                control_id="HIPAA-164.312(a)(1)",
                framework=ComplianceFramework.HIPAA,
                name="Access Control",
                description="Implement technical policies and procedures for electronic PHI access",
                category="Technical Safeguards",
                requirements=[
                    "Unique user identification",
                    "Automatic logoff",
                    "Encryption",
                ],
                evidence_types=["access_logs", "encryption_records"],
            ))
            self._add_control(ComplianceControl(
                control_id="HIPAA-164.312(b)",
                framework=ComplianceFramework.HIPAA,
                name="Audit Controls",
                description="Implement hardware, software, and procedural mechanisms for audit trails",
                category="Technical Safeguards",
                requirements=[
                    "Audit logging",
                    "Log retention",
                    "Log review",
                ],
                evidence_types=["audit_logs"],
            ))

        # EU AI Act Controls
        if ComplianceFramework.EU_AI_ACT in self.frameworks:
            self._add_control(ComplianceControl(
                control_id="EUAI-ART9",
                framework=ComplianceFramework.EU_AI_ACT,
                name="Risk Management System",
                description="High-risk AI systems shall have a risk management system",
                category="High-Risk AI",
                requirements=[
                    "Risk identification",
                    "Risk mitigation",
                    "Continuous monitoring",
                ],
                evidence_types=["risk_assessments", "mitigation_logs"],
            ))
            self._add_control(ComplianceControl(
                control_id="EUAI-ART13",
                framework=ComplianceFramework.EU_AI_ACT,
                name="Transparency",
                description="High-risk AI systems shall be designed to allow appropriate transparency",
                category="High-Risk AI",
                requirements=[
                    "Explainability",
                    "Documentation",
                    "User notification",
                ],
                evidence_types=["decision_logs", "explanations"],
            ))

        # GDPR Controls
        if ComplianceFramework.GDPR in self.frameworks:
            self._add_control(ComplianceControl(
                control_id="GDPR-ART5",
                framework=ComplianceFramework.GDPR,
                name="Data Processing Principles",
                description="Personal data shall be processed lawfully, fairly and transparently",
                category="Principles",
                requirements=[
                    "Lawful basis",
                    "Purpose limitation",
                    "Data minimization",
                ],
                evidence_types=["processing_records", "consent_logs"],
            ))
            self._add_control(ComplianceControl(
                control_id="GDPR-ART22",
                framework=ComplianceFramework.GDPR,
                name="Automated Decision-Making",
                description="Right not to be subject to solely automated decision-making",
                category="Individual Rights",
                requirements=[
                    "Human oversight",
                    "Explanation of logic",
                    "Right to contest",
                ],
                evidence_types=["decision_logs", "human_review_records"],
            ))

        # Set up default mappings
        self._setup_default_mappings()

    def _setup_default_mappings(self) -> None:
        """Set up default action-to-control mappings."""

        # Agent registration
        self._mappings["agent_registration"] = ComplianceMapping(
            action_type="agent_registration",
            controls=["SOC2-CC6.1", "HIPAA-164.312(a)(1)"],
            evidence_generated=["identity_record", "registration_log"],
        )

        # Data access
        self._mappings["data_access"] = ComplianceMapping(
            action_type="data_access",
            controls=["SOC2-CC6.1", "HIPAA-164.312(b)", "GDPR-ART5"],
            evidence_generated=["access_log", "data_classification"],
        )

        # Automated decision
        self._mappings["automated_decision"] = ComplianceMapping(
            action_type="automated_decision",
            controls=["EUAI-ART13", "GDPR-ART22"],
            evidence_generated=["decision_log", "explanation"],
            evidence_required=["human_review"] if ComplianceFramework.GDPR in self.frameworks else [],
        )

        # Supply chain audit
        self._mappings["supply_chain_audit"] = ComplianceMapping(
            action_type="supply_chain_audit",
            controls=["SOC2-CC7.2", "EUAI-ART9"],
            evidence_generated=[
                "Package version pinning",
                "Dependency freshness validation",
                "SBOM generation",
            ],
        )

    def _add_control(self, control: ComplianceControl) -> None:
        """Add a control to the registry."""
        self._controls[control.control_id] = control

    def map_action(self, action_type: str) -> Optional[ComplianceMapping]:
        """Get the compliance mapping for an action type.

        Args:
            action_type: Action identifier (e.g. ``"data_access"``).

        Returns:
            The ``ComplianceMapping`` if one exists, otherwise ``None``.
        """
        return self._mappings.get(action_type)

    def check_compliance(
        self,
        agent_did: str,
        action_type: str,
        context: dict,
    ) -> list[ComplianceViolation]:
        """Check an action for compliance violations.

        Evaluates the action against all mapped controls for the given
        action type, records that each of those controls was assessed, and
        records any violations found.

        Args:
            agent_did: DID of the agent performing the action.
            action_type: The type of action being performed.
            context: Runtime context (e.g. data type, encryption status).

        Returns:
            List of ``ComplianceViolation`` instances (empty if compliant).
        """
        violations = []
        mapping = self.map_action(action_type)

        if not mapping:
            return violations

        now = datetime.now(timezone.utc)
        for control_id in mapping.controls:
            control = self._controls.get(control_id)
            if not control:
                continue

            self._record_assessment(control.control_id, agent_did, now)

            # Check requirements
            violation = self._check_control(agent_did, action_type, control, context)
            if violation:
                violations.append(violation)
                self._violations.append(violation)

        return violations

    def _record_assessment(self, control_id: str, agent_did: str, at: datetime) -> None:
        """Record that ``control_id`` was assessed for ``agent_did`` at ``at``.

        "Assessed" means ``check_compliance()`` ran the control's checks for an
        action mapped to it. ``_check_control`` has no specific rules for SOC 2
        or EU AI Act controls, so for those it means the action was mapped to
        the control and no violation was raised.
        """
        key = (control_id, agent_did, at.date())
        seen = self._assessments.get(key)
        if seen is None:
            self._assessments[key] = (at, at)
        else:
            self._assessments[key] = (min(seen[0], at), max(seen[1], at))

    def _assessed_control_ids(
        self,
        period_start: datetime,
        period_end: datetime,
        agent_ids: Optional[list[str]],
    ) -> set[str]:
        """Return IDs of controls assessed within the period and agent scope.

        A day bucket counts only when its first or last assessment falls inside
        the period. This can under-report coverage for a period shorter than a
        day whose bounds both fall between the day's first and last assessment,
        but it never reports an unassessed control as assessed.
        """
        assessed: set[str] = set()
        for (control_id, agent_did, _day), (first, last) in self._assessments.items():
            if agent_ids and agent_did not in agent_ids:
                continue
            if period_start <= first <= period_end or period_start <= last <= period_end:
                assessed.add(control_id)
        return assessed

    def _check_control(
        self,
        agent_did: str,
        action_type: str,
        control: ComplianceControl,
        context: dict,
    ) -> Optional[ComplianceViolation]:
        """Check if an action violates a specific control."""
        import uuid

        # Framework-specific checks
        if control.framework == ComplianceFramework.HIPAA:
            # Check for PHI handling
            if context.get("data_type") == "phi" and not context.get("encrypted"):
                return ComplianceViolation(
                    violation_id=f"viol_{uuid.uuid4().hex[:12]}",
                    agent_did=agent_did,
                    action_type=action_type,
                    control_id=control.control_id,
                    framework=control.framework,
                    severity="high",
                    description="PHI data accessed without encryption",
                    evidence={"data_type": "phi", "encrypted": False},
                )

        if control.framework == ComplianceFramework.GDPR:
            # Check for consent
            if context.get("personal_data") and not context.get("consent_verified"):
                return ComplianceViolation(
                    violation_id=f"viol_{uuid.uuid4().hex[:12]}",
                    agent_did=agent_did,
                    action_type=action_type,
                    control_id=control.control_id,
                    framework=control.framework,
                    severity="high",
                    description="Personal data processed without verified consent",
                    evidence={"personal_data": True, "consent": False},
                )

        return None

    def generate_report(
        self,
        framework: ComplianceFramework,
        period_start: datetime,
        period_end: datetime,
        agent_ids: Optional[list[str]] = None,
    ) -> ComplianceReport:
        """Generate a compliance report for a framework and time period.

        A control counts as met only if ``check_compliance()`` assessed it
        within the period (and agent scope) and no violation was recorded for
        it. Controls that were never assessed are reported in
        ``controls_unassessed`` / ``unassessed_controls`` and do not count
        towards ``controls_met`` or the score.

        Args:
            framework: The compliance framework to report on.
            period_start: Start of the reporting window. Naive datetimes are
                interpreted as UTC.
            period_end: End of the reporting window. Naive datetimes are
                interpreted as UTC.
            agent_ids: Optional list of agent DIDs to scope the report.
                When ``None``, all agents are included.

        Returns:
            A ``ComplianceReport`` with score, violations, and recommendations.
        """
        import uuid

        # Recorded timestamps are UTC-aware; comparing them with naive bounds
        # would raise TypeError.
        if period_start.tzinfo is None:
            period_start = period_start.replace(tzinfo=timezone.utc)
        if period_end.tzinfo is None:
            period_end = period_end.replace(tzinfo=timezone.utc)

        # Filter violations
        violations = [
            v for v in self._violations
            if v.framework == framework
            and period_start <= v.timestamp <= period_end
            and (not agent_ids or v.agent_did in agent_ids)
        ]

        # Get controls for framework
        framework_controls = [
            c for c in self._controls.values()
            if c.framework == framework
        ]

        # Calculate compliance score. A recorded violation is itself evidence
        # that its control was assessed.
        violated_controls = set(v.control_id for v in violations)
        assessed_controls = (
            self._assessed_control_ids(period_start, period_end, agent_ids) | violated_controls
        )
        unassessed = [
            c.control_id for c in framework_controls if c.control_id not in assessed_controls
        ]
        total = len(framework_controls)
        failed = len(violated_controls)
        met = total - failed - len(unassessed)

        score = (met / total * 100) if total > 0 else 100.0

        # Generate recommendations
        recommendations = []
        for v in violations:
            if not v.remediated:
                recommendations.append(
                    f"Remediate {v.control_id}: {v.description}"
                )

        return ComplianceReport(
            report_id=f"report_{uuid.uuid4().hex[:12]}",
            framework=framework,
            period_start=period_start,
            period_end=period_end,
            agents_covered=agent_ids or [],
            total_controls=total,
            controls_met=met,
            controls_failed=failed,
            controls_unassessed=len(unassessed),
            unassessed_controls=unassessed,
            compliance_score=score,
            violations=violations,
            recommendations=recommendations[:10],  # Top 10
        )

    def remediate_violation(
        self,
        violation_id: str,
        notes: str,
    ) -> bool:
        """Mark a violation as remediated.

        Args:
            violation_id: ID of the violation to remediate.
            notes: Free-text description of the remediation action taken.

        Returns:
            ``True`` if the violation was found and updated,
            ``False`` if no violation with that ID exists.
        """
        for v in self._violations:
            if v.violation_id == violation_id:
                v.remediated = True
                v.remediated_at = datetime.now(timezone.utc)
                v.remediation_notes = notes
                return True
        return False

    def get_violations(
        self,
        framework: Optional[ComplianceFramework] = None,
        agent_did: Optional[str] = None,
        remediated: Optional[bool] = None,
    ) -> list[ComplianceViolation]:
        """Get recorded violations with optional filters.

        Args:
            framework: Filter to a specific compliance framework.
            agent_did: Filter to a specific agent DID.
            remediated: Filter by remediation status. ``None`` returns all.

        Returns:
            List of matching ``ComplianceViolation`` instances.
        """
        violations = self._violations

        if framework:
            violations = [v for v in violations if v.framework == framework]

        if agent_did:
            violations = [v for v in violations if v.agent_did == agent_did]

        if remediated is not None:
            violations = [v for v in violations if v.remediated == remediated]

        return violations
