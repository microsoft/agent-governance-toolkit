#!/usr/bin/env python3
# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""
EU AI Act Compliance Checker — Interactive Demo

Demonstrates:
 1. Classifying an agent as high-risk
 2. Checking transparency requirements
 3. Generating a full compliance report
 4. Blocking a non-compliant agent deployment

Runs entirely offline — no API keys required.
"""

from compliance_checker import (
    AgentProfile,
    EUAIActComplianceChecker,
    RiskLevel,
)


def _redact(value, visible_chars: int = 0) -> str:
    """Redact a sensitive value for safe logging."""
    import hashlib
    raw = str(value)
    if not raw:
        return "[REDACTED]"
    digest = hashlib.sha256(raw.encode()).hexdigest()[:8]
    return f"***{digest}"


def banner(title: str) -> None:
    print(f"\n{'=' * 70}")
    print(f"  {title}")
    print("=" * 70)


def main() -> None:
    checker = EUAIActComplianceChecker()

    # ------------------------------------------------------------------
    # Demo 1 — Risk classification for a medical-diagnosis agent
    # ------------------------------------------------------------------
    banner("Demo 1: Risk Classification (Article 6)")

    medical_agent = AgentProfile(
        name="MedAssist-AI",
        description="AI agent that assists radiologists with X-ray diagnosis",
        domain="medical_diagnosis",
        capabilities=["autonomous_decision_making", "personal_data_processing"],
        has_human_oversight=True,
        transparency_disclosure=True,
        logs_decisions=True,
        tested_for_bias=True,
        has_documentation=True,
        has_risk_assessment=True,
        has_quality_management=True,
        cybersecurity_measures=True,
        accuracy_metrics_available=True,
        data_governance=True,
        deployer="EuroHealth Hospitals",
    )

    risk = checker.classify_risk(medical_agent)
    explanation = checker.explain_risk(medical_agent)
    print(f"\nAgent:      {medical_agent.name}")
    print(f"Domain:     {medical_agent.domain}")
    print(f"Risk Level: {risk.value.upper()}")
    print("Triggers:")
    for t in explanation["triggers"]:
        print(f"  • {t}")

    # ------------------------------------------------------------------
    # Demo 2 — Transparency check for a chatbot
    # ------------------------------------------------------------------
    banner("Demo 2: Transparency Check (Articles 13 & 50)")

    chatbot = AgentProfile(
        name="SupportBot-v2",
        description="Customer-facing support chatbot",
        domain="chatbot",
        capabilities=["text_generation"],
        transparency_disclosure=False,  # ← violation
    )

    risk_chat = checker.classify_risk(chatbot)
    print(f"\nAgent:      {chatbot.name}")
    print(f"Risk Level: {risk_chat.value.upper()}")

    report_chat = checker.check_compliance(chatbot)
    for issue in report_chat.issues:
        icon = "✅" if issue.status == "pass" else "❌"
        print(f"  {icon} [{issue.article}] {issue.requirement} — {issue.status.upper()}")
        if issue.status == "fail":
            print(f"     ↳ {issue.detail}")

    # ------------------------------------------------------------------
    # Demo 3 — Full compliance report for a recruitment agent
    # ------------------------------------------------------------------
    banner("Demo 3: Full Compliance Report (Recruitment Agent)")

    recruitment_agent = AgentProfile(
        name="HireBot-Pro",
        description="Automated resume screening and candidate ranking",
        domain="employment_recruitment",
        capabilities=["autonomous_decision_making", "personal_data_processing"],
        has_human_oversight=False,       # ← critical gap
        transparency_disclosure=False,   # ← violation
        logs_decisions=False,            # ← violation
        tested_for_bias=False,           # ← violation
        has_documentation=False,         # ← violation
        has_risk_assessment=False,
        has_quality_management=False,
        cybersecurity_measures=False,
        accuracy_metrics_available=False,
        data_governance=False,
        deployer="TalentCorp Inc.",
    )

    report = checker.check_compliance(recruitment_agent)
    print(checker.format_report(report))

    # ------------------------------------------------------------------
    # Demo 4 — Deployment gate (block non-compliant agent)
    # ------------------------------------------------------------------
    banner("Demo 4: Deployment Gate — Block Non-Compliant Agent")

    agents = [
        ("MedAssist-AI (compliant)", medical_agent),
        ("HireBot-Pro (non-compliant)", recruitment_agent),
    ]

    for label, agent in agents:
        deployable = checker.can_deploy(agent)
        icon = "✅" if deployable else "🚫"
        status = "APPROVED" if deployable else "BLOCKED"
        print(f"  {icon}  {_redact(label, 20):40s} → {status}")

    # ------------------------------------------------------------------
    # Demo 5 — Prohibited (unacceptable-risk) system
    # ------------------------------------------------------------------
    banner("Demo 5: Prohibited AI System (Article 5)")

    social_scoring = AgentProfile(
        name="CitizenRank-AI",
        description="Government social credit scoring system",
        domain="social_scoring",
        capabilities=["autonomous_decision_making"],
    )

    risk_ss = checker.classify_risk(social_scoring)
    print(f"\nAgent:      {social_scoring.name}")
    print(f"Risk Level: {risk_ss.value.upper()}")

    report_ss = checker.check_compliance(social_scoring)
    print(f"\n🚫 {report_ss.summary}")
    deployable = checker.can_deploy(social_scoring)
    print(f"   Deployment allowed: {deployable}")

    # ------------------------------------------------------------------
    # Summary
    # ------------------------------------------------------------------
    banner("Demo Complete")
    print()
    print("Key EU AI Act features demonstrated:")
    print("  • Article 5  — Prohibited AI practices detection")
    print("  • Article 6  — Risk classification (Unacceptable/High/Limited/Minimal)")
    print("  • Article 12 — Record-keeping / automatic logging")
    print("  • Article 13 — Transparency documentation for high-risk AI")
    print("  • Article 14 — Human oversight requirements")
    print("  • Article 15 — Accuracy, robustness, cybersecurity")
    print("  • Article 17 — Quality management system")
    print("  • Article 50 — User-facing transparency disclosure")
    print()
    print("🔗 Learn more: https://github.com/microsoft/agent-governance-toolkit")
    print()


if __name__ == "__main__":
    main()
