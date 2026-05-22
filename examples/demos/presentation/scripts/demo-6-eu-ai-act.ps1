###############################################################################
# Demo 6: EU AI Act Compliance Checker
# GenAI Gurus Meetup - Agent Governance Toolkit
#
# Shows the EU AI Act compliance checker classifying agents,
# checking compliance, and blocking non-compliant deployments.
# Runs entirely offline - no API keys needed.
# Expected time: ~30 seconds
###############################################################################

Write-Host ""
Write-Host ("=" * 65) -ForegroundColor Cyan
Write-Host "  DEMO: EU AI Act Compliance Checker" -ForegroundColor Cyan
Write-Host "  Regulation (EU) 2024/1689 - High-risk obligations: Aug 2026" -ForegroundColor DarkCyan
Write-Host ("=" * 65) -ForegroundColor Cyan
Write-Host ""

# Find the EU AI Act example in the AGT repo
$agtPaths = @(
    "$PSScriptRoot\..\..\..\agent-governance-python\agent-mesh\examples\06-eu-ai-act-compliance",
    "$env:USERPROFILE\source\repos\imran-siddique\agent-governance-toolkit\agent-governance-python\agent-mesh\examples\06-eu-ai-act-compliance",
    "$env:USERPROFILE\source\repos\agent-governance-toolkit\agent-governance-python\agent-mesh\examples\06-eu-ai-act-compliance"
)

$demoPath = $null
foreach ($p in $agtPaths) {
    if (Test-Path "$p\demo.py") {
        $demoPath = (Resolve-Path $p).Path
        break
    }
}

if ($demoPath) {
    Write-Host "  Running from: $demoPath" -ForegroundColor DarkGray
    Write-Host ""

    # Run the repo demo.py directly
    $proc = Start-Process python -ArgumentList "demo.py" -WorkingDirectory $demoPath -NoNewWindow -PassThru -Wait
    if ($proc.ExitCode -ne 0) {
        Write-Host "  (Repo demo had an issue - running inline version)" -ForegroundColor Yellow
        $demoPath = $null
    }
}

if (-not $demoPath) {
    # Fallback: self-contained inline demo using agentmesh compliance checker
    # or pure Python implementation if the example isn't installed
    $pyScript = @'
import sys, os
if sys.platform == "win32":
    sys.stdout.reconfigure(encoding="utf-8")

G = "\033[92m"; R = "\033[91m"; Y = "\033[93m"; C = "\033[96m"
B = "\033[1m"; D = "\033[2m"; X = "\033[0m"

# Try to import from the repo example first
demo_paths = [
    os.path.expanduser("~/source/repos/imran-siddique/agent-governance-toolkit/agent-governance-python/agent-mesh/examples/06-eu-ai-act-compliance"),
    os.path.expanduser("~/source/repos/agent-governance-toolkit/agent-governance-python/agent-mesh/examples/06-eu-ai-act-compliance"),
]
for dp in demo_paths:
    if os.path.isfile(os.path.join(dp, "compliance_checker.py")):
        sys.path.insert(0, dp)
        break

try:
    from compliance_checker import AgentProfile, EUAIActComplianceChecker, RiskLevel
    USE_REAL = True
except ImportError:
    USE_REAL = False

def banner(title):
    print(f"\n{Y}{B}{'=' * 65}")
    print(f"  {title}")
    print(f"{'=' * 65}{X}\n")

if USE_REAL:
    checker = EUAIActComplianceChecker()

    # --- Act 1: Risk Classification ---
    banner("Act 1: Risk Classification (Article 6)")
    agents = [
        AgentProfile(name="MedAssist-AI",
            description="AI agent that assists radiologists with X-ray diagnosis",
            domain="medical_diagnosis",
            capabilities=["autonomous_decision_making", "personal_data_processing"],
            has_human_oversight=True, transparency_disclosure=True,
            logs_decisions=True, tested_for_bias=True, has_documentation=True,
            has_risk_assessment=True, has_quality_management=True,
            cybersecurity_measures=True, accuracy_metrics_available=True,
            data_governance=True, deployer="EuroHealth Hospitals"),
        AgentProfile(name="SupportBot-v2",
            description="Customer-facing support chatbot",
            domain="chatbot", capabilities=["text_generation"],
            transparency_disclosure=False),
        AgentProfile(name="HireBot-Pro",
            description="Automated resume screening and candidate ranking",
            domain="employment_recruitment",
            capabilities=["autonomous_decision_making", "personal_data_processing"],
            has_human_oversight=False, transparency_disclosure=False,
            logs_decisions=False, tested_for_bias=False),
        AgentProfile(name="CitizenRank-AI",
            description="Government social credit scoring system",
            domain="social_scoring",
            capabilities=["autonomous_decision_making"]),
    ]

    hdr = f"  {B}{'Agent':<24} {'Domain':<28} {'Risk Level':<16}{X}"
    print(hdr)
    print(f"  {'_' * 66}")
    for agent in agents:
        risk = checker.classify_risk(agent)
        color = R if risk in (RiskLevel.UNACCEPTABLE, RiskLevel.HIGH) else Y if risk == RiskLevel.LIMITED else G
        icon = "\U0001f6ab" if risk == RiskLevel.UNACCEPTABLE else "\u26a0\ufe0f " if risk == RiskLevel.HIGH else "\u2139\ufe0f " if risk == RiskLevel.LIMITED else "\u2705"
        print(f"  {icon} {agent.name:<24} {agent.domain:<28} {color}{risk.value.upper():<16}{X}")

    # --- Act 2: Compliance Report ---
    banner("Act 2: Compliance Report (HireBot-Pro - Recruitment Agent)")
    hire_bot = agents[2]
    report = checker.check_compliance(hire_bot)
    for issue in report.issues:
        icon = f"{G}\u2713{X}" if issue.status == "pass" else f"{R}\u2717{X}"
        status = f"{G}PASS{X}" if issue.status == "pass" else f"{R}FAIL{X}"
        print(f"  {icon} [{issue.article}] {issue.requirement[:50]:<50} {status}")
        if issue.status == "fail":
            print(f"    {D}{issue.detail[:70]}{X}")

    # --- Act 3: Deployment Gate ---
    banner("Act 3: Deployment Gate - Block Non-Compliant Agents")
    for agent in agents:
        deployable = checker.can_deploy(agent)
        icon = f"{G}\u2713{X}" if deployable else f"{R}\u2717{X}"
        status = f"{G}APPROVED{X}" if deployable else f"{R}BLOCKED{X}"
        print(f"  {icon} {agent.name:<24} {status}")

    # --- Summary ---
    banner("EU AI Act Articles Demonstrated")
    articles = [
        ("Art. 5",  "Prohibited AI practices detection"),
        ("Art. 6",  "Risk classification (4 tiers)"),
        ("Art. 12", "Record-keeping / decision logging"),
        ("Art. 13", "Transparency documentation"),
        ("Art. 14", "Human oversight requirements"),
        ("Art. 15", "Accuracy, robustness, cybersecurity"),
        ("Art. 17", "Quality management system"),
        ("Art. 50", "Transparency for GPAI"),
    ]
    for art, desc in articles:
        print(f"  {G}\u2713{X} {B}{art:<8}{X} {desc}")

else:
    # Minimal fallback when compliance_checker is not available
    banner("EU AI Act Risk Classification (Simplified)")
    print(f"  {R}Note: Full compliance checker not found.{X}")
    print(f"  {Y}Install: pip install agentmesh-platform{X}")
    print()
    tiers = [
        ("\U0001f6ab", "UNACCEPTABLE", "Social scoring, subliminal manipulation",      R),
        ("\u26a0\ufe0f ", "HIGH",          "Medical diagnosis, recruitment, credit scoring", R),
        ("\u2139\ufe0f ", "LIMITED",       "Chatbots, content generators",                  Y),
        ("\u2705", "MINIMAL",       "Spam filters, game AI",                        G),
    ]
    for icon, tier, examples, color in tiers:
        print(f"  {icon} {color}{B}{tier:<16}{X} {examples}")

    print(f"\n  {Y}Full demo: python examples/06-eu-ai-act-compliance/demo.py{X}")

print(f"\n  {C}Learn more: github.com/microsoft/agent-governance-toolkit{X}")
print(f"  {C}EU AI Act checklist: docs/compliance/eu-ai-act-checklist.md{X}")
print(f"  {C}FRIA template: docs/compliance/fria-template.md{X}")
'@
    $tmpFile = Join-Path $env:TEMP "demo6_eu_ai_act.py"
    $pyScript | Out-File -FilePath $tmpFile -Encoding utf8
    python $tmpFile
}

Write-Host ""
Write-Host ("=" * 65) -ForegroundColor Green
Write-Host "  DEMO COMPLETE - EU AI Act compliance, built into your pipeline!" -ForegroundColor Green
Write-Host ("=" * 65) -ForegroundColor Green
Write-Host ""
Write-Host "TALKING POINTS:" -ForegroundColor DarkGray
Write-Host "  - High-risk obligations apply August 2, 2026 (3 months away)" -ForegroundColor DarkGray
Write-Host "  - Risk classifier maps agents to EU AI Act tiers automatically" -ForegroundColor DarkGray
Write-Host "  - Deployment gate blocks non-compliant agents in CI/CD" -ForegroundColor DarkGray
Write-Host "  - Prohibited practices (Art. 5) detected and blocked" -ForegroundColor DarkGray
Write-Host "  - Annex IV technical documentation auto-generated" -ForegroundColor DarkGray
Write-Host "  - FRIA template included for fundamental rights assessment" -ForegroundColor DarkGray
Write-Host "  - Works offline, no API keys, deterministic" -ForegroundColor DarkGray
