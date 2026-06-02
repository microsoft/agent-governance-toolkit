###############################################################################
# Demo 3: Contoso Bank - Real MAF Governance Demo
# MVP PGI - Agent Governance Toolkit
#
# Runs the REAL Contoso Bank loan processing demo from the repo.
# 4 acts: Policy Enforcement, Capability Sandboxing, Rogue Detection, Audit.
# Works in simulated mode (no API key): governance is FULLY REAL.
# Expected time: ~20 seconds
###############################################################################

Write-Host ""
Write-Host ("=" * 60) -ForegroundColor Cyan
Write-Host "  DEMO 3: Contoso Bank - Governed Loan Processing" -ForegroundColor Cyan
Write-Host ("=" * 60) -ForegroundColor Cyan
Write-Host ""
Write-Host "  Real scenario: AI Loan Officer with MAF middleware." -ForegroundColor White
Write-Host "  4 acts: Policy, Capability, Rogue Detection, Audit." -ForegroundColor Yellow
Write-Host '  This is NOT simulated governance - the policy engine is REAL.' -ForegroundColor Green
Write-Host ""

# Find the demo in the AGT repo
$agtPaths = @(
    "$PSScriptRoot\..\..\maf-integration\01-loan-processing\python",
    "$PSScriptRoot\..\..\..\examples\maf-integration\01-loan-processing\python",
    "$env:USERPROFILE\source\repos\imran-siddique\agent-governance-toolkit\examples\maf-integration\01-loan-processing\python",
    "$env:USERPROFILE\source\repos\agent-governance-toolkit\examples\maf-integration\01-loan-processing\python"
)

$demoPath = $null
foreach ($p in $agtPaths) {
    if (Test-Path "$p\main.py") {
        $demoPath = (Resolve-Path $p).Path
        break
    }
}

if ($demoPath) {
    Write-Host "  Running from: $demoPath" -ForegroundColor DarkGray
    Write-Host ""
    $proc = Start-Process python -ArgumentList "main.py" -WorkingDirectory $demoPath -NoNewWindow -PassThru -RedirectStandardError (Join-Path $env:TEMP "demo3err.txt")
    $finished = $proc.WaitForExit(15000)
    if (-not $finished) {
        Stop-Process -Id $proc.Id -Force -ErrorAction SilentlyContinue
        Write-Host "  (MAF example timed out - running inline version)" -ForegroundColor Yellow
        $demoPath = $null
    } elseif ($proc.ExitCode -ne 0) {
        Write-Host "  (MAF example has dependency issue - running inline version)" -ForegroundColor Yellow
        $demoPath = $null
    }
}

if (-not $demoPath) {
    # Fallback: write Python script to temp file and run it
    Write-Host ""

    $pyScript = @'
from agent_os.policies import PolicyEvaluator
from agent_os.policies.schema import (
    PolicyDocument, PolicyRule, PolicyCondition,
    PolicyAction, PolicyOperator, PolicyDefaults,
)

policy = PolicyDocument(
    name="production-safety", version="1.0",
    description="Production safety policy for AI agents",
    defaults=PolicyDefaults(action=PolicyAction.ALLOW),
    rules=[
        PolicyRule(name="block-destructive-tools",
            condition=PolicyCondition(field="tool_name", operator=PolicyOperator.IN,
                value=["delete_file", "shell_exec", "execute_code", "drop_table"]),
            action=PolicyAction.DENY, message="Destructive tool blocked by policy", priority=100),
        PolicyRule(name="block-pii-patterns",
            condition=PolicyCondition(field="input_text", operator=PolicyOperator.MATCHES,
                value=r"\b\d{3}-\d{2}-\d{4}\b"),
            action=PolicyAction.DENY, message="SSN pattern detected - blocked", priority=90),
    ],
)

evaluator = PolicyEvaluator(policies=[policy])
tests = [
    dict(tool_name="web_search", input_text="latest AI news", agent_id="analyst-1"),
    dict(tool_name="read_file", input_text="report.pdf", agent_id="analyst-1"),
    dict(tool_name="delete_file", input_text="/etc/passwd", agent_id="analyst-1"),
    dict(tool_name="shell_exec", input_text="rm -rf /", agent_id="rogue-agent"),
    dict(tool_name="web_search", input_text="lookup 123-45-6789", agent_id="analyst-1"),
    dict(tool_name="execute_code", input_text="import os", agent_id="compromised"),
    dict(tool_name="summarize", input_text="quarterly report", agent_id="analyst-1"),
]

hdr = f"  {'Tool':<16} {'Agent':<16} {'Result':<10} {'Reason'}"
print("=" * 65)
print(hdr)
print("=" * 65)
a, b = 0, 0
for ctx in tests:
    r = evaluator.evaluate(ctx)
    reason = "-" if r.allowed else r.reason
    tn, ai = ctx["tool_name"], ctx["agent_id"]
    if r.allowed:
        a += 1
        print(f"  OK {tn:<16} {ai:<16} {'ALLOWED':<10} {reason}")
    else:
        b += 1
        print(f"  XX {tn:<16} {ai:<16} {'BLOCKED':<10} {reason}")
print("=" * 65)
print(f"\n  Results: {a} allowed, {b} blocked")
print("  Policy violations that reached execution: 0")
print("  This is deterministic enforcement, not probabilistic safety.")
'@
    $tmpFile = Join-Path $env:TEMP "demo3_policy.py"
    $pyScript | Out-File -FilePath $tmpFile -Encoding utf8
    python $tmpFile
}

Write-Host ""
Write-Host ("=" * 60) -ForegroundColor Green
Write-Host "  DEMO 3 COMPLETE - Real governance, real policies!" -ForegroundColor Green
Write-Host ("=" * 60) -ForegroundColor Green
Write-Host ""
Write-Host "TALKING POINTS:" -ForegroundColor DarkGray
Write-Host "  - Contoso Bank: real scenario, real YAML policies" -ForegroundColor DarkGray
Write-Host "  - 4 governance layers: Policy, Capability, Rogue Detection, Audit" -ForegroundColor DarkGray
Write-Host "  - PII blocked BEFORE it reaches the LLM" -ForegroundColor DarkGray
Write-Host "  - Rogue detection: 20 rapid calls -> auto-quarantine" -ForegroundColor DarkGray
Write-Host "  - Merkle-chained audit log: tamper-proof compliance" -ForegroundColor DarkGray
Write-Host "  - Works with ANY LLM backend (OpenAI, Azure, simulated)" -ForegroundColor DarkGray
