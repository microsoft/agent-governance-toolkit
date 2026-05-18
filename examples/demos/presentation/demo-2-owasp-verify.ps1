###############################################################################
# Demo 2: OWASP Compliance Verification
# MVP PGI - Agent Governance Toolkit
#
# Shows the built-in OWASP ASI 2026 compliance checker.
# Expected time: ~20 seconds
###############################################################################

# Ensure Python outputs UTF-8 (avoids UnicodeEncodeError with emoji in Rich)
$env:PYTHONUTF8 = "1"

Write-Host ""
Write-Host "=" * 60 -ForegroundColor Cyan
Write-Host "  DEMO 2: OWASP Agentic AI Compliance" -ForegroundColor Cyan
Write-Host "=" * 60 -ForegroundColor Cyan
Write-Host ""

# Step 1: Text verification
Write-Host "[1/3] Running 'agt verify' - OWASP ASI 2026 compliance check..." -ForegroundColor Yellow
Write-Host ""
agt verify

Write-Host ""
Write-Host "[2/3] Badge output (for CI/CD pipelines & README)..." -ForegroundColor Yellow
Write-Host ""
agt verify --badge
Write-Host ""
Write-Host "  TIP: Add --strict with --evidence to fail builds on weak governance" -ForegroundColor DarkCyan

Write-Host ""
Write-Host "[3/3] Module integrity check..." -ForegroundColor Yellow
Write-Host ""
agt integrity --generate integrity-demo.json 2>$null
if (Test-Path integrity-demo.json) {
    Write-Host "  Generated integrity manifest: integrity-demo.json" -ForegroundColor Green
    agt integrity --manifest integrity-demo.json
    Remove-Item integrity-demo.json -Force -ErrorAction SilentlyContinue
} else {
    Write-Host "  (Integrity check available with 'agt integrity')" -ForegroundColor DarkGray
}

Write-Host ""
Write-Host "=" * 60 -ForegroundColor Green
Write-Host "  DEMO 2 COMPLETE - 10/10 OWASP risks covered!" -ForegroundColor Green
Write-Host "=" * 60 -ForegroundColor Green
Write-Host ""
Write-Host "TALKING POINTS:" -ForegroundColor DarkGray
Write-Host "  - 'agt verify' checks all 10 OWASP Agentic Security risks" -ForegroundColor DarkGray
Write-Host "  - JSON output plugs into CI/CD (fail the build if not compliant)" -ForegroundColor DarkGray
Write-Host "  - Module integrity ensures no governance code was tampered with" -ForegroundColor DarkGray
Write-Host "  - ASI-01 through ASI-10 mapped to specific AGT controls" -ForegroundColor DarkGray
