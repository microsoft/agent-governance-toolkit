###############################################################################
# Demo 5: Add Governance to Any Agent - 3 Lines of Code
# MVP PGI - Agent Governance Toolkit
#
# Shows that governance wraps around ANY framework without rewriting.
# Uses real AGT PolicyEvaluator with a real policy to intercept calls.
# Expected time: ~15 seconds
###############################################################################

Write-Host ""
Write-Host ("=" * 60) -ForegroundColor Cyan
Write-Host "  DEMO 5: Wrap Any Agent in 3 Lines" -ForegroundColor Cyan
Write-Host ("=" * 60) -ForegroundColor Cyan
Write-Host ""
Write-Host "  No framework rewrite. No vendor lock-in." -ForegroundColor White
Write-Host "  Same policy engine, any framework." -ForegroundColor Yellow
Write-Host ""

python "$PSScriptRoot\demo5_framework.py"

Write-Host ""
Write-Host ("=" * 60) -ForegroundColor Green
Write-Host "  DEMO 5 COMPLETE - Governance for any framework!" -ForegroundColor Green
Write-Host ("=" * 60) -ForegroundColor Green
Write-Host ""
Write-Host "TALKING POINTS:" -ForegroundColor DarkGray
Write-Host "  - 3 lines to add governance to ANY existing agent" -ForegroundColor DarkGray
Write-Host "  - Same YAML policy, same engine, any framework" -ForegroundColor DarkGray
Write-Host "  - Real PolicyEvaluator running real rules (not a mock)" -ForegroundColor DarkGray
Write-Host "  - SSN pattern matched via regex - data exfiltration blocked" -ForegroundColor DarkGray
Write-Host "  - 4 language SDKs: Python, TypeScript, .NET, Rust" -ForegroundColor DarkGray
