###############################################################################
# Demo 3: Native ACS policy enforcement
###############################################################################

$ErrorActionPreference = "Stop"
$demo = Join-Path $PSScriptRoot "..\..\..\deerflow-governed\demo.py"

Write-Host ""
Write-Host ("=" * 60) -ForegroundColor Cyan
Write-Host "  DEMO 3: Native ACS Policy Enforcement" -ForegroundColor Cyan
Write-Host ("=" * 60) -ForegroundColor Cyan

python $demo
if ($LASTEXITCODE -ne 0) {
    throw "Native policy demo failed with exit code $LASTEXITCODE"
}

Write-Host ""
Write-Host "  DEMO 3 COMPLETE" -ForegroundColor Green
Write-Host "  - ACS manifest and Rego bundle" -ForegroundColor DarkGray
Write-Host "  - Native intervention-point evaluation" -ForegroundColor DarkGray
Write-Host "  - Sanitized denials and structured audit" -ForegroundColor DarkGray
