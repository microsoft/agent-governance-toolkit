###############################################################################
# Demo 5: Native framework integration
###############################################################################

$ErrorActionPreference = "Stop"
$demo = Join-Path $PSScriptRoot "..\..\..\crewai-governed\getting_started.py"

Write-Host ""
Write-Host ("=" * 60) -ForegroundColor Cyan
Write-Host "  DEMO 5: Framework Adapter with Native ACS" -ForegroundColor Cyan
Write-Host ("=" * 60) -ForegroundColor Cyan

python $demo
if ($LASTEXITCODE -ne 0) {
    throw "Framework integration demo failed with exit code $LASTEXITCODE"
}

Write-Host ""
Write-Host "  DEMO 5 COMPLETE" -ForegroundColor Green
Write-Host "  - Framework constructor receives runtime=" -ForegroundColor DarkGray
Write-Host "  - Policy definitions stay in the ACS manifest" -ForegroundColor DarkGray
Write-Host "  - Tool and output paths are mediated before side effects" -ForegroundColor DarkGray
