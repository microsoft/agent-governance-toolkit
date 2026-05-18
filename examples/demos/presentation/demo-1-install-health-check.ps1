###############################################################################
# Demo 1: Install & Health Check
# MVP PGI - Agent Governance Toolkit
# 
# Run this FIRST to install AGT and verify your environment.
# Expected time: ~30 seconds
###############################################################################

# Ensure Python outputs UTF-8 (avoids UnicodeEncodeError with emoji in Rich)
$env:PYTHONUTF8 = "1"

Write-Host ""
Write-Host "=" * 60 -ForegroundColor Cyan
Write-Host "  DEMO 1: Install & Health Check" -ForegroundColor Cyan
Write-Host "=" * 60 -ForegroundColor Cyan
Write-Host ""

# Step 1: Install
Write-Host "[1/3] Installing agent-governance-toolkit..." -ForegroundColor Yellow
pip install agent-governance-toolkit[full] --quiet 2>&1 | Select-Object -Last 3

Write-Host ""
Write-Host "[2/3] Running 'agt doctor' - environment health check..." -ForegroundColor Yellow
Write-Host ""
agt doctor

Write-Host ""
Write-Host "[3/3] Checking installed version..." -ForegroundColor Yellow
pip show agent-governance-toolkit 2>$null | Select-String "Version|Name"

Write-Host ""
Write-Host "=" * 60 -ForegroundColor Green
Write-Host "  DEMO 1 COMPLETE - Environment is healthy!" -ForegroundColor Green
Write-Host "=" * 60 -ForegroundColor Green
Write-Host ""
Write-Host "TALKING POINTS:" -ForegroundColor DarkGray
Write-Host "  - One pip install gets you everything" -ForegroundColor DarkGray
Write-Host "  - 'agt doctor' verifies all packages, Python version, etc." -ForegroundColor DarkGray
Write-Host "  - Individual packages also available (agent-os-kernel, etc.)" -ForegroundColor DarkGray
