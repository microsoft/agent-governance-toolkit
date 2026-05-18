###############################################################################
# Demo Runner - All 5 demos in sequence
# MVP PGI - Agent Governance Toolkit
# May 2026
#
# Usage:
#   .\demo-run-all.ps1           # Run all demos
#   .\demo-run-all.ps1 -Demo 3   # Run just demo 3
###############################################################################
param(
    [int]$Demo = 0
)

$ErrorActionPreference = "Continue"
$env:PYTHONUTF8 = "1"
$demoDir = $PSScriptRoot
if (-not $demoDir) { $demoDir = "C:\Users\mosiddi\Downloads" }

$demos = @(
    @{ Num = 1; File = "demo-1-install-health-check.ps1";  Title = "Install & Health Check" },
    @{ Num = 2; File = "demo-2-owasp-verify.ps1";          Title = "OWASP Compliance" },
    @{ Num = 3; File = "demo-3-policy-enforcement.ps1";    Title = "Contoso Bank - Real MAF Governance" },
    @{ Num = 4; File = "demo-4-trust-scoring.ps1";         Title = "Two Agents, Zero Trust" },
    @{ Num = 5; File = "demo-5-framework-integration.ps1"; Title = "Wrap Any Agent in 3 Lines" },
    @{ Num = 6; File = "demo-6-eu-ai-act.ps1";             Title = "EU AI Act Compliance Checker" }
)

function Show-Menu {
    Write-Host ""
    Write-Host "=" * 60 -ForegroundColor Magenta
    Write-Host "  Agent Governance Toolkit - MVP PGI Demo Suite" -ForegroundColor Magenta
    Write-Host "  github.com/microsoft/agent-governance-toolkit" -ForegroundColor DarkGray
    Write-Host "=" * 60 -ForegroundColor Magenta
    Write-Host ""
    foreach ($d in $demos) {
        Write-Host "  [$($d.Num)] $($d.Title)" -ForegroundColor Cyan
    }
    Write-Host ""
}

if ($Demo -ge 1 -and $Demo -le 6) {
    $selected = $demos[$Demo - 1]
    & "$demoDir\$($selected.File)"
} else {
    Show-Menu
    foreach ($d in $demos) {
        Write-Host ""
        Write-Host ("-" * 60) -ForegroundColor DarkGray
        Write-Host "  Starting Demo $($d.Num): $($d.Title)" -ForegroundColor Magenta
        Write-Host ("-" * 60) -ForegroundColor DarkGray
        & "$demoDir\$($d.File)"

        if ($d.Num -lt 6) {
            Write-Host ""
            Write-Host "  Press ENTER to continue to next demo..." -ForegroundColor DarkYellow
            Read-Host
        }
    }

    Write-Host ""
    Write-Host "=" * 60 -ForegroundColor Green
    Write-Host "  ALL DEMOS COMPLETE!" -ForegroundColor Green
    Write-Host "=" * 60 -ForegroundColor Green
    Write-Host ""
    Write-Host "  Resources:" -ForegroundColor White
    Write-Host "    GitHub:  github.com/microsoft/agent-governance-toolkit" -ForegroundColor Cyan
    Write-Host "    Docs:    microsoft.github.io/agent-governance-toolkit" -ForegroundColor Cyan
    Write-Host "    Blog:    aka.ms/agt-opensource-blog" -ForegroundColor Cyan
    Write-Host "    Install: pip install agent-governance-toolkit[full]" -ForegroundColor Green
    Write-Host ""
}
