<#
.SYNOPSIS
    Build and publish all Agent-OS packages to PyPI.
.PARAMETER Target
    Publish target: 'pypi' (default) or 'testpypi'
.PARAMETER BuildOnly
    If set, only build packages without publishing
.PARAMETER DryRun
    If set, run twine check but don't actually upload
.PARAMETER Packages
    Comma-separated list of package names to publish. If omitted, all packages are published.
.EXAMPLE
    .\scripts\publish-all.ps1
    .\scripts\publish-all.ps1 -Target testpypi
    .\scripts\publish-all.ps1 -BuildOnly
    .\scripts\publish-all.ps1 -DryRun
    .\scripts\publish-all.ps1 -Packages "agent-os-kernel,cmvk,emk"
#>

param(
    [ValidateSet("pypi", "testpypi")]
    [string]$Target = "pypi",
    [switch]$BuildOnly,
    [switch]$DryRun,
    [string]$Packages = ""
)

$ErrorActionPreference = "Stop"
$RepoRoot = (Get-Item (Join-Path $PSScriptRoot "..")).FullName

Write-Host ""
Write-Host "============================================" -ForegroundColor Cyan
Write-Host "  Agent-OS -- Publish All Packages" -ForegroundColor Cyan
Write-Host "============================================" -ForegroundColor Cyan
Write-Host ""
Write-Host "  Repo Root : $RepoRoot"
Write-Host "  Target    : $Target"
Write-Host "  Build Only: $BuildOnly"
Write-Host "  Dry Run   : $DryRun"
Write-Host ""

# Package registry - dependencies first, then dependents
$AllPackages = @(
    @{ Name = "agent-primitives";           Dir = "..\..\agent-governance-python\agent-primitives" }
    @{ Name = "cmvk";                       Dir = "modules/cmvk" }
    @{ Name = "caas-core";                  Dir = "modules/caas" }
    @{ Name = "emk";                        Dir = "modules/emk" }
    @{ Name = "amb-core";                   Dir = "modules/amb" }
    @{ Name = "agent-tool-registry";        Dir = "modules/atr" }
    @{ Name = "inter-agent-trust-protocol"; Dir = "modules/iatp" }
    @{ Name = "agent-control-plane";        Dir = "modules/control-plane" }
    @{ Name = "scak";                       Dir = "modules/scak" }
    @{ Name = "mute-agent";                 Dir = "modules/mute-agent" }
    @{ Name = "mcp-kernel-server";          Dir = "modules/mcp-kernel-server" }
    @{ Name = "agent-os-observability";     Dir = "modules/observability" }
    @{ Name = "nexus-trust-exchange";       Dir = "modules/nexus" }
    @{ Name = "agent-os-kernel";            Dir = "." }
)

# Filter packages if specified
if ($Packages -ne "") {
    $selected = $Packages -split "," | ForEach-Object { $_.Trim() }
    $AllPackages = $AllPackages | Where-Object { $selected -contains $_.Name }
    if ($AllPackages.Count -eq 0) {
        Write-Host "ERROR: No matching packages found for: $Packages" -ForegroundColor Red
        exit 1
    }
}

# Preflight checks
Write-Host "-- Preflight Checks --" -ForegroundColor Yellow
$pythonVersion = python --version 2>&1
Write-Host "  Python: $pythonVersion" -ForegroundColor Gray

try { python -m build --version 2>&1 | Out-Null; Write-Host "  build:  OK" -ForegroundColor Gray }
catch { Write-Host "  build:  MISSING" -ForegroundColor Red; pip install build }

try { twine --version 2>&1 | Out-Null; Write-Host "  twine:  OK" -ForegroundColor Gray }
catch { Write-Host "  twine:  MISSING" -ForegroundColor Red; pip install twine }

Write-Host ""

# Build and Publish Loop
$results = [System.Collections.ArrayList]::new()
$totalPackages = $AllPackages.Count
$current = 0

foreach ($pkg in $AllPackages) {
    $current++
    $pkgDir = Join-Path $RepoRoot $pkg.Dir
    $pkgName = $pkg.Name

    Write-Host "--------------------------------------------" -ForegroundColor DarkGray
    Write-Host "[$current/$totalPackages] $pkgName" -ForegroundColor White
    Write-Host "  Directory: $($pkg.Dir)" -ForegroundColor Gray

    if (-not (Test-Path $pkgDir)) {
        Write-Host "  SKIP: Directory not found" -ForegroundColor Red
        [void]$results.Add(@{ Name = $pkgName; Status = "SKIP"; Reason = "Directory not found" })
        continue
    }

    $hasPyproject = Test-Path (Join-Path $pkgDir "pyproject.toml")
    $hasSetupPy = Test-Path (Join-Path $pkgDir "setup.py")
    if ((-not $hasPyproject) -and (-not $hasSetupPy)) {
        Write-Host "  SKIP: No pyproject.toml or setup.py" -ForegroundColor Red
        [void]$results.Add(@{ Name = $pkgName; Status = "SKIP"; Reason = "No build config" })
        continue
    }

    # Clean old dist/
    $distDir = Join-Path $pkgDir "dist"
    if (Test-Path $distDir) {
        Write-Host "  Cleaning old dist/..." -ForegroundColor Gray
        Remove-Item -Recurse -Force $distDir
    }

    # Build
    Write-Host "  Building..." -ForegroundColor Cyan
    Push-Location $pkgDir
    try {
        $buildOutput = python -m build 2>&1
        if ($LASTEXITCODE -ne 0) {
            Write-Host "  BUILD FAILED:" -ForegroundColor Red
            $buildOutput | ForEach-Object { Write-Host "    $_" -ForegroundColor Red }
            [void]$results.Add(@{ Name = $pkgName; Status = "FAIL"; Reason = "Build failed" })
            Pop-Location
            continue
        }

        # List built artifacts
        $artifacts = Get-ChildItem (Join-Path $pkgDir "dist") -File
        foreach ($a in $artifacts) {
            $sizeKB = [math]::Round($a.Length / 1KB, 1)
            Write-Host "    -> $($a.Name) ($sizeKB KB)" -ForegroundColor Green
        }

        # Twine check
        Write-Host "  Checking with twine..." -ForegroundColor Cyan
        $checkOutput = python -m twine check dist/* 2>&1
        if ($LASTEXITCODE -ne 0) {
            Write-Host "  TWINE CHECK FAILED:" -ForegroundColor Red
            $checkOutput | ForEach-Object { Write-Host "    $_" -ForegroundColor Red }
            [void]$results.Add(@{ Name = $pkgName; Status = "FAIL"; Reason = "Twine check failed" })
            Pop-Location
            continue
        }
        Write-Host "  Twine check: PASSED" -ForegroundColor Green

        if ($BuildOnly) {
            [void]$results.Add(@{ Name = $pkgName; Status = "BUILT"; Reason = "Build only mode" })
            Pop-Location
            continue
        }

        if ($DryRun) {
            Write-Host "  DRY RUN: Would publish to $Target" -ForegroundColor Yellow
            [void]$results.Add(@{ Name = $pkgName; Status = "DRY-RUN"; Reason = "Dry run" })
            Pop-Location
            continue
        }

        # Publish
        Write-Host "  Publishing to $Target..." -ForegroundColor Cyan
        if ($Target -eq "testpypi") {
            $uploadOutput = python -m twine upload --repository testpypi dist/* 2>&1
        }
        else {
            $uploadOutput = python -m twine upload dist/* 2>&1
        }

        if ($LASTEXITCODE -ne 0) {
            $alreadyExists = $uploadOutput | Where-Object { $_ -match "File already exists|already been uploaded" }
            if ($alreadyExists) {
                Write-Host "  ALREADY PUBLISHED (version exists on $Target)" -ForegroundColor Yellow
                [void]$results.Add(@{ Name = $pkgName; Status = "EXISTS"; Reason = "Already published" })
            }
            else {
                Write-Host "  PUBLISH FAILED:" -ForegroundColor Red
                $uploadOutput | ForEach-Object { Write-Host "    $_" -ForegroundColor Red }
                [void]$results.Add(@{ Name = $pkgName; Status = "FAIL"; Reason = "Upload failed" })
            }
        }
        else {
            Write-Host "  PUBLISHED" -ForegroundColor Green
            [void]$results.Add(@{ Name = $pkgName; Status = "PUBLISHED"; Reason = "Success" })
        }
    }
    catch {
        Write-Host "  ERROR: $_" -ForegroundColor Red
        [void]$results.Add(@{ Name = $pkgName; Status = "FAIL"; Reason = $_.ToString() })
    }
    finally {
        Pop-Location
    }
}

# Summary
Write-Host ""
Write-Host "============================================" -ForegroundColor Cyan
Write-Host "  Summary" -ForegroundColor Cyan
Write-Host "============================================" -ForegroundColor Cyan
Write-Host ""

$maxNameLen = ($results | ForEach-Object { $_.Name.Length } | Measure-Object -Maximum).Maximum
foreach ($r in $results) {
    $paddedName = $r.Name.PadRight($maxNameLen)
    $statusPad = $r.Status.PadRight(10)
    switch ($r.Status) {
        "PUBLISHED" { Write-Host "  $paddedName  $statusPad  $($r.Reason)" -ForegroundColor Green }
        "BUILT"     { Write-Host "  $paddedName  $statusPad  $($r.Reason)" -ForegroundColor Green }
        "DRY-RUN"   { Write-Host "  $paddedName  $statusPad  $($r.Reason)" -ForegroundColor Yellow }
        "EXISTS"    { Write-Host "  $paddedName  $statusPad  $($r.Reason)" -ForegroundColor Yellow }
        "SKIP"      { Write-Host "  $paddedName  $statusPad  $($r.Reason)" -ForegroundColor DarkGray }
        "FAIL"      { Write-Host "  $paddedName  $statusPad  $($r.Reason)" -ForegroundColor Red }
        default     { Write-Host "  $paddedName  $statusPad  $($r.Reason)" -ForegroundColor White }
    }
}

$published = @($results | Where-Object { $_.Status -eq "PUBLISHED" }).Count
$built = @($results | Where-Object { $_.Status -eq "BUILT" }).Count
$failed = @($results | Where-Object { $_.Status -eq "FAIL" }).Count
$skipped = @($results | Where-Object { $_.Status -eq "SKIP" }).Count
$exists = @($results | Where-Object { $_.Status -eq "EXISTS" }).Count

Write-Host ""
Write-Host "  Published: $published | Built: $built | Exists: $exists | Failed: $failed | Skipped: $skipped" -ForegroundColor White
Write-Host ""

if ($failed -gt 0) {
    Write-Host "Some packages failed. Check output above." -ForegroundColor Red
    exit 1
}

Write-Host "Done!" -ForegroundColor Green
