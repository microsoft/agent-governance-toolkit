# Build and publish script for SCAK PyPI package (PowerShell)
# This script helps prepare the package for PyPI publication on Windows

$ErrorActionPreference = "Stop"

Write-Host "======================================" -ForegroundColor Cyan
Write-Host "SCAK Package Build & Publish Script" -ForegroundColor Cyan
Write-Host "======================================" -ForegroundColor Cyan
Write-Host ""

# Check if we're in the right directory
if (-not (Test-Path "setup.py")) {
    Write-Host "Error: setup.py not found. Run this script from the repository root." -ForegroundColor Red
    exit 1
}

# Clean previous builds
Write-Host "1. Cleaning previous builds..." -ForegroundColor Yellow
if (Test-Path "build") { Remove-Item -Recurse -Force "build" }
if (Test-Path "dist") { Remove-Item -Recurse -Force "dist" }
Get-ChildItem -Filter "*.egg-info" -Directory | Remove-Item -Recurse -Force
Write-Host "   ✓ Cleaned" -ForegroundColor Green
Write-Host ""

# Install build dependencies
Write-Host "2. Installing build dependencies..." -ForegroundColor Yellow
pip install --upgrade build twine
Write-Host "   ✓ Dependencies installed" -ForegroundColor Green
Write-Host ""

# Build the package
Write-Host "3. Building package..." -ForegroundColor Yellow
python -m build
Write-Host "   ✓ Package built successfully" -ForegroundColor Green
Write-Host ""

# Check the distribution
Write-Host "4. Checking package with twine..." -ForegroundColor Yellow
python -m twine check dist/*
Write-Host "   ✓ Package check passed" -ForegroundColor Green
Write-Host ""

# Display package info
Write-Host "5. Package information:" -ForegroundColor Yellow
Write-Host "   Contents of dist/:"
Get-ChildItem dist/ | Format-Table Name, Length, LastWriteTime
Write-Host ""

# Instructions for publishing
Write-Host "======================================" -ForegroundColor Cyan
Write-Host "Package is ready for publication!" -ForegroundColor Cyan
Write-Host "======================================" -ForegroundColor Cyan
Write-Host ""
Write-Host "To test on TestPyPI:" -ForegroundColor Yellow
Write-Host "  python -m twine upload --repository testpypi dist/*"
Write-Host ""
Write-Host "To publish to PyPI (using .pypirc):" -ForegroundColor Yellow
Write-Host "  python -m twine upload --config-file .pypirc dist/*"
Write-Host ""
Write-Host "To publish to PyPI (using environment variables):" -ForegroundColor Yellow
Write-Host '  $env:TWINE_USERNAME = "__token__"'
Write-Host '  $env:TWINE_PASSWORD = "<your-pypi-token>"'
Write-Host "  python -m twine upload dist/*"
Write-Host ""
Write-Host "To install locally and test:" -ForegroundColor Yellow
Write-Host "  pip install (Get-ChildItem dist/*.whl)"
Write-Host ""
Write-Host "To verify installation:" -ForegroundColor Yellow
Write-Host '  python -c "from agent_kernel import SelfCorrectingKernel; print(''Success!'')"'
Write-Host ""
Write-Host "To create git tags:" -ForegroundColor Yellow
Write-Host "  git tag -a v1.1.0 -m 'Release v1.1.0 - Production features'"
Write-Host "  git push origin --tags"
Write-Host ""
