# Agent OS Quickstart Script for Windows
# Run with: powershell -ExecutionPolicy Bypass -File quickstart.ps1

$ErrorActionPreference = "Continue"

Write-Host "[Agent OS] Quickstart" -ForegroundColor Cyan
Write-Host "======================"

# Check for Python
$pythonVersion = python --version 2>&1
if ($LASTEXITCODE -ne 0) {
    Write-Host "[ERROR] Python is required. Install from https://python.org" -ForegroundColor Red
    exit 1
}
Write-Host "[OK] Found $pythonVersion" -ForegroundColor Green

# Check if we're in the agent-os repo (for local development)
$InRepo = (Test-Path ".\src\agent_os") -or (Test-Path "..\src\agent_os") -or (Test-Path ".\pyproject.toml")

if ($InRepo) {
    Write-Host ""
    Write-Host "[*] Detected agent-os repository - installing from source..." -ForegroundColor Yellow
    
    # Find the repo root
    if (Test-Path ".\pyproject.toml") {
        $RepoRoot = "."
    } elseif (Test-Path "..\pyproject.toml") {
        $RepoRoot = ".."
    } else {
        $RepoRoot = "."
    }
    
    pip install -e "$RepoRoot" 2>&1 | Out-Null
    if ($LASTEXITCODE -ne 0) {
        Write-Host "[ERROR] Failed to install Agent OS from source" -ForegroundColor Red
        Write-Host "        Run manually: pip install -e $RepoRoot" -ForegroundColor Yellow
        exit 1
    }
    Write-Host "[OK] Agent OS installed from source" -ForegroundColor Green
} else {
    # Try to install from PyPI
    Write-Host ""
    Write-Host "[*] Installing Agent OS from PyPI..." -ForegroundColor Yellow
    
    pip install agent-os-kernel 2>&1 | Out-Null
    if ($LASTEXITCODE -ne 0) {
        Write-Host "[ERROR] Agent OS is not yet published to PyPI." -ForegroundColor Red
        Write-Host ""
        Write-Host "To install from source:" -ForegroundColor Yellow
        Write-Host "  git clone https://github.com/microsoft/agent-governance-toolkit.git"
        Write-Host "  cd agent-os"
        Write-Host "  pip install -e ."
        Write-Host ""
        Write-Host "Then run this quickstart again from within the repo."
        exit 1
    }
    Write-Host "[OK] Agent OS installed" -ForegroundColor Green
}

# Create demo project
$DemoDir = "agent-os-demo"
Write-Host ""
Write-Host "[*] Creating demo project in .\$DemoDir" -ForegroundColor Yellow

New-Item -ItemType Directory -Path $DemoDir -Force | Out-Null
Set-Location $DemoDir

# Create agent.py using StatelessKernel (always available)
$AgentCode = @"
"""Agent OS Demo - Your First Governed Agent"""
import asyncio
from agent_os import StatelessKernel, ExecutionContext

# Create stateless kernel (no external dependencies)
kernel = StatelessKernel()

async def my_agent(task: str) -> str:
    """Process a task safely through the kernel."""
    
    # Create execution context
    ctx = ExecutionContext(
        agent_id="demo-agent",
        policies=["read_only"]  # Apply safety policy
    )
    
    # Execute through the kernel
    result = await kernel.execute(
        action="process_task",
        params={"task": task, "output": f"Processed: {task.upper()}"},
        context=ctx
    )
    
    return result.data if result.success else f"Error: {result.error}"

async def main():
    print("[Agent OS] Demo")
    print("=" * 40)
    
    result = await my_agent("Hello, Agent OS!")
    print(f"[OK] Result: {result}")
    print("")
    print("Success! Your agent ran safely under kernel governance!")
    print("")
    print("The kernel checked the 'read_only' policy before execution.")

if __name__ == "__main__":
    asyncio.run(main())
"@

$AgentCode | Out-File -FilePath "agent.py" -Encoding ASCII

Write-Host "[OK] Created agent.py" -ForegroundColor Green

# Run the demo
Write-Host ""
Write-Host "[*] Running your first governed agent..." -ForegroundColor Yellow
Write-Host ""

python agent.py
if ($LASTEXITCODE -ne 0) {
    Write-Host ""
    Write-Host "[ERROR] Agent failed to run. Check the error above." -ForegroundColor Red
    exit 1
}

Write-Host ""
Write-Host "[SUCCESS] Quickstart Complete!" -ForegroundColor Green
Write-Host "   Project: $(Get-Location)"
Write-Host "   Docs: https://github.com/microsoft/agent-governance-toolkit/tree/main/docs"
