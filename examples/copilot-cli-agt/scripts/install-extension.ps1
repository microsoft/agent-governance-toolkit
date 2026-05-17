# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

[CmdletBinding()]
param(
    [string]$CopilotHome = (Join-Path $HOME ".copilot"),
    [ValidateSet("install", "update")]
    [string]$Command = "install",
    [string]$RepoRoot,
    [switch]$ForcePolicy
)

$scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$exampleRoot = (Resolve-Path (Join-Path $scriptDir "..")).Path
$resolvedRepoRoot = if ($RepoRoot) { (Resolve-Path $RepoRoot).Path } else { (Resolve-Path (Join-Path $exampleRoot "..\..")).Path }
$packageRoot = Join-Path $resolvedRepoRoot "agent-governance-copilot-cli"
$packageManifest = Join-Path $packageRoot "package.json"
$sdkManifest = Join-Path $packageRoot "node_modules\@microsoft\agent-governance-sdk\package.json"

if (-not (Test-Path $packageManifest)) {
    throw "Could not find agent-governance-copilot-cli at $packageRoot"
}

Push-Location $packageRoot
try {
    if (-not (Test-Path $sdkManifest)) {
        npm install --no-fund --no-audit
        if ($LASTEXITCODE -ne 0) {
            throw "npm install failed in $packageRoot"
        }
    }

    $arguments = @(".\bin\agt-copilot.mjs", $Command, "--copilot-home", $CopilotHome)
    if ($Command -eq "update") {
        $arguments += "--replace-unmanaged"
    }
    if ($ForcePolicy) {
        $arguments += "--force-policy"
    }
    node @arguments
    if ($LASTEXITCODE -ne 0) {
        throw "agt-copilot $Command failed"
    }
}
finally {
    Pop-Location
}
