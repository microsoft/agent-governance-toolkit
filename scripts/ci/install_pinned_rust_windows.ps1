# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

param(
    [Parameter(Mandatory = $true)]
    [ValidateSet("x86_64-pc-windows-msvc")]
    [string]$Target
)

$ErrorActionPreference = "Stop"
$rustupVersion = "1.27.1"
$rustToolchain = "1.89.0"
$rustupTarget = "x86_64-pc-windows-msvc"
$rustupSha256 = "193d6c727e18734edbf7303180657e96e9d5a08432002b4e6c5bbe77c60cb3e8"
$installer = Join-Path $env:AGENT_TEMPDIRECTORY "rustup-init.exe"
$uri = "https://static.rust-lang.org/rustup/archive/$rustupVersion/$rustupTarget/rustup-init.exe"

Invoke-WebRequest -Uri $uri -OutFile $installer -MaximumRetryCount 5 -RetryIntervalSec 5
$actualSha256 = (Get-FileHash -Path $installer -Algorithm SHA256).Hash.ToLowerInvariant()
if ($actualSha256 -ne $rustupSha256) {
    throw "rustup installer checksum mismatch"
}

& $installer -y --profile minimal --default-toolchain $rustToolchain
if ($LASTEXITCODE -ne 0) {
    exit $LASTEXITCODE
}
$cargoBin = Join-Path $env:USERPROFILE ".cargo\bin"
$env:PATH = "$cargoBin;$env:PATH"
& rustup target add --toolchain $rustToolchain $Target
if ($LASTEXITCODE -ne 0) {
    exit $LASTEXITCODE
}
& rustc --version
& cargo --version
Write-Host "##vso[task.prependpath]$cargoBin"
