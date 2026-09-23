#Requires -Version 7.0
param([string]$XrayPath)

$ErrorActionPreference = 'Stop'
$workspace = (Resolve-Path (Join-Path $PSScriptRoot '..')).Path
$oracleDir = Join-Path $workspace 'target/oracles/xray-v25.9.11'
$archiveHash = 'd8db96eb39d7bc8cae484b2e59b651ff3c04f21e26d66e310f6a44e256ed1cc4'
$binaryHash = 'c478ce1f56ff0b09ad804868e16bf4bbc4020a7f1f09c2ae9df20f5068c8e23a'

if (-not $XrayPath) {
    if (-not $IsWindows) { throw 'Supply -XrayPath for non-Windows hosts.' }
    New-Item -ItemType Directory -Path $oracleDir -Force | Out-Null
    $archive = Join-Path $oracleDir 'Xray-windows-64.zip'
    if (-not (Test-Path -LiteralPath $archive)) {
        Invoke-WebRequest -Uri 'https://github.com/XTLS/Xray-core/releases/download/v25.9.11/Xray-windows-64.zip' -OutFile $archive
    }
    if ((Get-FileHash -LiteralPath $archive -Algorithm SHA256).Hash.ToLowerInvariant() -ne $archiveHash) {
        throw 'Xray v25.9.11 archive checksum mismatch.'
    }
    $XrayPath = Join-Path $oracleDir 'xray.exe'
    if (-not (Test-Path -LiteralPath $XrayPath)) {
        Expand-Archive -LiteralPath $archive -DestinationPath $oracleDir -Force
    }
    if ((Get-FileHash -LiteralPath $XrayPath -Algorithm SHA256).Hash.ToLowerInvariant() -ne $binaryHash) {
        throw 'Xray v25.9.11 executable checksum mismatch.'
    }
}

$previousOracle = $env:XRAY_BIN
Push-Location $workspace
try {
    $env:XRAY_BIN = (Resolve-Path -LiteralPath $XrayPath).Path
    cargo test -p meta-protocol --locked --offline --test xray_vless --test reality_interop -- --ignored --nocapture
    if ($LASTEXITCODE -ne 0) { throw 'VLESS interoperability tests failed.' }
} finally {
    $env:XRAY_BIN = $previousOracle
    Pop-Location
}
