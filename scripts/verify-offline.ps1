#Requires -Version 7.0
param([string]$SourceDirectory = (Join-Path $PSScriptRoot '..'))

$ErrorActionPreference = 'Stop'
$sourceRoot = (Resolve-Path -LiteralPath $SourceDirectory).Path
$manifestPath = Join-Path $sourceRoot 'snapshot-files.json'
$manifest = Get-Content -LiteralPath $manifestPath -Raw | ConvertFrom-Json -AsHashtable
$actualFiles = @(Get-ChildItem -LiteralPath $sourceRoot -Recurse -Force -File | Where-Object FullName -ne $manifestPath)
if ($manifest.Count -ne $actualFiles.Count) { throw 'Snapshot file inventory does not match the extracted source.' }
foreach ($file in $actualFiles) {
    $relative = [System.IO.Path]::GetRelativePath($sourceRoot, $file.FullName).Replace('\', '/')
    $hash = (Get-FileHash -LiteralPath $file.FullName -Algorithm SHA256).Hash.ToLowerInvariant()
    if (-not $manifest.ContainsKey($relative) -or $manifest[$relative] -ne $hash) {
        throw "Snapshot checksum mismatch: $relative"
    }
}

$verificationRoot = Join-Path ([System.IO.Path]::GetTempPath()) ('clyntis-offline-' + [Guid]::NewGuid().ToString('N'))
$cargoHome = Join-Path $verificationRoot 'cargo-home'
$buildRoot = Join-Path $verificationRoot 'build'
New-Item -ItemType Directory -Path $cargoHome, $buildRoot | Out-Null
$savedEnvironment = @{}
foreach ($name in @('CARGO_HOME', 'CARGO_TARGET_DIR', 'CARGO_NET_OFFLINE')) {
    $savedEnvironment[$name] = [Environment]::GetEnvironmentVariable($name, 'Process')
}
Push-Location $sourceRoot
try {
    $env:CARGO_HOME = $cargoHome
    $env:CARGO_TARGET_DIR = $buildRoot
    $env:CARGO_NET_OFFLINE = 'true'
    rustup run 1.93.1 cargo build --workspace --release --locked --offline 2>&1 | Tee-Object -FilePath (Join-Path $verificationRoot 'build.log')
    if ($LASTEXITCODE -ne 0) { throw "Offline build failed; see $verificationRoot/build.log" }
    $binaryName = if ($IsWindows) { 'clyntis.exe' } else { 'clyntis' }
    $binary = Join-Path $buildRoot "release/$binaryName"
    $version = & $binary -v
    if ($LASTEXITCODE -ne 0) { throw 'Offline executable version check failed.' }
    & $binary -f (Join-Path $sourceRoot 'examples/vless.yaml') -t
    if ($LASTEXITCODE -ne 0) { throw 'Offline executable configuration check failed.' }
    $cachedCrates = @(Get-ChildItem -LiteralPath $cargoHome -Recurse -Filter '*.crate')
    if ($cachedCrates.Count -ne 0) { throw 'Unexpected Cargo registry archives in the isolated cache.' }
    $result = [ordered]@{
        source = $sourceRoot
        version = $version
        rustc = (rustup run 1.93.1 rustc -vV) -join "`n"
        offline = $true
        empty_initial_cargo_home = $true
        empty_initial_target_directory = $true
        snapshot_files_verified = $manifest.Count
        executable = $binary
        executable_sha256 = (Get-FileHash -LiteralPath $binary -Algorithm SHA256).Hash.ToLowerInvariant()
    }
    $result | ConvertTo-Json | Tee-Object -FilePath (Join-Path $verificationRoot 'result.json')
} finally {
    foreach ($name in $savedEnvironment.Keys) {
        [Environment]::SetEnvironmentVariable($name, $savedEnvironment[$name], 'Process')
    }
    Pop-Location
}
