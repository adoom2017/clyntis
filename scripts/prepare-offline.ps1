#Requires -Version 7.0
param([string]$OutputDirectory)

$ErrorActionPreference = 'Stop'
$workspace = (Resolve-Path (Join-Path $PSScriptRoot '..')).Path
if (-not $OutputDirectory) { $OutputDirectory = Join-Path $workspace 'dist' }
$outputRoot = [System.IO.Path]::GetFullPath($OutputDirectory)
$snapshotName = 'clyntis-offline-' + [Guid]::NewGuid().ToString('N').Substring(0, 8)
$snapshot = Join-Path $outputRoot $snapshotName
New-Item -ItemType Directory -Path $snapshot | Out-Null

Push-Location $workspace
try {
    $metadataJson = cargo metadata --format-version 1 --locked
    if ($LASTEXITCODE -ne 0) { throw 'Could not resolve locked dependencies.' }
    $metadata = $metadataJson | ConvertFrom-Json
    foreach ($package in $metadata.packages) {
        if ($package.source -and $package.source -ne 'registry+https://github.com/rust-lang/crates.io-index') {
            throw "Unapproved dependency source: $($package.name) $($package.source)"
        }
    }

    foreach ($name in @('Cargo.toml', 'Cargo.lock', 'rust-toolchain.toml', 'LICENSE', 'README.md', 'crates', 'third-party', 'examples')) {
        Copy-Item -LiteralPath (Join-Path $workspace $name) -Destination $snapshot -Recurse
    }
    New-Item -ItemType Directory -Path (Join-Path $snapshot 'scripts'), (Join-Path $snapshot '.cargo') | Out-Null
    foreach ($name in @('prepare-offline.ps1', 'prepare-offline.sh', 'verify-offline.ps1', 'verify-offline.sh', 'verify-offline-linux.sh', 'test-vless.ps1', 'test-vless.sh', 'check-boringssl-toolchain.ps1', 'check-mobile.ps1', 'check-mobile.sh', 'package-release.ps1', 'package-release.sh', 'test-desktop-linux.py')) {
        Copy-Item -LiteralPath (Join-Path $PSScriptRoot $name) -Destination (Join-Path $snapshot 'scripts')
    }
    $vendor = Join-Path $snapshot 'vendor'
    cargo vendor --locked --versioned-dirs $vendor | Out-Null
    if ($LASTEXITCODE -ne 0) { throw 'Dependency vendoring failed.' }
    $cargoConfig = @'
[source.crates-io]
replace-with = "vendored-sources"

[source.vendored-sources]
directory = "vendor"

[net]
offline = true
'@
    Set-Content -LiteralPath (Join-Path $snapshot '.cargo/config.toml') -Value $cargoConfig -Encoding utf8NoBOM

    $packages = foreach ($package in ($metadata.packages | Sort-Object name, version)) {
        $checksum = $null
        if ($package.source) {
            $checksumFile = Join-Path $vendor "$($package.name)-$($package.version)/.cargo-checksum.json"
            $checksum = (Get-Content -LiteralPath $checksumFile -Raw | ConvertFrom-Json).package
            if (-not $checksum) { throw "Missing registry checksum: $($package.name)" }
        }
        [ordered]@{
            name = $package.name
            version = $package.version
            source = $package.source
            license = $package.license
            license_file = if ($package.license_file) { Split-Path $package.license_file -Leaf } else { $null }
            sha256 = $checksum
            local_patch = $package.name -in @('boring-sys', 'route_manager') -and -not $package.source
        }
    }
    $revision = git rev-parse HEAD
    if ($LASTEXITCODE -ne 0) { $revision = $null }
    $state = git status --porcelain --untracked-files=normal
    $inventory = [ordered]@{
        format = 1
        created_utc = [DateTime]::UtcNow.ToString('o')
        base_revision = $revision
        working_tree_dirty = [bool]$state
        cargo = (cargo --version)
        rustc = (rustc --version)
        packages = @($packages)
    }
    $inventory | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath (Join-Path $snapshot 'dependency-inventory.json') -Encoding utf8NoBOM

    $files = [ordered]@{}
    foreach ($file in (Get-ChildItem -LiteralPath $snapshot -Recurse -Force -File | Sort-Object FullName)) {
        $relative = [System.IO.Path]::GetRelativePath($snapshot, $file.FullName).Replace('\', '/')
        $files[$relative] = (Get-FileHash -LiteralPath $file.FullName -Algorithm SHA256).Hash.ToLowerInvariant()
    }
    $checksumLines = foreach ($name in $files.Keys) { "$($files[$name])  $name" }
    $checksumPath = Join-Path $snapshot 'snapshot-files.sha256'
    [System.IO.File]::WriteAllText($checksumPath, ($checksumLines -join "`n") + "`n", [System.Text.UTF8Encoding]::new($false))
    $files['snapshot-files.sha256'] = (Get-FileHash -LiteralPath $checksumPath -Algorithm SHA256).Hash.ToLowerInvariant()
    $files | ConvertTo-Json -Depth 3 | Set-Content -LiteralPath (Join-Path $snapshot 'snapshot-files.json') -Encoding utf8NoBOM
    $archive = Join-Path $outputRoot "$snapshotName.tar.gz"
    tar -czf $archive -C $outputRoot $snapshotName
    if ($LASTEXITCODE -ne 0) { throw 'Source archive creation failed.' }
    $hash = (Get-FileHash -LiteralPath $archive -Algorithm SHA256).Hash.ToLowerInvariant()
    "$hash  $snapshotName.tar.gz`n" | Set-Content -LiteralPath "$archive.sha256" -Encoding ascii -NoNewline
    [ordered]@{ archive = $archive; sha256 = $hash; source = $snapshot; packages = $packages.Count } | ConvertTo-Json
} finally {
    Pop-Location
}
