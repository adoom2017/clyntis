#Requires -Version 7.0
param([string]$OutputDirectory, [string]$Target)
$ErrorActionPreference = 'Stop'
$workspace = (Resolve-Path (Join-Path $PSScriptRoot '..')).Path
if (-not $OutputDirectory) { $OutputDirectory = Join-Path $workspace 'dist' }
$outputRoot = [System.IO.Path]::GetFullPath($OutputDirectory)
$savedDeploymentTarget = $env:MACOSX_DEPLOYMENT_TARGET
Push-Location $workspace
try {
    if ($IsMacOS -and -not $env:MACOSX_DEPLOYMENT_TARGET) { $env:MACOSX_DEPLOYMENT_TARGET = '12.0' }
    $explicitTarget = [bool]$Target
    if (-not $Target) {
        $compiler = rustc -vV
        if ($LASTEXITCODE -ne 0) { throw 'Pinned Rust toolchain is unavailable.' }
        $Target = ($compiler | Where-Object { $_.StartsWith('host: ') }).Substring(6)
    }
    if ($Target -notin @('x86_64-pc-windows-msvc', 'x86_64-unknown-linux-gnu', 'aarch64-unknown-linux-gnu', 'x86_64-apple-darwin', 'aarch64-apple-darwin')) {
        throw 'Use a supported desktop target; mobile libraries use check-mobile.ps1.'
    }
    $options = @('build', '--workspace', '--release', '--locked', '--offline')
    if ($explicitTarget) { $options += @('--target', $Target) }
    cargo @options
    if ($LASTEXITCODE -ne 0) { throw 'Release build failed.' }
    $metadataJson = cargo metadata --format-version 1 --locked --offline --filter-platform $Target
    if ($LASTEXITCODE -ne 0) { throw 'Release dependency inventory failed.' }
    $metadata = $metadataJson | ConvertFrom-Json
    $version = ($metadata.packages | Where-Object name -eq 'clyntis').version
    if (-not $version) { throw 'CLI package version is missing.' }
    $name = "clyntis-$version-$Target-" + [Guid]::NewGuid().ToString('N').Substring(0, 8)
    $packageRoot = Join-Path $outputRoot $name
    New-Item -ItemType Directory -Path $packageRoot | Out-Null
    $buildRoot = $metadata.target_directory
    if ($explicitTarget) { $buildRoot = Join-Path $buildRoot $Target }
    $buildRoot = Join-Path $buildRoot 'release'
    $artifacts = if ($Target.Contains('windows')) {
        @('clyntis.exe', 'meta_ffi.dll', 'meta_ffi.dll.lib', 'meta_ffi.lib')
    } elseif ($Target.Contains('apple')) {
        @('clyntis', 'libmeta_ffi.dylib', 'libmeta_ffi.a')
    } else {
        @('clyntis', 'libmeta_ffi.so', 'libmeta_ffi.a')
    }
    foreach ($artifact in $artifacts) {
        Copy-Item -LiteralPath (Join-Path $buildRoot $artifact) -Destination $packageRoot
    }
    foreach ($entry in @('README.md', 'LICENSE', 'examples')) {
        Copy-Item -LiteralPath (Join-Path $workspace $entry) -Destination $packageRoot -Recurse
    }
    Copy-Item -LiteralPath (Join-Path $workspace 'crates/ffi/include') -Destination $packageRoot -Recurse
    $patchNotes = Join-Path $packageRoot 'third-party'
    New-Item -ItemType Directory -Path $patchNotes | Out-Null
    Get-ChildItem -LiteralPath (Join-Path $workspace 'third-party') -Filter '*.md' -File | Copy-Item -Destination $patchNotes
    $licenses = Join-Path $packageRoot 'third-party-licenses'
    New-Item -ItemType Directory -Path $licenses | Out-Null
    $inventory = foreach ($dependency in ($metadata.packages | Sort-Object name, version)) {
        if ($dependency.source -and $dependency.source -ne 'registry+https://github.com/rust-lang/crates.io-index') {
            throw "Unapproved dependency source: $($dependency.name)"
        }
        if ($metadata.workspace_members -contains $dependency.id) { continue }
        $directory = Split-Path $dependency.manifest_path -Parent
        $destination = Join-Path $licenses "$($dependency.name)-$($dependency.version)"
        New-Item -ItemType Directory -Path $destination | Out-Null
        $licenseFiles = @(Get-ChildItem -LiteralPath $directory -Force | Where-Object { $_.Name -match '^(LICENSE|LICENCE|COPYING|NOTICE|COPYRIGHT)([._-].*|S)?$' })
        if ($dependency.license_file) {
            $licensePath = if ([System.IO.Path]::IsPathRooted($dependency.license_file)) { $dependency.license_file } else { Join-Path $directory $dependency.license_file }
            $licenseFiles += Get-Item -LiteralPath $licensePath
        }
        $noticeSource = "$($dependency.name)-$($dependency.version)"
        if ($licenseFiles.Count -eq 0) {
            # Some published workspace members omit the repository-level license
            # files. Archive them from another crate published from the same repo.
            $companion = $metadata.packages | Where-Object {
                $_.id -ne $dependency.id -and $dependency.repository -and $_.repository -eq $dependency.repository
            } | Sort-Object name, { [version]$_.version } -Descending
            foreach ($candidate in $companion) {
                $candidateDirectory = Split-Path $candidate.manifest_path -Parent
                $candidateLicenses = @(Get-ChildItem -LiteralPath $candidateDirectory -Force | Where-Object {
                    $_.Name -match '^(LICENSE|LICENCE|COPYING|NOTICE|COPYRIGHT)([._-].*|S)?$'
                })
                if ($candidateLicenses.Count -gt 0) {
                    $licenseFiles = $candidateLicenses
                    $noticeSource = "$($candidate.name)-$($candidate.version)"
                    break
                }
            }
            if ($licenseFiles.Count -eq 0 -and $dependency.repository) {
                $repositoryName = [System.IO.Path]::GetFileNameWithoutExtension(([Uri]$dependency.repository).AbsolutePath.TrimEnd('/'))
                $overrideDirectory = Join-Path $workspace "third-party/license-overrides/$repositoryName"
                if (Test-Path -LiteralPath $overrideDirectory -PathType Container) {
                    $licenseFiles = @(Get-ChildItem -LiteralPath $overrideDirectory -File)
                    $noticeSource = "repository-license:$repositoryName"
                }
            }
            if ($licenseFiles.Count -eq 0) { throw "Upstream workspace license notices missing for $($dependency.name)." }
        }
        foreach ($licenseFile in ($licenseFiles | Sort-Object FullName -Unique)) {
            Copy-Item -LiteralPath $licenseFile.FullName -Destination $destination -Recurse -Force
        }
        [ordered]@{ name = $dependency.name; version = $dependency.version; license = $dependency.license; source = $dependency.source; notice_source = $noticeSource }
    }
    @($inventory) | ConvertTo-Json -Depth 5 | Set-Content -LiteralPath (Join-Path $packageRoot 'dependencies.json') -Encoding utf8NoBOM
    $files = [ordered]@{}
    foreach ($file in (Get-ChildItem -LiteralPath $packageRoot -Recurse -Force -File | Sort-Object FullName)) {
        $relative = [System.IO.Path]::GetRelativePath($packageRoot, $file.FullName).Replace('\', '/')
        $files[$relative] = (Get-FileHash -LiteralPath $file.FullName -Algorithm SHA256).Hash.ToLowerInvariant()
    }
    $sourceManifest = Join-Path $workspace 'snapshot-files.json'
    $record = [ordered]@{
        format = 1
        version = $version
        target = $Target
        rustc = (rustc --version)
        cargo_lock_sha256 = (Get-FileHash -LiteralPath (Join-Path $workspace 'Cargo.lock') -Algorithm SHA256).Hash.ToLowerInvariant()
        source_snapshot_manifest_sha256 = if (Test-Path -LiteralPath $sourceManifest) { (Get-FileHash -LiteralPath $sourceManifest -Algorithm SHA256).Hash.ToLowerInvariant() } else { $null }
        files = $files
    }
    $record | ConvertTo-Json -Depth 5 | Set-Content -LiteralPath (Join-Path $packageRoot 'release-manifest.json') -Encoding utf8NoBOM
    $archive = Join-Path $outputRoot "$name.tar.gz"
    tar -czf $archive -C $outputRoot $name
    if ($LASTEXITCODE -ne 0) { throw 'Release archive creation failed.' }
    $hash = (Get-FileHash -LiteralPath $archive -Algorithm SHA256).Hash.ToLowerInvariant()
    "$hash  $name.tar.gz`n" | Set-Content -LiteralPath "$archive.sha256" -Encoding ascii -NoNewline
    [ordered]@{ archive = $archive; sha256 = $hash; package = $packageRoot; target = $Target } | ConvertTo-Json
} finally {
    $env:MACOSX_DEPLOYMENT_TARGET = $savedDeploymentTarget
    Pop-Location
}
