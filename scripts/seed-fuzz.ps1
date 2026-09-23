#Requires -Version 7.0
$ErrorActionPreference = 'Stop'
$workspace = (Resolve-Path (Join-Path $PSScriptRoot '..')).Path
$seeds = Get-Content -LiteralPath (Join-Path $workspace 'fuzz/seeds.json') -Raw | ConvertFrom-Json -AsHashtable
foreach ($target in $seeds.Keys) {
    $directory = Join-Path $workspace "fuzz/corpus/$target"
    New-Item -ItemType Directory -Path $directory -Force | Out-Null
    foreach ($name in $seeds[$target].Keys) {
        [System.IO.File]::WriteAllBytes((Join-Path $directory $name), [Convert]::FromHexString($seeds[$target][$name]))
    }
}
