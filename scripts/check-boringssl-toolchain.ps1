#Requires -Version 7.0
param(
    [Parameter(ValueFromRemainingArguments = $true)]
    [string[]]$CargoArguments
)

$ErrorActionPreference = 'Stop'

function Require-Command([string]$Name) {
    $command = Get-Command $Name -ErrorAction SilentlyContinue | Select-Object -First 1
    if (-not $command) { throw "Missing required BoringSSL build tool: $Name" }
    return $command.Source
}

function Find-MsvcCompiler {
    $command = Get-Command 'cl.exe' -ErrorAction SilentlyContinue | Select-Object -First 1
    if ($command) { return $command.Source }
    $vswhere = Join-Path ${env:ProgramFiles(x86)} 'Microsoft Visual Studio\Installer\vswhere.exe'
    if (Test-Path -LiteralPath $vswhere -PathType Leaf) {
        $installation = & $vswhere -latest -products * -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 -property installationPath
        if ($installation) {
            $compiler = Get-ChildItem -LiteralPath (Join-Path $installation 'VC\Tools\MSVC') -Directory |
                Sort-Object Name -Descending |
                ForEach-Object { Join-Path $_.FullName 'bin\Hostx64\x64\cl.exe' } |
                Where-Object { Test-Path -LiteralPath $_ -PathType Leaf } |
                Select-Object -First 1
            if ($compiler) { return $compiler }
        }
    }
    throw 'Missing required BoringSSL build tool: MSVC cl.exe'
}

$tools = [ordered]@{
    cmake = Require-Command 'cmake.exe'
    msvc  = Find-MsvcCompiler
    nasm  = Require-Command 'nasm.exe'
    clang = Require-Command 'clang.exe'
}
$clangDirectory = Split-Path -Parent $tools.clang
$libclang = Join-Path $clangDirectory 'libclang.dll'
if (-not (Test-Path -LiteralPath $libclang -PathType Leaf)) {
    throw "libclang.dll was not found beside clang.exe: $clangDirectory"
}
$env:LIBCLANG_PATH = $clangDirectory

$tools.GetEnumerator() | ForEach-Object { Write-Host ("{0}: {1}" -f $_.Key, $_.Value) }
Write-Host "libclang: $libclang"

if ($CargoArguments.Count -gt 0) {
    & cargo @CargoArguments
    exit $LASTEXITCODE
}
