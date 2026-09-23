#Requires -Version 7.0
param([Parameter(Mandatory)][ValidateSet('android', 'ios')][string]$Platform, [string]$Ndk, [switch]$Release)
$ErrorActionPreference = 'Stop'
$workspace = (Resolve-Path (Join-Path $PSScriptRoot '..')).Path
$savedEnvironment = @{}
foreach ($name in @('ANDROID_NDK_HOME', 'CC_aarch64_linux_android', 'CXX_aarch64_linux_android', 'CARGO_TARGET_AARCH64_LINUX_ANDROID_LINKER', 'AR_aarch64_linux_android', 'IPHONEOS_DEPLOYMENT_TARGET')) {
    $savedEnvironment[$name] = [Environment]::GetEnvironmentVariable($name, 'Process')
}
$buildOptions = @('--locked', '--offline')
if ($Release) { $buildOptions += '--release' }
Push-Location $workspace
try {
    if ($Platform -eq 'android') {
        if (-not $Ndk) { $Ndk = $env:ANDROID_NDK_HOME }
        if (-not $Ndk) { throw 'Supply -Ndk or ANDROID_NDK_HOME.' }
        $hostTag = if ($IsWindows) { 'windows-x86_64' } elseif ($IsMacOS) { 'darwin-x86_64' } else { 'linux-x86_64' }
        $bin = Join-Path $Ndk "toolchains/llvm/prebuilt/$hostTag/bin"
        $suffix = if ($IsWindows) { '.cmd' } else { '' }
        $env:ANDROID_NDK_HOME = $Ndk
        $env:CC_aarch64_linux_android = Join-Path $bin "aarch64-linux-android24-clang$suffix"
        $env:CXX_aarch64_linux_android = Join-Path $bin "aarch64-linux-android24-clang++$suffix"
        $env:CARGO_TARGET_AARCH64_LINUX_ANDROID_LINKER = $env:CC_aarch64_linux_android
        $env:AR_aarch64_linux_android = Join-Path $bin $(if ($IsWindows) { 'llvm-ar.exe' } else { 'llvm-ar' })
        foreach ($tool in @($env:CC_aarch64_linux_android, $env:CXX_aarch64_linux_android, $env:AR_aarch64_linux_android)) {
            if (-not (Test-Path -LiteralPath $tool -PathType Leaf)) { throw "Missing Android NDK tool: $tool" }
        }
        cargo build -p meta-ffi --target aarch64-linux-android @buildOptions
    } else {
        if (-not $IsMacOS) { throw 'iOS compilation requires macOS with Xcode and the iPhoneOS SDK.' }
        $env:IPHONEOS_DEPLOYMENT_TARGET = '12.0'
        cargo build -p meta-ffi --target aarch64-apple-ios @buildOptions
    }
    if ($LASTEXITCODE -ne 0) { throw 'Mobile core/FFI build failed.' }
} finally {
    foreach ($name in $savedEnvironment.Keys) {
        [Environment]::SetEnvironmentVariable($name, $savedEnvironment[$name], 'Process')
    }
    Pop-Location
}
