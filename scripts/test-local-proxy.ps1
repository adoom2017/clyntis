#Requires -Version 7.0
<#
Validates a private configuration without printing CLI diagnostics or credentials.
It can test an already-running proxy, or start an isolated VLESS-only/no-TUN
instance on an automatically selected mixed HTTP/SOCKS port.
Exit codes: 0 passed, 1 validation/request failure, 2 setup failure.
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory)][string]$ConfigPath,
    [string]$Executable = (Join-Path $PSScriptRoot '../target/debug/clyntis.exe'),
    [ValidateRange(0,65535)][int]$HttpProxyPort = 0,
    [ValidateRange(0,65535)][int]$SocksProxyPort = 0,
    [switch]$StartProxy,
    [switch]$TestResources,
    [ValidateSet('','chrome','firefox','safari','ios','android','edge','360','qq','random','randomized','native')]
    [string]$ProxyTestClientFingerprint = '',
    [uri]$HttpUrl = 'http://example.com/',
    [uri]$HttpsUrl = 'https://example.com/',
    [ValidateRange(1,120)][int]$TimeoutSeconds = 20
)
$ErrorActionPreference = 'Stop'
$ownedProcess = $null
$networkFailed = $false

function Invoke-Captured([string]$Program, [string[]]$Arguments, [int]$Deadline) {
    $info = [System.Diagnostics.ProcessStartInfo]::new()
    $info.FileName = $Program
    $info.UseShellExecute = $false
    $info.CreateNoWindow = $true
    $info.RedirectStandardOutput = $true
    $info.RedirectStandardError = $true
    foreach ($argument in $Arguments) { $info.ArgumentList.Add($argument) }
    # Prevent inherited CLI settings from overriding the explicitly supplied file.
    foreach ($key in @('CLASH_CONFIG_STRING','CLASH_CONFIG_FILE','CLASH_HOME_DIR',
                       'CLASH_OVERRIDE_EXTERNAL_CONTROLLER','CLASH_OVERRIDE_SECRET')) {
        $null = $info.Environment.Remove($key)
    }
    $process = [System.Diagnostics.Process]::new()
    $process.StartInfo = $info
    try {
        $null = $process.Start()
        $stdout = $process.StandardOutput.ReadToEndAsync()
        $stderr = $process.StandardError.ReadToEndAsync()
        if (-not $process.WaitForExit($Deadline * 1000)) {
            $process.Kill($true)
            $process.WaitForExit()
            return @{ Code = -1; Output = '' }
        }
        $null = $stderr.GetAwaiter().GetResult()
        return @{ Code = $process.ExitCode; Output = $stdout.GetAwaiter().GetResult() }
    } finally { $process.Dispose() }
}

function Get-FreeTcpPort {
    $listener = [System.Net.Sockets.TcpListener]::new(
        [System.Net.IPAddress]::Loopback, 0)
    try {
        $listener.Start()
        return ([System.Net.IPEndPoint]$listener.LocalEndpoint).Port
    } finally { $listener.Stop() }
}

function Start-PrivateProxy([string]$Program, [string]$File, [int]$Port,
                            [string]$Fingerprint) {
    $info = [System.Diagnostics.ProcessStartInfo]::new()
    $info.FileName = $Program
    $info.UseShellExecute = $false
    $info.CreateNoWindow = $true
    $info.RedirectStandardOutput = $true
    $info.RedirectStandardError = $true
    foreach ($argument in @('-f', $File, '--no-tun', '--vless-only',
                             '--proxy-test-port', "$Port")) {
        $info.ArgumentList.Add($argument)
    }
    if ($Fingerprint) {
        $info.ArgumentList.Add('--proxy-test-client-fingerprint')
        $info.ArgumentList.Add($Fingerprint)
    }
    foreach ($key in @('CLASH_CONFIG_STRING','CLASH_CONFIG_FILE','CLASH_HOME_DIR',
                       'CLASH_OVERRIDE_EXTERNAL_CONTROLLER','CLASH_OVERRIDE_SECRET')) {
        $null = $info.Environment.Remove($key)
    }
    $process = [System.Diagnostics.Process]::new()
    $process.StartInfo = $info
    $null = $process.Start()
    return $process
}

function Get-PrivateDiagnosticCategory([string]$Text) {
    $Text = (($Text -split "`r?`n") |
        Where-Object { $_ -match 'local connection ended' }) -join "`n"
    $categories = [System.Collections.Generic.List[string]]::new()
    $patterns = [ordered]@{
        'POLICY_REJECTED' = 'connection rejected|UDP rejected'
        'OUTBOUND_UNAVAILABLE' = 'protocol is unavailable|proxy not found'
        'DNS_RESOLUTION' = 'resolve|lookup|no destination address'
        'TCP_CONNECT' = 'connection attempt|connect.*failed|refused|timed out'
        'TLS_CERTIFICATE' = 'certificate|CERTIFICATE_VERIFY_FAILED'
        'TLS_HANDSHAKE' = 'TLS|SSL|handshake|cipher|alert'
        'VLESS_PROTOCOL' = 'VLESS|UUID|Vision|REALITY|WebSocket|gRPC'
        'LOCAL_AUTH' = 'authentication'
    }
    foreach ($entry in $patterns.GetEnumerator()) {
        if ($Text -match $entry.Value) { $categories.Add($entry.Key) }
    }
    if ($categories.Count -eq 0) { return 'UNCLASSIFIED' }
    return ($categories -join ',')
}

function Get-PrivateDiagnosticSummary([string]$Text) {
    $items = [System.Collections.Generic.List[string]]::new()
    foreach ($line in ($Text -split "`r?`n")) {
        if ($line -notmatch 'local connection ended') { continue }
        $reason = $line -replace '^.*local connection ended\s*', ''
        $reason = $reason -replace '(?i)(password|uuid|server|host|node|proxy)=(("[^"]*")|\S+)', '$1=<redacted>'
        $reason = $reason -replace '(?i)\b[0-9a-f]{8}-[0-9a-f-]{27,}\b', '<uuid>'
        $reason = $reason -replace '\b(?:\d{1,3}\.){3}\d{1,3}(?::\d+)?\b', '<ip>'
        $reason = $reason -replace '(?i)\b(?:[a-z0-9-]+\.)+[a-z]{2,}(?::\d+)?\b', '<host>'
        $reason = $reason -replace '(?i)[A-Z]:\\[^\s]+', '<path>'
        if (-not $items.Contains($reason)) { $items.Add($reason) }
        if ($items.Count -ge 4) { break }
    }
    return $items
}

function Wait-LocalPort([System.Diagnostics.Process]$Process, [int]$Port,
                        [int]$DeadlineSeconds) {
    $deadline = [DateTime]::UtcNow.AddSeconds($DeadlineSeconds)
    while ([DateTime]::UtcNow -lt $deadline) {
        if ($Process.HasExited) { return $false }
        $client = [System.Net.Sockets.TcpClient]::new()
        try {
            $attempt = $client.ConnectAsync('127.0.0.1', $Port)
            if ($attempt.Wait(250) -and $client.Connected) { return $true }
        } catch {
            # Listener is still starting.
        } finally { $client.Dispose() }
        Start-Sleep -Milliseconds 100
    }
    return $false
}

try {
    $file = (Resolve-Path -LiteralPath $ConfigPath).Path
    $binary = (Resolve-Path -LiteralPath $Executable).Path
    $validation = Invoke-Captured $binary @('-f', $file, '-t') 30
    if ($validation.Code -ne 0) {
        Write-Output 'CONFIG FAIL: configuration rejected or validation timed out; raw diagnostics withheld.'
        exit 1
    }
    Write-Output 'CONFIG PASS'
    if ($TestResources) {
        $resources = Invoke-Captured $binary @('-f', $file, '--test-resources') 60
        if ($resources.Code -ne 0) {
            Write-Output 'RESOURCES FAIL: rule resources rejected or timed out; raw diagnostics withheld.'
            exit 1
        }
        Write-Output 'RESOURCES PASS'
    }
    if ($StartProxy) {
        if ($HttpProxyPort -ne 0 -or $SocksProxyPort -ne 0) {
            throw 'Do not combine -StartProxy with explicit proxy ports'
        }
        $mixedPort = Get-FreeTcpPort
        $ownedProcess = Start-PrivateProxy $binary $file $mixedPort $ProxyTestClientFingerprint
        if (-not (Wait-LocalPort $ownedProcess $mixedPort 15)) {
            Write-Output 'PROXY START FAIL: listener did not become ready; raw diagnostics withheld.'
            exit 1
        }
        $HttpProxyPort = $mixedPort
        $SocksProxyPort = $mixedPort
        Write-Output 'PROXY START PASS (no-tun, vless-only)'
    }
    if ($HttpProxyPort -eq 0 -and $SocksProxyPort -eq 0) {
        Write-Output 'NETWORK NOT TESTED: supply ports of an already-running proxy to test requests.'
        exit 0
    }
    if ($HttpUrl.Scheme -ne 'http' -or $HttpsUrl.Scheme -ne 'https' -or
        $HttpUrl.UserInfo -or $HttpsUrl.UserInfo) { throw 'Invalid test URLs' }
    $curl = (Get-Command curl.exe -ErrorAction Stop).Source
    $checks = @()
    if ($HttpProxyPort) { $checks += @{ Name = 'HTTP'; Proxy = "http://127.0.0.1:$HttpProxyPort" } }
    if ($SocksProxyPort) { $checks += @{ Name = 'SOCKS5'; Proxy = "socks5h://127.0.0.1:$SocksProxyPort" } }
    $failed = $false
    foreach ($check in $checks) {
        foreach ($destination in @(@{Name='HTTP'; Url=$HttpUrl}, @{Name='HTTPS'; Url=$HttpsUrl})) {
            $arguments = @('--disable', '--silent', '--show-error', '--fail', '--noproxy', '',
                '--proxy', $check.Proxy, '--connect-timeout', "$TimeoutSeconds",
                '--max-time', "$TimeoutSeconds", '--output', 'NUL',
                '--write-out', '%{http_code} %{time_total} %{ssl_verify_result}',
                '--url', $destination.Url.AbsoluteUri)
            $result = Invoke-Captured $curl $arguments ($TimeoutSeconds + 5)
            $status = '000'; $elapsed = '-'; $tls = '-'
            if ($result.Output.Trim() -match '^(\d{3}) ([0-9.]+) (\d+)$') {
                $status = $Matches[1]; $elapsed = $Matches[2]; $tls = $Matches[3]
            }
            $passed = $result.Code -eq 0 -and [int]$status -ge 200 -and [int]$status -lt 400
            if ($destination.Name -eq 'HTTPS') { $passed = $passed -and $tls -eq '0' }
            if (-not $passed) { $failed = $true; $networkFailed = $true }
            $label = if ($passed) { 'PASS' } else { 'FAIL' }
            Write-Output "$($check.Name) -> $($destination.Name): $label; status=$status; seconds=$elapsed; curl_exit=$($result.Code)"
        }
    }
    if ($StartProxy -and -not $failed) {
        Write-Output 'SCOPE: isolated no-TUN VLESS process and remote node connectivity verified.'
    } elseif (-not $StartProxy) {
        Write-Output 'SCOPE: running listener connectivity only; config/process identity and remote node selection are not verified.'
    }
    if ($failed) { exit 1 }
    exit 0
} catch {
    Write-Output 'SETUP FAIL: check local file paths, executable, curl.exe and URL arguments; raw diagnostics withheld.'
    exit 2
} finally {
    if ($null -ne $ownedProcess) {
        try {
            if (-not $ownedProcess.HasExited) {
                $ownedProcess.Kill($true)
                $ownedProcess.WaitForExit(5000) | Out-Null
            }
            $privateDiagnostics = $ownedProcess.StandardOutput.ReadToEnd() + "`n" +
                                  $ownedProcess.StandardError.ReadToEnd()
            if ($networkFailed) {
                $category = Get-PrivateDiagnosticCategory $privateDiagnostics
                Write-Output "PRIVATE DIAGNOSTIC CATEGORY: $category"
                $profiles = [System.Collections.Generic.HashSet[string]]::new()
                foreach ($profileLine in ($privateDiagnostics -split "`r?`n" |
                    Where-Object { $_ -match 'using BoringSSL TLS profile' })) {
                    if ($profileLine -match 'tls_profile=([^ ]+).*browser_version=([^ ]+)') {
                        $null = $profiles.Add("$($Matches[1]) $($Matches[2])")
                    }
                }
                foreach ($profileName in $profiles) {
                    Write-Output "TLS PROFILE: $profileName"
                }
                $transportLine = ($privateDiagnostics -split "`r?`n" |
                    Where-Object { $_ -match 'connecting VLESS transport' } |
                    Select-Object -First 1)
                if ($transportLine -match 'transport=([^ ]+) flow=([^ ]*) tls=([^ ]+) reality=([^ ]+) skip_cert_verify=([^ ]+)') {
                    Write-Output "VLESS TRANSPORT: network=$($Matches[1]) flow=$($Matches[2]) tls=$($Matches[3]) reality=$($Matches[4]) skip_cert_verify=$($Matches[5])"
                }
                foreach ($summary in (Get-PrivateDiagnosticSummary $privateDiagnostics)) {
                    Write-Output "PRIVATE DIAGNOSTIC: $summary"
                }
            }
        } finally { $ownedProcess.Dispose() }
    }
}
