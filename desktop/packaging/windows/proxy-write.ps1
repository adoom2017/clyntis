$target = [Console]::In.ReadToEnd() | ConvertFrom-Json
$key = [Microsoft.Win32.Registry]::CurrentUser.OpenSubKey('Software\Microsoft\Windows\CurrentVersion\Internet Settings', $true)
try {
    foreach ($name in @('ProxyEnable', 'ProxyServer', 'ProxyOverride', 'AutoConfigURL')) {
        $entry = $target.$name
        if ($null -eq $entry) { $key.DeleteValue($name, $false) }
        else {
            $kind = [System.Enum]::Parse([Microsoft.Win32.RegistryValueKind], [string]$entry.kind)
            $value = $entry.value
            if ($entry.kind -eq 'DWord') { $value = [int]$value }
            $key.SetValue($name, $value, $kind)
        }
    }
    [ClyntisWinInet]::Flags([int]$target.ConnectionFlags.value)
} finally { $key.Dispose() }
