$key = [Microsoft.Win32.Registry]::CurrentUser.OpenSubKey('Software\Microsoft\Windows\CurrentVersion\Internet Settings', $false)
try {
    $result = @{}
    foreach ($name in @('ProxyEnable', 'ProxyServer', 'ProxyOverride', 'AutoConfigURL')) {
        if ($key.GetValueNames() -contains $name) {
            $result[$name] = @{kind = $key.GetValueKind($name).ToString(); value = $key.GetValue($name)}
        } else { $result[$name] = $null }
    }
    $result['ConnectionFlags'] = @{kind = 'DWord'; value = [ClyntisWinInet]::Flags()}
    $result | ConvertTo-Json -Depth 4 -Compress
} finally { $key.Dispose() }
