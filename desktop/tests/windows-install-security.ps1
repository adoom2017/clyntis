$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot '../packaging/windows/install-security.ps1') -Action Verify

$script:Checks = 0
$unicodeName = -join @([char]0x81EA, [char]0x5B9A, [char]0x4E49, ' ', [char]0x5B89, [char]0x88C5)
function Expect-Rejected([scriptblock]$Check, [string]$Message) {
    $rejected = $false
    try { & $Check } catch { $rejected = $true }
    if (-not $rejected) { throw "Expected rejection: $Message" }
    $script:Checks++
}
function New-TestAcl([string]$Sddl) {
    $acl = [Security.AccessControl.DirectorySecurity]::new()
    $acl.SetSecurityDescriptorSddlForm($Sddl)
    return $acl
}

# Program Files is no longer a requirement, and localized account names are not used.
$protected = New-TestAcl $script:ProgramSddl
Assert-SecureAcl $protected "D:\$unicodeName\Clyntis" $script:MutationRights
$script:Checks++
Assert-SecureAcl (New-TestAcl $script:PrivateSddl) 'D:\Clyntis\service-data' $script:MutationRights
$script:Checks++

# Explicit grants must be checked even when inheritance has been disabled.
foreach ($sddl in @(
    'O:BAG:BAD:P(A;;FA;;;BA)(A;;FW;;;AU)',
    'O:BAG:BAD:P(A;;FA;;;BA)(A;;WD;;;BU)',
    'O:BAG:BAD:P(A;;FA;;;BA)(A;;0x40;;;BU)',
    'O:BAG:BAD:P(A;;FA;;;BA)(A;;WO;;;BU)',
    'O:BAG:BAD:P(A;;FA;;;BA)(A;;GA;;;WD)',
    'O:S-1-5-21-1-2-3-1001G:BAD:P(A;;FA;;;BA)',
    'O:BAG:BAD:NO_ACCESS_CONTROL'
)) {
    $acl = New-TestAcl $sddl
    Expect-Rejected { Assert-SecureAcl $acl 'unsafe' $script:MutationRights } $sddl
}

# Drive roots normally allow users to create directories. These grants do not permit
# replacing an administrator-owned protected leaf, but delete-child and ACL changes do.
$volume = New-TestAcl 'O:SYG:SYD:(A;;0x1301bf;;;AU)(A;;FA;;;SY)(A;;FA;;;BA)'
Assert-SecureAcl $volume 'D:\' $script:VolumeRootRights
$script:Checks++
Expect-Rejected { Assert-SecureAcl $volume 'D:\Shared' $script:AncestorRights } 'writable ancestor'
Expect-Rejected {
    Assert-SecureAcl (New-TestAcl 'O:SYG:SYD:(A;;0x40;;;AU)(A;;FA;;;SY)') 'D:\' $script:VolumeRootRights
} 'delete-child on volume root'

foreach ($path in @('D:\', 'relative\Clyntis', '\\server\share\Clyntis')) {
    Expect-Rejected { Get-InstallPath $path } "unsafe path $path"
}

$directory = Join-Path ([IO.Path]::GetTempPath()) ('clyntis-security-' + [guid]::NewGuid().ToString('N'))
$null = New-Item -ItemType Directory -Path $directory
try {
    $unicode = Join-Path $directory $unicodeName
    $null = New-Item -ItemType Directory -Path $unicode
    if ((Get-InstallPath $unicode) -ne $unicode) { throw 'Unicode/spaces path was changed.' }
    if ((Get-InstallPath $unicode.Replace('\', '/')) -ne $unicode) { throw 'Slash normalization failed.' }
    if ((Get-InstallPath ('\\?\' + $unicode)) -ne $unicode) { throw 'SCM extended path normalization failed.' }
    $script:Checks += 3
    Expect-Rejected { Get-InstallPath '\\?\UNC\server\share\Clyntis' } 'extended UNC path'
    Expect-Rejected { Get-InstallPath '\\?\GLOBALROOT\Device\HarddiskVolume1\Clyntis' } 'device namespace'
    Expect-Rejected { Assert-SecureParents $unicode } 'user-writable parent'

    # Exercise the actual native ACL setter without elevation. Keep the test's owner/group
    # so cleanup remains possible, but use the production DACL to remove an explicit grant.
    $file = Join-Path $directory 'dummy-program.exe'
    [IO.File]::WriteAllText($file, 'test fixture')
    $originalAcl = Get-Acl -LiteralPath $file
    $writableAcl = Get-Acl -LiteralPath $file
    $everyone = [Security.Principal.SecurityIdentifier]::new('S-1-1-0')
    $writableAcl.AddAccessRule([Security.AccessControl.FileSystemAccessRule]::new(
        $everyone, [Security.AccessControl.FileSystemRights]::Write,
        [Security.AccessControl.AccessControlType]::Allow
    ))
    Set-Acl -LiteralPath $file -AclObject $writableAcl
    $owner = $originalAcl.GetOwner([Security.Principal.SecurityIdentifier]).Value
    $group = $originalAcl.GetGroup([Security.Principal.SecurityIdentifier]).Value
    $productionSddl = $script:ProgramSddl
    try {
        $script:ProgramSddl = $productionSddl.Replace('O:BAG:BA', "O:${owner}G:${group}")
        Set-ProtectedAcl $file $false
        $hardened = Get-Acl -LiteralPath $file
        if (-not $hardened.AreAccessRulesProtected) { throw 'ACL inheritance was not disabled.' }
        foreach ($rule in $hardened.GetAccessRules($true, $true, [Security.Principal.SecurityIdentifier])) {
            if ($rule.IdentityReference.Value -eq 'S-1-1-0') { throw 'Explicit Everyone write access survived hardening.' }
        }
        $script:Checks += 2
    }
    finally {
        $script:ProgramSddl = $productionSddl
        $restore = [Security.AccessControl.FileSecurity]::new()
        $restore.SetSecurityDescriptorBinaryForm($originalAcl.GetSecurityDescriptorBinaryForm(), [Security.AccessControl.AccessControlSections]::Access)
        [IO.File]::SetAccessControl($file, $restore)
        [IO.File]::Delete($file)
    }

    $junction = Join-Path $directory 'junction'
    $null = New-Item -ItemType Junction -Path $junction -Target $unicode
    try { Expect-Rejected { Get-InstallPath (Join-Path $junction 'Clyntis') } 'junction ancestor' }
    finally { [IO.Directory]::Delete($junction) }
}
finally {
    # A test-created directory only; do not follow links during recursive cleanup.
    [IO.Directory]::Delete((Join-Path $directory $unicodeName))
    [IO.Directory]::Delete($directory)
}
Write-Output "Windows installation security: $script:Checks checks passed."
