param(
    [string]$InstallDirectory = $env:CLYNTIS_INSTALL_DIRECTORY,
    [ValidateSet('Prepare', 'Finalize', 'Verify', 'ProtectData')]
    [string]$Action = $env:CLYNTIS_INSTALL_SECURITY_ACTION
)

$ErrorActionPreference = 'Stop'
[Console]::OutputEncoding = [Text.UTF8Encoding]::new($false)
# Elevated processes can inherit a user-controlled module search path.
$env:PSModulePath = Join-Path $PSHOME 'Modules'
Import-Module (Join-Path $PSHOME 'Modules/Microsoft.PowerShell.Security') -Force
Import-Module (Join-Path $PSHOME 'Modules/Microsoft.PowerShell.Management') -Force

# One policy is embedded in the Windows service/desktop and NSIS installer.
# Never repair parent directories: they may belong to another application.
$script:TrustedOwners = @(
    'S-1-5-18',
    'S-1-5-32-544',
    'S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464'
)
$script:MutationRights = 0x500D0156L # generic write/all, delete, ACL/owner, file writes
$script:AncestorRights = 0x500D0156L
$script:VolumeRootRights = 0x100C0040L # ACL/owner, delete-child, generic all
$script:ProgramSddl = 'O:BAG:BAD:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;0x1200a9;;;BU)'
$script:PrivateSddl = 'O:BAG:BAD:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)'

function Assert-SecureAcl($Acl, [string]$Path, [long]$ForbiddenRights) {
    $owner = $Acl.GetOwner([Security.Principal.SecurityIdentifier]).Value
    if ($owner -notin $script:TrustedOwners) {
        throw "Directory or file is owned by an ordinary user: $Path. Choose an administrator-owned installation directory."
    }
    $raw = [Security.AccessControl.RawSecurityDescriptor]::new($Acl.GetSecurityDescriptorBinaryForm(), 0)
    if ($null -eq $raw.DiscretionaryAcl) { throw "Missing file permissions: $Path" }
    foreach ($ace in $raw.DiscretionaryAcl) {
        if ($ace.AceType -notin @([Security.AccessControl.AceType]::AccessAllowed, [Security.AccessControl.AceType]::AccessDenied)) {
            throw "Unsupported file permission rule: $Path"
        }
    }
    foreach ($rule in $Acl.GetAccessRules($true, $true, [Security.Principal.SecurityIdentifier])) {
        if ($rule.AccessControlType -ne [Security.AccessControl.AccessControlType]::Allow -or
            ($rule.PropagationFlags -band [Security.AccessControl.PropagationFlags]::InheritOnly)) { continue }
        $rights = [long]$rule.FileSystemRights -band 0xFFFFFFFFL
        if ($rule.IdentityReference.Value -notin $script:TrustedOwners -and ($rights -band $ForbiddenRights)) {
            throw "Ordinary users can modify or replace the installation path: $Path. Reinstall in a protected directory, for example D:\Clyntis."
        }
    }
}

function Get-InstallPath([string]$Directory) {
    # Rust canonicalize()/SCM can supply extended-length DOS paths. Strip only the
    # local-disk prefix; UNC and device namespaces still fail the local path check.
    if ($Directory -and $Directory.StartsWith('\\?\', [StringComparison]::Ordinal)) {
        $Directory = $Directory.Substring(4)
    }
    if ([string]::IsNullOrWhiteSpace($Directory) -or $Directory -notmatch '^[A-Za-z]:[\\/]') {
        throw 'Select an absolute directory on a local disk, for example D:\Clyntis.'
    }
    $full = [IO.Path]::GetFullPath($Directory.Replace('/', '\')).TrimEnd('\')
    $root = [IO.Path]::GetPathRoot($full)
    if ($full -eq $root.TrimEnd('\')) { throw 'The installation directory cannot be a disk root.' }
    $drive = [IO.DriveInfo]::new($root)
    if ($drive.DriveType -ne [IO.DriveType]::Fixed -or $drive.DriveFormat -notin @('NTFS', 'ReFS')) {
        throw 'The installation directory must be on a local NTFS or ReFS disk.'
    }
    # Check the original path before resolving anything; canonicalization would hide junctions.
    $candidate = $full
    while ($candidate) {
        if (Test-Path -LiteralPath $candidate) {
            $item = Get-Item -LiteralPath $candidate -Force
            if (-not $item.PSIsContainer -or ($item.Attributes -band [IO.FileAttributes]::ReparsePoint)) {
                throw "Installation paths cannot contain files, junctions or symbolic links: $candidate"
            }
        }
        $candidate = [IO.Path]::GetDirectoryName($candidate)
    }
    return $full
}

function Assert-SecureParents([string]$Directory) {
    $parent = [IO.Path]::GetDirectoryName($Directory)
    while ($parent) {
        if (Test-Path -LiteralPath $parent) {
            $mask = $script:AncestorRights
            if ($parent -eq [IO.Path]::GetPathRoot($parent)) { $mask = $script:VolumeRootRights }
            Assert-SecureAcl (Get-Acl -LiteralPath $parent) $parent $mask
        }
        $parent = [IO.Path]::GetDirectoryName($parent)
    }
}

function Set-ProtectedAcl([string]$Path, [bool]$Private) {
    $item = Get-Item -LiteralPath $Path -Force
    if ($item.Attributes -band [IO.FileAttributes]::ReparsePoint) {
        throw "Cannot change permissions on a junction or symbolic link: $Path"
    }
    if ($item.PSIsContainer) { $acl = [Security.AccessControl.DirectorySecurity]::new() }
    else { $acl = [Security.AccessControl.FileSecurity]::new() }
    $sddl = $script:ProgramSddl
    if ($Private) { $sddl = $script:PrivateSddl }
    # Replace the whole DACL, including explicit grants; /grant:r alone retains other users.
    $acl.SetSecurityDescriptorSddlForm($sddl)
    Set-Acl -LiteralPath $Path -AclObject $acl
}

function Set-ProtectedTree([string]$Directory, [bool]$Private) {
    Set-ProtectedAcl $Directory $Private
    foreach ($item in Get-ChildItem -LiteralPath $Directory -Force) {
        if ($item.PSIsContainer) { Set-ProtectedTree $item.FullName $Private }
        else { Set-ProtectedAcl $item.FullName $Private }
    }
}

function Assert-Installation([string]$Directory) {
    Assert-SecureParents $Directory
    Assert-SecureAcl (Get-Acl -LiteralPath $Directory) $Directory $script:MutationRights
    foreach ($name in @('clyntis-desktop.exe', 'clyntis-service.exe', 'clyntis-runner.exe', 'wintun.dll')) {
        $path = Join-Path $Directory $name
        $item = Get-Item -LiteralPath $path -Force
        if ($item.PSIsContainer -or ($item.Attributes -band [IO.FileAttributes]::ReparsePoint)) {
            throw "Untrusted program file: $path"
        }
        Assert-SecureAcl (Get-Acl -LiteralPath $path) $path $script:MutationRights
    }
}

# Dot-sourcing exposes policy functions to the Windows regression tests without changing files.
if ($MyInvocation.InvocationName -eq '.') { return }

try {
    $directory = Get-InstallPath $InstallDirectory
    switch ($Action) {
        'Prepare' {
            Assert-SecureParents $directory
            if (Test-Path -LiteralPath $directory) {
                if ((Get-ChildItem -LiteralPath $directory -Force | Select-Object -First 1) -and
                    -not (Test-Path -LiteralPath (Join-Path $directory 'clyntis-desktop.exe') -PathType Leaf)) {
                    throw 'Select an empty directory or an existing Clyntis installation directory.'
                }
                if ((Test-Path -LiteralPath (Join-Path $directory 'clyntis-service.exe')) -and
                    (Get-Service -Name 'org.clyntis.desktop.service' -ErrorAction SilentlyContinue)) {
                    # Do not promote untrusted old executables to trusted ones and then run them elevated.
                    Assert-Installation $directory
                }
            }
            else {
                $parent = [IO.Path]::GetDirectoryName($directory)
                if (-not (Test-Path -LiteralPath $parent -PathType Container)) {
                    throw 'The parent directory must already exist and be protected by administrator permissions.'
                }
                $acl = [Security.AccessControl.DirectorySecurity]::new()
                $acl.SetSecurityDescriptorSddlForm($script:ProgramSddl)
                # Windows PowerShell/.NET Framework creates with the final ACL atomically.
                $null = [IO.Directory]::CreateDirectory($directory, $acl)
            }
            Set-ProtectedAcl $directory $false
            foreach ($item in Get-ChildItem -LiteralPath $directory -Force) {
                if ($item.PSIsContainer) { Set-ProtectedTree $item.FullName ($item.Name -eq 'service-data') }
                else { Set-ProtectedAcl $item.FullName $false }
            }
        }
        'Finalize' {
            Assert-SecureParents $directory
            Set-ProtectedAcl $directory $false
            foreach ($item in Get-ChildItem -LiteralPath $directory -Force) {
                if ($item.PSIsContainer) { Set-ProtectedTree $item.FullName ($item.Name -eq 'service-data') }
                else { Set-ProtectedAcl $item.FullName $false }
            }
            Assert-Installation $directory
        }
        'Verify' { Assert-Installation $directory }
        'ProtectData' {
            Assert-Installation $directory
            Set-ProtectedTree (Join-Path $directory 'service-data') $true
        }
        default { throw 'Invalid installation security action.' }
    }
}
catch {
    [Console]::Error.WriteLine($_.Exception.Message)
    exit 1
}
