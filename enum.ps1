<#
.SYNOPSIS
    Windows local privilege-escalation enumeration.

.DESCRIPTION
    Enumerates the local Windows host for common privilege-escalation
    conditions: dangerous token privileges, weak service permissions,
    unquoted service paths, writable scheduled tasks, autoruns, stored
    credentials, missing hardening, and more.

    Intended for authorized security testing, CTFs, and lab use only.

.PARAMETER Full
    Enables slower/deeper checks:
      - ACL checks against every service (not just non-Microsoft ones)
      - recursive credential searches in common web/config roots
      - SYSVOL Group Policy Preferences (GPP) password search on domain hosts

.PARAMETER OutputPath
    Write all findings to a JSON file at this path.

.EXAMPLE
    .\enum.ps1

.EXAMPLE
    .\enum.ps1 -Full -OutputPath .\findings.json
#>
#Requires -Version 5.0
[CmdletBinding()]
param(
    [switch]$Full,
    [string]$OutputPath
)

$ErrorActionPreference = 'SilentlyContinue'
$ProgressPreference = 'SilentlyContinue'

$script:Findings = [System.Collections.Generic.List[object]]::new()
$script:IdentitySIDs = @()
$script:CurrentUserSID = $null
$script:CurrentUser = $null
$script:IsAdmin = $false
$script:StartTime = Get-Date
$script:TokenPrivileges = $null
$script:Services = $null

# ---------------------------------------------------------------------------
# Output helpers
# ---------------------------------------------------------------------------

function Show-Banner {
    Write-Host ""
    Write-Host "============================================================" -ForegroundColor Cyan
    Write-Host "   Windows Local Privilege Escalation Enumeration" -ForegroundColor Cyan
    Write-Host "============================================================" -ForegroundColor Cyan
    Write-Host ""
}

function Write-Header {
    param([string]$Title)
    Write-Host ""
    Write-Host ("[+] ==================== {0} ====================" -f $Title) -ForegroundColor Cyan
}

function Write-SectionInfo {
    param([string]$Message)
    Write-Host "[*] $Message"
}

function Add-Finding {
    param(
        [ValidateSet('High', 'Medium', 'Low', 'Info')]
        [string]$Severity,
        [string]$Title,
        [string]$Detail = '',
        [string]$Evidence = ''
    )

    $script:Findings.Add([pscustomobject]@{
        Severity = $Severity
        Title    = $Title
        Detail   = $Detail
        Evidence = $Evidence
    })

    $line = "[{0}] {1}" -f $Severity.ToUpper(), $Title
    if ($Detail) { $line = "$line - $Detail" }

    switch ($Severity) {
        'High'   { Write-Host $line -ForegroundColor Red }
        'Medium' { Write-Host $line -ForegroundColor Yellow }
        'Low'    { Write-Host $line -ForegroundColor DarkYellow }
        default  { Write-Host $line -ForegroundColor Green }
    }
    if ($Evidence) { Write-Host ("        {0}" -f $Evidence) -ForegroundColor DarkGray }
}

# ---------------------------------------------------------------------------
# Identity / token helpers (locale independent)
# ---------------------------------------------------------------------------

function Initialize-IdentityContext {
    try {
        $identity = [System.Security.Principal.WindowsIdentity]::GetCurrent()
        $script:CurrentUser = $identity.Name
        $script:CurrentUserSID = $identity.User.Value
        $script:IdentitySIDs = @($identity.User.Value) + @($identity.Groups | ForEach-Object { $_.Value })

        $principal = [System.Security.Principal.WindowsPrincipal]::new($identity)
        $script:IsAdmin = $principal.IsInRole([System.Security.Principal.WindowsBuiltInRole]::Administrator)
    }
    catch {
        $script:CurrentUser = [string]$env:USERNAME
        $script:IdentitySIDs = @()
    }
}

$script:TokenPrivilegeSource = @'
using System;
using System.Collections.Generic;
using System.Runtime.InteropServices;
using System.Text;

public static class WinPrivToken
{
    [StructLayout(LayoutKind.Sequential)]
    private struct LUID { public uint LowPart; public int HighPart; }

    [StructLayout(LayoutKind.Sequential)]
    private struct LUID_AND_ATTRIBUTES { public LUID Luid; public uint Attributes; }

    [DllImport("advapi32.dll", SetLastError = true)]
    private static extern bool OpenProcessToken(IntPtr ProcessHandle, uint DesiredAccess, out IntPtr TokenHandle);

    [DllImport("advapi32.dll", SetLastError = true)]
    private static extern bool GetTokenInformation(IntPtr TokenHandle, int TokenInformationClass, IntPtr TokenInformation, int TokenInformationLength, out int ReturnLength);

    [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    private static extern bool LookupPrivilegeName(string lpSystemName, ref LUID lpLuid, StringBuilder lpName, ref int cchName);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern IntPtr GetCurrentProcess();

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool CloseHandle(IntPtr hObject);

    public static string[] Get()
    {
        IntPtr token = IntPtr.Zero;
        List<string> result = new List<string>();
        try
        {
            if (!OpenProcessToken(GetCurrentProcess(), 0x0008, out token)) { return result.ToArray(); }

            int length = 0;
            GetTokenInformation(token, 3, IntPtr.Zero, 0, out length);
            if (length <= 0) { return result.ToArray(); }

            IntPtr buffer = Marshal.AllocHGlobal(length);
            try
            {
                if (!GetTokenInformation(token, 3, buffer, length, out length)) { return result.ToArray(); }

                int count = Marshal.ReadInt32(buffer);
                int size = Marshal.SizeOf(typeof(LUID_AND_ATTRIBUTES));
                long address = buffer.ToInt64() + 4;

                for (int i = 0; i < count; i++)
                {
                    LUID_AND_ATTRIBUTES entry = (LUID_AND_ATTRIBUTES)Marshal.PtrToStructure(
                        new IntPtr(address + (i * size)), typeof(LUID_AND_ATTRIBUTES));

                    StringBuilder name = new StringBuilder(256);
                    int nameLength = name.Capacity;

                    if (LookupPrivilegeName(null, ref entry.Luid, name, ref nameLength))
                    {
                        bool enabled = (entry.Attributes & 0x00000002) != 0;
                        result.Add(name.ToString() + (enabled ? "|Enabled" : "|Disabled"));
                    }
                }
            }
            finally { Marshal.FreeHGlobal(buffer); }
        }
        finally
        {
            if (token != IntPtr.Zero) { CloseHandle(token); }
        }
        return result.ToArray();
    }
}
'@

function Get-TokenPrivilegeList {
    if ($null -ne $script:TokenPrivileges) { return $script:TokenPrivileges }

    if (-not ('WinPrivToken' -as [type])) {
        try { Add-Type -TypeDefinition $script:TokenPrivilegeSource -Language CSharp -ErrorAction Stop }
        catch { return @() }
    }

    $result = @()
    try {
        $result = @([WinPrivToken]::Get() | ForEach-Object {
            $parts = $_ -split '\|', 2
            [pscustomobject]@{
                Name    = $parts[0]
                Enabled = ($parts[1] -eq 'Enabled')
            }
        })
    }
    catch {
        $result = @()
    }

    # Fall back to whoami when Add-Type is blocked (e.g. ConstrainedLanguage)
    # or the native token call is unavailable.
    if ($result.Count -eq 0 -and (Get-Command whoami.exe -ErrorAction SilentlyContinue)) {
        $result = @(& whoami.exe /priv 2>$null | ForEach-Object {
            if ($_ -match '^\s*(Se\w+Privilege)\s+.*?\s+(Enabled|Disabled)\s*$') {
                [pscustomobject]@{
                    Name    = $matches[1]
                    Enabled = ($matches[2] -eq 'Enabled')
                }
            }
        })
    }

    $script:TokenPrivileges = $result
    return $result
}

# ---------------------------------------------------------------------------
# CIM / WMI compatibility
# ---------------------------------------------------------------------------

function Get-CimSafe {
    param(
        [string]$Class,
        [string]$Namespace = 'root/cimv2',
        [string]$Filter = ''
    )

    try {
        $hasCim = Get-Command Get-CimInstance -ErrorAction SilentlyContinue
        if ($hasCim) {
            if ($Filter) {
                return Get-CimInstance -ClassName $Class -Namespace $Namespace -Filter $Filter -ErrorAction Stop
            }
            return Get-CimInstance -ClassName $Class -Namespace $Namespace -ErrorAction Stop
        }

        if ($Filter) {
            return Get-WmiObject -Class $Class -Namespace $Namespace -Filter $Filter -ErrorAction Stop
        }
        return Get-WmiObject -Class $Class -Namespace $Namespace -ErrorAction Stop
    }
    catch {
        return @()
    }
}

function Get-ServiceList {
    if ($null -eq $script:Services) {
        $script:Services = @(Get-CimSafe -Class Win32_Service)
    }
    return $script:Services
}

# ---------------------------------------------------------------------------
# Access-control helpers
# ---------------------------------------------------------------------------

function Test-IdentityMatch {
    param($IdentityReference)

    try {
        $sid = $IdentityReference.Translate([System.Security.Principal.SecurityIdentifier]).Value
    }
    catch {
        return $false
    }

    # Everyone, Authenticated Users, Users, INTERACTIVE, Console Logon
    $broad = @('S-1-1-0', 'S-1-5-11', 'S-1-5-32-545', 'S-1-5-4', 'S-1-2-1')
    if ($broad -contains $sid) { return $true }

    return ($script:IdentitySIDs -contains $sid)
}

function Test-WritablePath {
    param([string]$Path)

    $result = [pscustomobject]@{
        Path     = $Path
        Writable = $false
        Evidence = ''
    }

    if ([string]::IsNullOrWhiteSpace($Path)) { return $result }

    $clean = $Path.Trim().Trim('"')
    if (-not (Test-Path -LiteralPath $clean)) { return $result }

    $acl = Get-Acl -LiteralPath $clean -ErrorAction SilentlyContinue
    if (-not $acl) { return $result }

    foreach ($rule in $acl.Access) {
        if ($rule.AccessControlType -ne 'Allow') { continue }
        if (-not (Test-IdentityMatch $rule.IdentityReference)) { continue }

        $rights = [string]$rule.FileSystemRights
        if ($rights -match 'Write|Modify|FullControl|CreateFiles|AppendData|TakeOwnership|ChangePermissions|Delete') {
            $result.Writable = $true
            $result.Evidence = '{0} : {1}' -f $rule.IdentityReference, $rights
            break
        }
    }

    return $result
}

function Test-WritableRegistryPath {
    param([string]$Path)

    $result = [pscustomobject]@{
        Path     = $Path
        Writable = $false
        Evidence = ''
    }

    if ([string]::IsNullOrWhiteSpace($Path)) { return $result }
    if (-not (Test-Path -LiteralPath $Path)) { return $result }

    $acl = Get-Acl -LiteralPath $Path -ErrorAction SilentlyContinue
    if (-not $acl) { return $result }

    foreach ($rule in $acl.Access) {
        if ($rule.AccessControlType -ne 'Allow') { continue }
        if (-not (Test-IdentityMatch $rule.IdentityReference)) { continue }

        $rights = [string]$rule.RegistryRights
        if ($rights -match 'WriteKey|SetValue|CreateSubKey|FullControl|TakeOwnership|ChangePermissions|Delete') {
            $result.Writable = $true
            $result.Evidence = '{0} : {1}' -f $rule.IdentityReference, $rights
            break
        }
    }

    return $result
}

# ---------------------------------------------------------------------------
# Path / service parsing helpers
# ---------------------------------------------------------------------------

function Resolve-ExecutablePath {
    param([string]$Path)

    if ([string]::IsNullOrWhiteSpace($Path)) { return $null }

    $clean = $Path.Trim().Trim('"')
    $clean = [Environment]::ExpandEnvironmentVariables($clean)
    if ($clean -match '^\\\?\?\\') { $clean = $clean.Substring(4) }
    if ($env:windir -and $clean -match '(?i)^\\SystemRoot\\') {
        $clean = Join-Path $env:windir ($clean.Substring(12))
    }

    if (Test-Path -LiteralPath $clean -PathType Leaf) {
        $resolved = Resolve-Path -LiteralPath $clean -ErrorAction SilentlyContinue
        if ($resolved) { return $resolved.ProviderPath }
    }

    if ($clean -notmatch '[\\/]') {
        $cmd = Get-Command $clean -ErrorAction SilentlyContinue | Select-Object -First 1
        if ($cmd -and $cmd.Source) { return $cmd.Source }
    }

    return $clean
}

function Get-FirstCommandPath {
    param([string]$CommandLine)

    if ([string]::IsNullOrWhiteSpace($CommandLine)) { return $null }

    $command = $CommandLine.Trim()
    if ($command.StartsWith('"')) {
        $end = $command.IndexOf('"', 1)
        if ($end -gt 1) { $command = $command.Substring(1, $end - 1) }
    }
    else {
        $index = $command.ToLowerInvariant().IndexOf('.exe')
        if ($index -ge 0) {
            $command = $command.Substring(0, $index + 4)
        }
        else {
            $command = ($command -split '\s+')[0]
        }
    }

    return Resolve-ExecutablePath $command
}

function Get-ServiceBinaryPath {
    param([string]$PathName)

    if ([string]::IsNullOrWhiteSpace($PathName)) { return $null }

    $path = $PathName.Trim()

    if ($path.StartsWith('"')) {
        $end = $path.IndexOf('"', 1)
        if ($end -gt 1) { return $path.Substring(1, $end - 1) }
    }

    if ($path -match '^\\\?\?\\') { $path = $path.Substring(4) }

    $index = $path.ToLowerInvariant().IndexOf('.exe')
    if ($index -ge 0) { return $path.Substring(0, $index + 4) }

    return ($path -split '\s+')[0]
}

function Get-UnquotedServicePathCandidates {
    param([string]$PathName)

    $candidates = [System.Collections.Generic.List[string]]::new()

    if ([string]::IsNullOrWhiteSpace($PathName)) { return $candidates }
    if ($PathName.Trim().StartsWith('"')) { return $candidates }
    if ($PathName -notmatch '\s') { return $candidates }

    $tokens = @($PathName.Trim() -split '\s+')
    $prefix = ''

    for ($i = 0; $i -lt $tokens.Count; $i++) {
        if ($i -eq 0) { $prefix = $tokens[$i] }
        else { $prefix = $prefix + ' ' + $tokens[$i] }

        if ($prefix -match '\.exe$') { break }
        $candidates.Add($prefix + '.exe')
    }

    return $candidates
}

function Test-ServiceDaclWeak {
    param([string]$Name)

    $raw = (& sc.exe sdshow $Name 2>$null) -join ''
    if ([string]::IsNullOrWhiteSpace($raw)) { return @() }

    $weak = [System.Collections.Generic.List[string]]::new()
    $pattern = '\(A;[^;]*;([^;]*);[^;]*;[^;]*;([^;)]+)\)'

    foreach ($ace in [regex]::Matches($raw, $pattern)) {
        $rights = $ace.Groups[1].Value
        $trustee = $ace.Groups[2].Value

        if ($trustee -in @('WD', 'AU', 'BU', 'IU', 'S-1-1-0', 'S-1-5-11', 'S-1-5-32-545')) {
            # DC = SERVICE_CHANGE_CONFIG, GW/GA = generic write/all, WD/WO = DACL/owner write
            if ($rights -match 'DC|GW|GA|WD|WO|FA') {
                $weak.Add(('{0}:{1}' -f $trustee, $rights))
            }
        }
    }

    return $weak
}

# ===========================================================================
# Enumeration modules
# ===========================================================================

function Get-InstalledHotfixes {
    $fixes = @(Get-CimSafe -Class Win32_QuickFixEngineering)
    if ($fixes.Count -gt 0) {
        return $fixes | Sort-Object InstalledOn -Descending
    }

    if (Get-Command Get-HotFix -ErrorAction SilentlyContinue) {
        return Get-HotFix -ErrorAction SilentlyContinue | Sort-Object InstalledOn -Descending
    }

    return @()
}

function Get-SystemInfo {
    Write-Header 'System Information'

    $os = Get-CimSafe -Class Win32_OperatingSystem | Select-Object -First 1
    $cs = Get-CimSafe -Class Win32_ComputerSystem | Select-Object -First 1

    Write-SectionInfo "Hostname: $env:COMPUTERNAME"
    Write-SectionInfo "User/Domain: $env:USERDOMAIN\$env:USERNAME"
    Write-SectionInfo "Architecture: $env:PROCESSOR_ARCHITECTURE"
    Write-SectionInfo "PowerShell: $($PSVersionTable.PSVersion) ($($PSVersionTable.PSEdition))"

    if ($os) {
        Write-SectionInfo "OS: $($os.Caption) $($os.Version) (Build $($os.BuildNumber))"
        Write-SectionInfo "Install date: $($os.InstallDate)"
        Write-SectionInfo "Last boot: $($os.LastBootUpTime)"
    }
    if ($cs) {
        Write-SectionInfo "Manufacturer/Model: $($cs.Manufacturer) / $($cs.Model)"
    }

    Write-SectionInfo 'Installed hotfixes (most recent 15):'
    Get-InstalledHotfixes |
        Select-Object -First 15 HotFixID, Description, InstalledOn |
        Format-Table -AutoSize

    if ($os -and $os.BuildNumber) {
        $build = [int]$os.BuildNumber
        if ($build -lt 7601) {
            Add-Finding -Severity High -Title 'Unsupported Windows version' -Detail "Build $build has no security support."
        }
        elseif ($build -lt 10240) {
            Add-Finding -Severity High -Title 'Unsupported Windows version' -Detail "Build $build is out of support."
        }
        elseif ($build -lt 17763) {
            Add-Finding -Severity Medium -Title 'Old Windows build' -Detail "Build $build is likely out of support."
        }
    }
}

function Get-UserInfo {
    Write-Header 'User Context'

    Write-SectionInfo "Current user: $script:CurrentUser (SID $script:CurrentUserSID)"
    Write-SectionInfo "Elevated token: $script:IsAdmin"

    $identity = $null
    try { $identity = [System.Security.Principal.WindowsIdentity]::GetCurrent() } catch { $identity = $null }

    $rawGroups = ''
    if (Get-Command whoami.exe -ErrorAction SilentlyContinue) {
        $rawGroups = (& whoami.exe /groups 2>$null) -join "`n"
    }

    if ($rawGroups -match '(S-1-16-\d+)') {
        $integrity = $matches[1]
        $level = switch ($integrity) {
            'S-1-16-4096'  { 'Medium' }
            'S-1-16-8192'  { 'High' }
            'S-1-16-12288' { 'System' }
            'S-1-16-16384' { 'Protected Process' }
            default        { $integrity }
        }
        Write-SectionInfo "Integrity level: $level ($integrity)"
    }

    Write-SectionInfo 'Token privileges:'
    $privileges = Get-TokenPrivilegeList
    $privileges | Format-Table Name, Enabled -AutoSize

    $dangerousPrivileges = [ordered]@{
        'SeImpersonatePrivilege'          = 'Token impersonation (Potato-family attacks)'
        'SeAssignPrimaryTokenPrivilege'   = 'Token assignment (Potato-family attacks)'
        'SeTcbPrivilege'                  = 'Act as part of the operating system'
        'SeBackupPrivilege'               = 'Backup files (copy SAM/SYSTEM/SECURITY)'
        'SeRestorePrivilege'              = 'Restore files (overwrite protected files)'
        'SeCreateTokenPrivilege'          = 'Create arbitrary tokens'
        'SeLoadDriverPrivilege'           = 'Load kernel drivers'
        'SeTakeOwnershipPrivilege'        = 'Take ownership of any object'
        'SeDebugPrivilege'                = 'Debug processes (dump LSASS)'
        'SeRelabelPrivilege'              = 'Modify mandatory integrity labels'
        'SeManageVolumePrivilege'         = 'Manage volumes'
        'SeUndockPrivilege'               = 'Undock / lock workstation'
        'SeSyncAgentPrivilege'            = 'Synchronize directory service data'
        'SeEnableDelegationPrivilege'     = 'Enable computer/user delegation'
    }

    foreach ($name in $dangerousPrivileges.Keys) {
        $entry = $privileges | Where-Object { $_.Name -eq $name } | Select-Object -First 1
        if (-not $entry) { continue }

        if ($entry.Enabled) {
            Add-Finding -Severity High -Title "Dangerous privilege enabled: $name" -Detail $dangerousPrivileges[$name]
        }
        else {
            Add-Finding -Severity Low -Title "Dangerous privilege present (disabled): $name" -Detail $dangerousPrivileges[$name]
        }
    }

    Write-SectionInfo 'Group memberships:'
    if ($identity) {
        $identity.Groups | ForEach-Object {
            $sid = $_.Value
            $name = $sid
            try { $name = $_.Translate([System.Security.Principal.NTAccount]).Value } catch { $name = $sid }
            [pscustomobject]@{ Name = $name; SID = $sid }
        } | Sort-Object Name | Format-Table -AutoSize
    }

    $highPrivilegeGroups = @{
        'S-1-5-32-544' = 'Administrators'
        'S-1-5-32-548' = 'Account Operators'
        'S-1-5-32-549' = 'Server Operators'
        'S-1-5-32-550' = 'Print Operators'
        'S-1-5-32-551' = 'Backup Operators'
        'S-1-5-32-556' = 'Network Configuration Operators'
        'S-1-5-32-559' = 'Performance Log Users'
        'S-1-5-32-562' = 'Distributed COM Users'
        'S-1-5-32-569' = 'Cryptographic Operators'
        'S-1-5-32-578' = 'Hyper-V Administrators'
    }

    foreach ($group in @($identity.Groups)) {
        $sid = $group.Value

        if ($highPrivilegeGroups.ContainsKey($sid)) {
            $name = $highPrivilegeGroups[$sid]

            if ($sid -eq 'S-1-5-32-544') {
                if ($script:IsAdmin) {
                    Add-Finding -Severity Info -Title 'Member of Administrators (elevated)' -Detail $name
                }
                else {
                    Add-Finding -Severity Medium -Title 'Member of Administrators (filtered token)' -Detail 'UAC may allow elevation.'
                }
            }
            else {
                Add-Finding -Severity Medium -Title "High-privilege group: $name" -Detail "Member of $name"
            }
        }

        if ($sid -match '^S-1-5-21-\d+-\d+-\d+-(512|518|519|520)$') {
            Add-Finding -Severity High -Title 'Domain privileged group membership' -Detail "SID $sid (Domain/Enterprise/Schema Admins or GPO Creator Owners)"
        }
    }

    Write-SectionInfo 'Environment variables:'
    Get-ChildItem Env: | Sort-Object Name | Format-Table Name, Value -AutoSize

    Write-SectionInfo 'Local user accounts:'
    Get-CimSafe -Class Win32_UserAccount -Filter 'LocalAccount=True' |
        Select-Object Name, Disabled, Lockout, PasswordRequired |
        Format-Table -AutoSize

    Write-SectionInfo 'Local Administrators:'
    try {
        Get-LocalGroupMember -SID 'S-1-5-32-544' -ErrorAction Stop |
            Select-Object Name, ObjectClass, PrincipalSource |
            Format-Table -AutoSize
    }
    catch {
        net.exe localgroup administrators 2>$null
    }
}

function Get-NetworkInfo {
    Write-Header 'Network Information'

    Write-SectionInfo 'IP configuration:'
    ipconfig.exe /all 2>$null | Select-String 'IPv4 Address', 'Subnet Mask', 'Default Gateway', 'DNS Servers'

    Write-SectionInfo 'Routing table:'
    route.exe print 2>$null | Select-String '0.0.0.0'

    Write-SectionInfo 'Listening TCP ports:'
    $listeners = @()
    if (Get-Command Get-NetTCPConnection -ErrorAction SilentlyContinue) {
        $listeners = @(Get-NetTCPConnection -State Listen -ErrorAction SilentlyContinue)
    }

    if ($listeners.Count -gt 0) {
        $listeners | ForEach-Object {
            $process = Get-Process -Id $_.OwningProcess -ErrorAction SilentlyContinue
            [pscustomobject]@{
                LocalAddress = $_.LocalAddress
                LocalPort    = $_.LocalPort
                PID          = $_.OwningProcess
                Process      = $process.ProcessName
            }
        } | Sort-Object LocalPort | Format-Table -AutoSize
    }
    else {
        netstat.exe -ano 2>$null | Select-String 'LISTENING'
    }

    Write-SectionInfo 'Hosts file:'
    Get-Content "$env:windir\System32\drivers\etc\hosts" -ErrorAction SilentlyContinue

    Write-SectionInfo 'Network shares:'
    net.exe share 2>$null

    Write-SectionInfo 'Mapped drives and sessions:'
    net.exe use 2>$null
    net.exe session 2>$null
}

function Get-ServiceInfo {
    Write-Header 'Services, Drivers and Processes'

    $services = Get-ServiceList
    Write-SectionInfo "Total services: $($services.Count)"

    Write-SectionInfo 'Non-Microsoft services:'
    $services |
        Where-Object { $_.PathName -and $_.PathName -notmatch '(?i)\\Windows\\(System32|SysWOW64|WinSxS)' } |
        Select-Object Name, DisplayName, StartMode, State, StartName, PathName |
        Format-Table -AutoSize

    Write-SectionInfo 'Processes:'
    try {
        Get-Process -IncludeUserName -ErrorAction Stop |
            Sort-Object ProcessName |
            Select-Object Id, ProcessName, UserName, Path |
            Format-Table -AutoSize
    }
    catch {
        Get-Process |
            Sort-Object ProcessName |
            Select-Object Id, ProcessName, Path |
            Format-Table -AutoSize
    }

    Write-SectionInfo 'Non-Microsoft drivers:'
    $drivers = Get-CimSafe -Class Win32_SystemDriver
    $drivers | ForEach-Object {
        $driver = $_
        $path = Resolve-ExecutablePath $driver.PathName
        $company = ''
        if ($path -and (Test-Path -LiteralPath $path)) {
            $company = (Get-Item -LiteralPath $path -ErrorAction SilentlyContinue).VersionInfo.CompanyName
        }

        if ($company -notmatch 'Microsoft') {
            [pscustomobject]@{
                Name      = $driver.Name
                State     = $driver.State
                StartMode = $driver.StartMode
                Company   = $company
                Path      = $path
            }
        }
    } | Format-Table -AutoSize
}

function Get-ExploitableServices {
    Write-Header 'Service Exploitation Checks'

    $services = Get-ServiceList
    if (-not $services -or $services.Count -eq 0) {
        Write-SectionInfo 'Unable to enumerate services.'
        return
    }

    if ($Full) {
        $targets = @($services)
    }
    else {
        $targets = @($services | Where-Object {
            $_.PathName -and $_.PathName -notmatch '(?i)\\Windows\\(System32|SysWOW64|WinSxS)'
        })
    }

    foreach ($service in $targets) {
        $name = $service.Name
        $pathName = $service.PathName

        if ([string]::IsNullOrWhiteSpace($pathName)) { continue }

        # --- unquoted service path -----------------------------------------
        $candidates = Get-UnquotedServicePathCandidates $pathName
        if ($candidates.Count -gt 0) {
            $writableCandidates = [System.Collections.Generic.List[string]]::new()

            foreach ($candidate in $candidates) {
                $directory = Split-Path -Parent $candidate
                if ([string]::IsNullOrWhiteSpace($directory)) { continue }

                $access = Test-WritablePath $directory
                if ($access.Writable) {
                    $writableCandidates.Add(('{0} ({1})' -f $candidate, $access.Evidence))
                }
            }

            if ($writableCandidates.Count -gt 0) {
                Add-Finding -Severity High -Title "Unquoted service path with writable component: $name" `
                    -Detail $pathName -Evidence ($writableCandidates -join '; ')
            }
            else {
                Add-Finding -Severity Low -Title "Unquoted service path: $name" -Detail $pathName
            }
        }

        # --- writable binary / directory ------------------------------------
        $binary = Get-ServiceBinaryPath $pathName
        $resolvedBinary = Resolve-ExecutablePath $binary

        if ($resolvedBinary -and (Test-Path -LiteralPath $resolvedBinary -PathType Leaf)) {
            $access = Test-WritablePath $resolvedBinary
            if ($access.Writable) {
                Add-Finding -Severity High -Title "Writable service binary: $name" `
                    -Detail $resolvedBinary -Evidence $access.Evidence
            }

            $directory = Split-Path -Parent $resolvedBinary
            if ($directory) {
                $directoryAccess = Test-WritablePath $directory
                if ($directoryAccess.Writable) {
                    Add-Finding -Severity High -Title "Writable service directory: $name" `
                        -Detail $directory -Evidence $directoryAccess.Evidence
                }
            }
        }
        elseif ($resolvedBinary) {
            # Service points at a missing binary - planting it may yield SYSTEM.
            $directory = Split-Path -Parent $resolvedBinary
            if ($directory) {
                $directoryAccess = Test-WritablePath $directory
                if ($directoryAccess.Writable) {
                    Add-Finding -Severity High -Title "Missing service binary in writable directory: $name" `
                        -Detail $resolvedBinary -Evidence $directoryAccess.Evidence
                }
            }
        }

        # --- writable service registry key ----------------------------------
        $registryPath = "HKLM:\SYSTEM\CurrentControlSet\Services\$name"
        $registryAccess = Test-WritableRegistryPath $registryPath
        if ($registryAccess.Writable) {
            Add-Finding -Severity High -Title "Writable service registry key: $name" `
                -Detail $registryPath -Evidence $registryAccess.Evidence
        }

        # --- weak service DACL ----------------------------------------------
        $weakDacl = Test-ServiceDaclWeak $name
        if ($weakDacl.Count -gt 0) {
            Add-Finding -Severity High -Title "Weak service DACL: $name" `
                -Detail 'A non-admin principal can modify the service configuration.' `
                -Evidence ($weakDacl -join ', ')
        }
    }
}

function Get-ScheduledTasks {
    Write-Header 'Scheduled Tasks'

    $tasks = $null
    if (Get-Command Get-ScheduledTask -ErrorAction SilentlyContinue) {
        $tasks = Get-ScheduledTask -ErrorAction SilentlyContinue
    }

    if ($tasks) {
        $nonMicrosoft = @($tasks | Where-Object { $_.TaskPath -notlike '\Microsoft\*' })
        Write-SectionInfo "Non-Microsoft tasks: $($nonMicrosoft.Count)"

        $nonMicrosoft |
            Select-Object TaskName, TaskPath, State,
                @{ Name = 'RunAs'; Expression = { $_.Principal.UserId } },
                @{ Name = 'Action'; Expression = { ($_.Actions | ForEach-Object { $_.Execute }) -join '; ' } } |
            Format-Table -AutoSize -Wrap

        $checked = if ($Full) { @($tasks) } else { $nonMicrosoft }

        foreach ($task in $checked) {
            foreach ($action in @($task.Actions)) {
                if (-not ($action.PSObject.Properties.Name -contains 'Execute')) { continue }

                $execute = $action.Execute
                if ([string]::IsNullOrWhiteSpace($execute)) { continue }

                $resolved = Resolve-ExecutablePath $execute
                if (-not $resolved -or -not (Test-Path -LiteralPath $resolved -PathType Leaf)) { continue }

                $access = Test-WritablePath $resolved
                if ($access.Writable) {
                    Add-Finding -Severity High -Title "Writable scheduled-task binary: $($task.TaskName)" `
                        -Detail $resolved -Evidence $access.Evidence
                }

                $directory = Split-Path -Parent $resolved
                if ($directory) {
                    $directoryAccess = Test-WritablePath $directory
                    if ($directoryAccess.Writable) {
                        Add-Finding -Severity High -Title "Writable scheduled-task directory: $($task.TaskName)" `
                            -Detail $directory -Evidence $directoryAccess.Evidence
                    }
                }
            }

            # Task definition file
            $taskFile = "$env:windir\System32\Tasks$($task.TaskPath)$($task.TaskName)"
            $fileAccess = Test-WritablePath $taskFile
            if ($fileAccess.Writable) {
                Add-Finding -Severity High -Title "Writable task definition: $($task.TaskName)" `
                    -Detail $taskFile -Evidence $fileAccess.Evidence
            }
        }
    }
    else {
        Write-SectionInfo 'Get-ScheduledTask unavailable; falling back to schtasks.'
        schtasks.exe /query /fo LIST /v 2>$null |
            Select-String 'TaskName:', 'Task To Run:', 'Run As User:' |
            Select-String -NotMatch 'Microsoft'
    }

    $tasksDirectory = "$env:windir\System32\Tasks"
    $tasksAccess = Test-WritablePath $tasksDirectory
    if ($tasksAccess.Writable) {
        Add-Finding -Severity Medium -Title 'Writable Tasks directory' -Detail $tasksDirectory -Evidence $tasksAccess.Evidence
    }
}

function Get-RegistryChecks {
    Write-Header 'Registry Checks'

    # --- AlwaysInstallElevated ---------------------------------------------
    $hkcuInstaller = Get-ItemProperty 'HKCU:\SOFTWARE\Policies\Microsoft\Windows\Installer' -Name AlwaysInstallElevated -ErrorAction SilentlyContinue
    $hklmInstaller = Get-ItemProperty 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\Installer' -Name AlwaysInstallElevated -ErrorAction SilentlyContinue

    if ($hkcuInstaller.AlwaysInstallElevated -eq 1 -and $hklmInstaller.AlwaysInstallElevated -eq 1) {
        Add-Finding -Severity High -Title 'AlwaysInstallElevated enabled' -Detail 'Any user can install MSI packages with SYSTEM privileges.'
    }
    elseif ($hkcuInstaller.AlwaysInstallElevated -eq 1 -or $hklmInstaller.AlwaysInstallElevated -eq 1) {
        Add-Finding -Severity Low -Title 'AlwaysInstallElevated partially configured' `
            -Detail "HKCU=$($hkcuInstaller.AlwaysInstallElevated) HKLM=$($hklmInstaller.AlwaysInstallElevated)"
    }

    # --- AutoLogon / Winlogon ----------------------------------------------
    $winlogon = Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon' -ErrorAction SilentlyContinue

    if ($winlogon.DefaultPassword) {
        Add-Finding -Severity High -Title 'AutoLogon password stored in registry' -Detail "DefaultUserName=$($winlogon.DefaultUserName)"
    }
    if ($winlogon.AutoAdminLogon -eq 1) {
        Add-Finding -Severity Medium -Title 'AutoAdminLogon enabled'
    }
    if ($winlogon.Shell -and $winlogon.Shell -notmatch '(?i)explorer\.exe') {
        Add-Finding -Severity High -Title 'Non-default Winlogon Shell' -Detail $winlogon.Shell
    }
    if ($winlogon.Userinit -and $winlogon.Userinit -notmatch '(?i)userinit\.exe') {
        Add-Finding -Severity High -Title 'Non-default Winlogon Userinit' -Detail $winlogon.Userinit
    }

    # --- Autoruns -----------------------------------------------------------
    $runKeys = @(
        'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run',
        'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce',
        'HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Run',
        'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run',
        'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce',
        'HKCU:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Run'
    )

    foreach ($key in $runKeys) {
        if (-not (Test-Path $key)) { continue }

        if ($key -like 'HKLM:*') {
            $keyAccess = Test-WritableRegistryPath $key
            if ($keyAccess.Writable) {
                Add-Finding -Severity High -Title 'Writable machine-wide autorun registry key' -Detail $key -Evidence $keyAccess.Evidence
            }
        }

        $properties = Get-ItemProperty $key -ErrorAction SilentlyContinue
        foreach ($property in $properties.PSObject.Properties) {
            if ($property.Name -match '^PS') { continue }

            $command = [string]$property.Value
            Write-SectionInfo ("Autorun {0}\{1} = {2}" -f $key, $property.Name, $command)

            $executable = Get-FirstCommandPath $command
            if (-not $executable) { continue }

            $access = Test-WritablePath $executable
            if ($access.Writable) {
                Add-Finding -Severity High -Title 'Writable autorun binary' -Detail "$key\$($property.Name)" -Evidence $executable
            }

            if (Test-Path -LiteralPath $executable) {
                $directory = Split-Path -Parent $executable
                $directoryAccess = Test-WritablePath $directory
                if ($directoryAccess.Writable) {
                    Add-Finding -Severity High -Title 'Writable autorun directory' -Detail "$key\$($property.Name)" -Evidence $directory
                }
            }
        }
    }

    # --- Image File Execution Options / AppInit DLLs ------------------------
    $ifeo = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options'
    if (Test-Path $ifeo) {
        Get-ChildItem $ifeo -ErrorAction SilentlyContinue | ForEach-Object {
            $debugger = Get-ItemProperty $_.PSPath -Name Debugger -ErrorAction SilentlyContinue
            if ($debugger.Debugger) {
                Add-Finding -Severity High -Title "IFEO debugger configured: $($_.PSChildName)" `
                    -Detail $debugger.Debugger
            }
        }
    }

    $appInit = Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows' -ErrorAction SilentlyContinue
    if ($appInit.AppInit_DLLs) {
        Add-Finding -Severity High -Title 'AppInit_DLLs configured' -Detail $appInit.AppInit_DLLs
    }
    if ($appInit.LoadAppInit_DLLs -eq 1) {
        Add-Finding -Severity Medium -Title 'LoadAppInit_DLLs enabled'
    }

    # --- Stored remote-access credentials ----------------------------------
    $credentialKeys = @(
        'HKCU:\Software\SimonTatham\PuTTY\Sessions',
        'HKCU:\Software\ORL\WinVNC3',
        'HKCU:\Software\TightVNC\Server',
        'HKCU:\Software\RealVNC\WinVNC4'
    )
    foreach ($key in $credentialKeys) {
        if (Test-Path $key) {
            Add-Finding -Severity Medium -Title 'Stored remote-access credentials possible' -Detail $key
        }
    }

    # --- WDigest / LSA ------------------------------------------------------
    $wdigest = Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest' -Name UseLogonCredential -ErrorAction SilentlyContinue
    if ($wdigest.UseLogonCredential -eq 1) {
        Add-Finding -Severity High -Title 'WDigest cleartext credentials enabled' -Detail 'UseLogonCredential=1'
    }

    $lsa = Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' -ErrorAction SilentlyContinue
    if ($lsa.RunAsPPL -ne 1) {
        Add-Finding -Severity Low -Title 'LSA protection (RunAsPPL) not enabled'
    }
    if ($lsa.LimitBlankPasswordUse -eq 0) {
        Add-Finding -Severity Low -Title 'Blank passwords permitted for network logon'
    }

    # --- UAC -----------------------------------------------------------------
    $uac = Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' -ErrorAction SilentlyContinue

    Write-SectionInfo ("UAC: EnableLUA={0} ConsentPromptBehaviorAdmin={1} FilterAdministratorToken={2}" -f `
        $uac.EnableLUA, $uac.ConsentPromptBehaviorAdmin, $uac.FilterAdministratorToken)

    if ($uac.EnableLUA -eq 0) {
        Add-Finding -Severity High -Title 'UAC disabled' -Detail 'EnableLUA=0'
    }
    if ($uac.LocalAccountTokenFilterPolicy -eq 1) {
        Add-Finding -Severity Medium -Title 'LocalAccountTokenFilterPolicy enabled' -Detail 'Remote local-admin logons receive a full token.'
    }
    if ($uac.EnableLUA -eq 1 -and $uac.FilterAdministratorToken -ne 1) {
        Add-Finding -Severity Low -Title 'UAC does not filter the built-in Administrator token'
    }

    # --- LAPS ---------------------------------------------------------------
    if ((Test-Path 'HKLM:\SOFTWARE\Policies\Microsoft Services\AdmPwd') -or
        (Test-Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\LAPS')) {
        Add-Finding -Severity Info -Title 'LAPS configured' -Detail 'Local administrator password randomization is in use.'
    }
}

function Get-SensitiveFiles {
    Write-Header 'Sensitive Files and Credential Locations'

    $paths = @(
        'C:\unattend.xml',
        'C:\Windows\Panther\Unattend.xml',
        'C:\Windows\Panther\Unattend\Unattend.xml',
        'C:\Windows\System32\Sysprep\sysprep.xml',
        'C:\Windows\System32\Sysprep\sysprep.inf',
        'C:\Windows\System32\Sysprep\unattend.xml',
        'C:\Windows\System32\Sysprep\Panther\unattend.xml',
        "$env:APPDATA\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt",
        "$env:USERPROFILE\.ssh\id_rsa",
        "$env:USERPROFILE\.ssh\id_ed25519",
        "$env:USERPROFILE\.ssh\config",
        "$env:USERPROFILE\.aws\credentials",
        "$env:USERPROFILE\.azure\accessTokens.json",
        "$env:USERPROFILE\.config\gcloud\credentials.db",
        "$env:USERPROFILE\.kube\config",
        "$env:USERPROFILE\.docker\config.json",
        "$env:USERPROFILE\.git-credentials",
        "$env:USERPROFILE\_netrc",
        "$env:USERPROFILE\.npmrc",
        "$env:APPDATA\Microsoft\Credentials",
        "$env:LOCALAPPDATA\Microsoft\Vault",
        "$env:LOCALAPPDATA\Google\Chrome\User Data\Default\Login Data",
        "$env:LOCALAPPDATA\Microsoft\Edge\User Data\Default\Login Data",
        "$env:APPDATA\Mozilla\Firefox\Profiles",
        'C:\inetpub\wwwroot\web.config'
    )

    foreach ($path in $paths) {
        if (-not (Test-Path -LiteralPath $path)) { continue }

        $item = Get-Item -LiteralPath $path -ErrorAction SilentlyContinue
        $size = 0
        if ($item -and -not $item.PSIsContainer) { $size = $item.Length }

        Add-Finding -Severity Medium -Title 'Sensitive file present' -Detail $path -Evidence "Size: $size bytes"
    }

    Write-SectionInfo 'PowerShell transcripts:'
    $transcriptDirectories = @(
        "$env:USERPROFILE\Documents\PowerShell",
        "$env:USERPROFILE\Documents\WindowsPowerShell"
    )
    foreach ($directory in $transcriptDirectories) {
        Get-ChildItem -Path $directory -Recurse -Include '*.txt' -ErrorAction SilentlyContinue |
            Where-Object { $_.Name -like 'PowerShell_transcript*' } |
            Select-Object FullName, Length, LastWriteTime |
            Format-Table -AutoSize
    }

    Write-SectionInfo 'IIS application pool identities:'
    $appcmd = "$env:windir\system32\inetsrv\appcmd.exe"
    if (Test-Path $appcmd) {
        & $appcmd list apppool /config /xml 2>$null | Select-String 'userName|password'
    }

    if ($Full) {
        Write-SectionInfo 'Full mode: searching common config roots for credential strings...'
        $roots = @('C:\inetpub', 'C:\xampp', 'C:\Apache24', 'C:\ProgramData')
        $pattern = 'password\s*=|passwd\s*=|pwd\s*=|connectionString\s*=|secret\s*=|api[_-]?key\s*='

        foreach ($root in $roots) {
            if (-not (Test-Path -LiteralPath $root)) { continue }

            Get-ChildItem -Path $root -Recurse -Depth 4 -Include '*.config', '*.xml', '*.ini', '*.txt', '*.json', '*.ps1', '*.bat', '*.cmd' -ErrorAction SilentlyContinue |
                Select-String -Pattern $pattern -ErrorAction SilentlyContinue |
                Select-Object -First 50 Path, LineNumber, Line |
                Format-List
        }
    }
}

function Get-SensitiveAccess {
    Write-Header 'Sensitive File and Hive Access'

    $hives = @(
        'C:\Windows\System32\config\SAM',
        'C:\Windows\System32\config\SYSTEM',
        'C:\Windows\System32\config\SECURITY'
    )

    foreach ($hive in $hives) {
        try {
            $stream = [System.IO.File]::Open($hive, 'Open', 'Read', 'ReadWrite')
            $stream.Close()
            Add-Finding -Severity High -Title 'Read access to sensitive registry hive' -Detail $hive
        }
        catch {
            Write-SectionInfo "Access denied (expected): $hive"
        }
    }

    $backup = Get-TokenPrivilegeList | Where-Object { $_.Name -eq 'SeBackupPrivilege' -and $_.Enabled }
    if ($backup) {
        Add-Finding -Severity High -Title 'SeBackupPrivilege enabled' -Detail 'Hives can be copied using backup semantics.'
    }
}

function Get-WiFiPasswords {
    Write-Header 'WiFi Profiles'

    $lines = @(netsh.exe wlan show profiles 2>$null)
    $profiles = [System.Collections.Generic.List[string]]::new()

    foreach ($line in $lines) {
        if ($line -match 'All User Profile\s*:\s*(.+)$') {
            $profiles.Add($matches[1].Trim())
        }
    }

    if ($profiles.Count -eq 0) {
        Write-SectionInfo 'No WiFi profiles found (or locale not recognized).'
        return
    }

    foreach ($wifiProfile in $profiles) {
        $details = @(netsh.exe wlan show profile name="$wifiProfile" key=clear 2>$null)
        $key = $null

        foreach ($line in $details) {
            if ($line -match 'Key Content\s*:\s*(.+)$') {
                $key = $matches[1].Trim()
                break
            }
        }

        if ($key) {
            Add-Finding -Severity Medium -Title "WiFi PSK recoverable: $wifiProfile" -Evidence "Password: $key"
        }
        else {
            Write-SectionInfo "Profile: $wifiProfile (no cleartext key)"
        }
    }
}

function Get-SpoolerInfo {
    Write-Header 'Printer Spooler'

    $spooler = Get-Service -Name Spooler -ErrorAction SilentlyContinue
    if ($spooler -and $spooler.Status -eq 'Running') {
        Add-Finding -Severity Medium -Title 'Print Spooler running' -Detail 'Relevant to PrintNightmare-family issues on unpatched hosts.'

        $pointAndPrint = 'HKLM:\Software\Policies\Microsoft\Windows NT\Printers\PointAndPrint'
        foreach ($value in @('NoWarningNoElevationOnInstall', 'UpdatePromptSettings', 'RestrictDriverInstallationToAdministrators')) {
            $setting = Get-ItemProperty $pointAndPrint -Name $value -ErrorAction SilentlyContinue
            if ($null -ne $setting.$value) {
                Write-SectionInfo "$value = $($setting.$value)"
            }
        }
    }
    else {
        Write-SectionInfo 'Print Spooler is not running.'
    }
}

function Get-SecurityInfo {
    Write-Header 'Security Controls'

    $defender = Get-Command Get-MpComputerStatus -ErrorAction SilentlyContinue
    if ($defender) {
        $status = Get-MpComputerStatus -ErrorAction SilentlyContinue
        if ($status) {
            Write-SectionInfo ("Defender: AMServiceEnabled={0} RealTimeProtectionEnabled={1} SignatureAge={2}d" -f `
                $status.AMServiceEnabled, $status.RealTimeProtectionEnabled, $status.AntivirusSignatureAge)

            if ($status.AMServiceEnabled -and -not $status.RealTimeProtectionEnabled) {
                Add-Finding -Severity Medium -Title 'Defender real-time protection disabled'
            }
            if ($status.AntivirusSignatureAge -gt 7) {
                Add-Finding -Severity Low -Title 'Defender signatures stale' -Detail "$($status.AntivirusSignatureAge) days old"
            }
        }
    }
    else {
        Write-SectionInfo 'Get-MpComputerStatus not available.'
    }

    Write-SectionInfo 'Third-party antivirus products:'
    Get-CimSafe -Class AntiVirusProduct -Namespace 'root/SecurityCenter2' |
        Select-Object displayName, productState, pathToSignedProductExe |
        Format-Table -AutoSize

    $defenderPreferences = Get-Command Get-MpPreference -ErrorAction SilentlyContinue
    if ($defenderPreferences) {
        $preferences = Get-MpPreference -ErrorAction SilentlyContinue
        if ($preferences) {
            Write-SectionInfo 'Defender exclusions:'
            if ($preferences.ExclusionPath) { $preferences.ExclusionPath | ForEach-Object { Write-SectionInfo "  Path: $_" } }
            if ($preferences.ExclusionProcess) { $preferences.ExclusionProcess | ForEach-Object { Write-SectionInfo "  Process: $_" } }
            if ($preferences.ExclusionExtension) { $preferences.ExclusionExtension | ForEach-Object { Write-SectionInfo "  Extension: $_" } }
        }
    }

    Write-SectionInfo 'Firewall profiles:'
    if (Get-Command Get-NetFirewallProfile -ErrorAction SilentlyContinue) {
        Get-NetFirewallProfile -ErrorAction SilentlyContinue |
            Select-Object Name, Enabled, DefaultInboundAction, DefaultOutboundAction |
            Format-Table -AutoSize
    }
    else {
        netsh.exe advfirewall show allprofiles state 2>$null
    }

    Write-SectionInfo 'AppLocker policies:'
    if (Test-Path 'C:\Windows\System32\AppLocker') {
        Get-ChildItem 'C:\Windows\System32\AppLocker' -ErrorAction SilentlyContinue |
            Select-Object Name, Length |
            Format-Table -AutoSize
    }

    Write-SectionInfo 'PowerShell logging:'
    $loggingKeys = @(
        'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging',
        'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging',
        'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\Transcription'
    )
    foreach ($key in $loggingKeys) {
        if (Test-Path $key) { Get-ItemProperty $key | Format-List }
    }
}

function Get-ModifiablePaths {
    Write-Header 'Writable Paths'

    $paths = @(
        'C:\',
        'C:\Program Files',
        'C:\Program Files (x86)',
        'C:\ProgramData',
        "$env:windir\Temp",
        $env:TEMP,
        'C:\Windows\System32\spool\drivers',
        'C:\Windows\System32\spool\prtprocs',
        'C:\Windows\System32\Tasks',
        'C:\Windows\System32\catroot2',
        'C:\Windows\System32\config'
    )

    foreach ($path in $paths) {
        if ([string]::IsNullOrWhiteSpace($path)) { continue }
        $access = Test-WritablePath $path
        if ($access.Writable) {
            Add-Finding -Severity Medium -Title 'Writable directory' -Detail $path -Evidence $access.Evidence
        }
    }

    Write-SectionInfo 'Writable directories in PATH:'
    $seen = @{}
    foreach ($entry in ($env:PATH -split ';')) {
        $path = $entry.Trim().Trim('"')
        if ([string]::IsNullOrWhiteSpace($path)) { continue }

        $path = [Environment]::ExpandEnvironmentVariables($path)
        $key = $path.ToLowerInvariant()
        if ($seen.ContainsKey($key)) { continue }
        $seen[$key] = $true

        if (-not (Test-Path -LiteralPath $path)) {
            Add-Finding -Severity Low -Title 'Nonexistent PATH directory' -Detail $path -Evidence 'May be creatable if the parent is writable.'
            continue
        }

        $access = Test-WritablePath $path
        if ($access.Writable) {
            Add-Finding -Severity Medium -Title 'Writable PATH directory' -Detail $path -Evidence $access.Evidence
        }
    }

    if ($Full) {
        Write-SectionInfo 'Full mode: checking immediate subdirectories of common install roots...'
        $roots = @('C:\Program Files', 'C:\Program Files (x86)', 'C:\ProgramData')
        foreach ($root in $roots) {
            if (-not (Test-Path -LiteralPath $root)) { continue }

            Get-ChildItem -Path $root -Directory -ErrorAction SilentlyContinue | ForEach-Object {
                $access = Test-WritablePath $_.FullName
                if ($access.Writable) {
                    Add-Finding -Severity Medium -Title 'Writable application directory' `
                        -Detail $_.FullName -Evidence $access.Evidence
                }
            }
        }
    }
}

function Get-StartupInfo {
    Write-Header 'Startup Folders'

    $startupPaths = @(
        'C:\ProgramData\Microsoft\Windows\Start Menu\Programs\StartUp',
        "$env:APPDATA\Microsoft\Windows\Start Menu\Programs\StartUp"
    )

    foreach ($path in $startupPaths) {
        if (-not (Test-Path $path)) { continue }

        Write-SectionInfo "Contents of $path"
        Get-ChildItem $path -ErrorAction SilentlyContinue |
            Select-Object Name, Length, LastWriteTime |
            Format-Table -AutoSize

        $access = Test-WritablePath $path
        if ($access.Writable) {
            Add-Finding -Severity Medium -Title 'Writable startup folder' -Detail $path -Evidence $access.Evidence
        }
    }
}

function Get-SessionContext {
    Write-Header 'Active Sessions and Clipboard'

    Write-SectionInfo 'Logged-on users:'
    query.exe user 2>$null

    Write-SectionInfo 'Interactive/RDP logon sessions:'
    Get-CimSafe -Class Win32_LogonSession |
        Where-Object { $_.LogonType -in @(2, 10) } |
        Select-Object LogonId, LogonType, StartTime |
        Format-Table -AutoSize

    try {
        Add-Type -AssemblyName System.Windows.Forms -ErrorAction Stop
        $text = [System.Windows.Forms.Clipboard]::GetText()
        if ($text) {
            $preview = $text
            if ($preview.Length -gt 200) { $preview = $preview.Substring(0, 200) + '...' }
            Add-Finding -Severity Medium -Title 'Clipboard contains text' -Detail $preview
        }
    }
    catch {
        Write-SectionInfo 'Clipboard not accessible (non-interactive session?).'
    }
}

function Get-AppInfo {
    Write-Header 'Installed Applications'

    $keys = @(
        'HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*',
        'HKLM:\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*',
        'HKCU:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*'
    )

    Get-ItemProperty $keys -ErrorAction SilentlyContinue |
        Where-Object { $_.DisplayName } |
        Select-Object DisplayName, DisplayVersion, Publisher, InstallDate |
        Sort-Object DisplayName -Unique |
        Format-Table -AutoSize
}

function Get-UpdateInfo {
    Write-Header 'Windows Update / WSUS'

    Write-SectionInfo 'WSUS configuration:'
    reg.exe query 'HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate' /v WUServer 2>$null
    reg.exe query 'HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate' /v AUOptions 2>$null

    Write-SectionInfo 'Last 10 installed updates:'
    Get-InstalledHotfixes |
        Select-Object -First 10 |
        Format-Table -AutoSize
}

function Get-PSSecurity {
    Write-Header 'PowerShell Security'

    Write-SectionInfo "Version: $($PSVersionTable.PSVersion)"
    Write-SectionInfo "Edition: $($PSVersionTable.PSEdition)"
    Write-SectionInfo "Execution policy: $(Get-ExecutionPolicy)"
    Write-SectionInfo "Language mode: $($ExecutionContext.SessionState.LanguageMode)"

    if ($ExecutionContext.SessionState.LanguageMode -eq 'ConstrainedLanguage') {
        Add-Finding -Severity Info -Title 'PowerShell constrained language mode' -Detail 'Some enumeration techniques may be limited.'
    }

    Write-SectionInfo 'Software Restriction Policies:'
    reg.exe query 'HKLM\SOFTWARE\Policies\Microsoft\Windows\Safer\CodeIdentifiers' 2>$null
}

function Get-StorageInfo {
    Write-Header 'Storage and Shares'

    Write-SectionInfo 'Local drives:'
    Get-PSDrive -PSProvider FileSystem -ErrorAction SilentlyContinue |
        Select-Object Name, Root,
            @{ Name = 'FreeGB'; Expression = { '{0:N2}' -f ($_.Free / 1GB) } },
            @{ Name = 'UsedGB'; Expression = { '{0:N2}' -f ($_.Used / 1GB) } } |
        Format-Table -AutoSize

    Write-SectionInfo 'Mapped logical disks:'
    Get-CimSafe -Class Win32_MappedLogicalDisk |
        Select-Object Name, ProviderName, SessionID |
        Format-Table -AutoSize

    Write-SectionInfo 'SMB shares:'
    net.exe share 2>$null
}

function Get-AdvancedEnum {
    Write-Header 'Advanced Enumeration'

    Write-SectionInfo 'RDP settings:'
    $rdp = Get-ItemProperty 'HKLM:\System\CurrentControlSet\Control\Terminal Server' -Name fDenyTSConnections -ErrorAction SilentlyContinue
    Write-SectionInfo "fDenyTSConnections = $($rdp.fDenyTSConnections)"
    reg.exe query 'HKLM\System\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp' /v PortNumber 2>$null
    reg.exe query 'HKLM\System\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp' /v UserAuthentication 2>$null

    Write-SectionInfo 'WSL:'
    if (Get-Command wsl.exe -ErrorAction SilentlyContinue) {
        wsl.exe --list --quiet 2>$null
        if ($LASTEXITCODE -eq 0) { Write-SectionInfo 'WSL is installed.' }
    }
    else {
        Write-SectionInfo 'wsl.exe not available.'
    }

    Write-SectionInfo 'SMB server configuration:'
    if (Get-Command Get-SmbServerConfiguration -ErrorAction SilentlyContinue) {
        Get-SmbServerConfiguration -ErrorAction SilentlyContinue |
            Select-Object EnableSMB1Protocol, RequireSecuritySignature, EnableSecuritySignature |
            Format-List
    }
    else {
        Write-SectionInfo 'Get-SmbServerConfiguration not available.'
    }

    Write-SectionInfo 'WinRM service:'
    Get-Service -Name WinRM -ErrorAction SilentlyContinue | Select-Object Name, Status, StartType | Format-Table -AutoSize

    Write-SectionInfo 'Stored credentials (cmdkey):'
    cmdkey.exe /list 2>$null

    if ($Full) {
        Write-SectionInfo 'Full mode: searching SYSVOL for GPP cpassword values...'
        $sysvol = "\\$env:USERDOMAIN\SYSVOL"
        if (Test-Path $sysvol) {
            Get-ChildItem -Path $sysvol -Recurse -Include 'Groups.xml', 'Services.xml', 'Scheduledtasks.xml', 'DataSources.xml', 'Printers.xml', 'Drives.xml' -ErrorAction SilentlyContinue |
                Select-String -Pattern 'cpassword' -ErrorAction SilentlyContinue |
                Select-Object -First 25 Path, LineNumber, Line |
                Format-List
        }
        else {
            Write-SectionInfo 'SYSVOL not reachable (non-domain host?).'
        }
    }
}

function Get-PolicyRestrictions {
    Write-Header 'Policy Restrictions (AppLocker / SRP / WDAC)'

    Write-SectionInfo 'AppLocker policy files:'
    Get-ChildItem 'C:\Windows\System32\AppLocker\*.AppLocker' -ErrorAction SilentlyContinue |
        Select-Object FullName, Length |
        Format-Table -AutoSize

    Write-SectionInfo 'SRP registry:'
    reg.exe query 'HKLM\SOFTWARE\Policies\Microsoft\Windows\Safer\CodeIdentifiers' 2>$null

    Write-SectionInfo 'WDAC / CI policy:'
    $ciPolicy = 'HKLM:\SYSTEM\CurrentControlSet\Control\CI\Policy'
    if (Test-Path $ciPolicy) {
        Get-ItemProperty $ciPolicy | Format-List
    }
    else {
        Write-SectionInfo 'No CI policy key found.'
    }
}

# ===========================================================================
# Summary / export
# ===========================================================================

function Show-Summary {
    Write-Header 'Summary'

    $elapsed = (Get-Date) - $script:StartTime
    Write-Host ("Enumeration finished in {0:n1} seconds." -f $elapsed.TotalSeconds) -ForegroundColor Cyan

    if ($script:Findings.Count -eq 0) {
        Write-Host 'No findings recorded.' -ForegroundColor Green
        return
    }

    $counts = @{}
    foreach ($severity in @('High', 'Medium', 'Low', 'Info')) {
        $counts[$severity] = @($script:Findings | Where-Object { $_.Severity -eq $severity }).Count
    }

    Write-Host ("High: {0}  Medium: {1}  Low: {2}  Info: {3}" -f `
        $counts['High'], $counts['Medium'], $counts['Low'], $counts['Info']) -ForegroundColor Cyan

    foreach ($severity in @('High', 'Medium', 'Low', 'Info')) {
        $group = @($script:Findings | Where-Object { $_.Severity -eq $severity })
        if ($group.Count -eq 0) { continue }

        $color = switch ($severity) {
            'High'   { 'Red' }
            'Medium' { 'Yellow' }
            'Low'    { 'DarkYellow' }
            default  { 'Green' }
        }

        Write-Host ""
        Write-Host ("{0} ({1})" -f $severity.ToUpper(), $group.Count) -ForegroundColor $color

        $index = 0
        foreach ($finding in $group) {
            $index++
            Write-Host ("  {0}. {1}" -f $index, $finding.Title)
            if ($finding.Detail) { Write-Host ("     {0}" -f $finding.Detail) -ForegroundColor DarkGray }
        }
    }
}

function Export-Findings {
    if ([string]::IsNullOrWhiteSpace($OutputPath)) { return }

    try {
        $report = [pscustomobject]@{
            Computer  = $env:COMPUTERNAME
            User      = $script:CurrentUser
            Elevated  = $script:IsAdmin
            Timestamp = (Get-Date).ToString('o')
            Findings  = $script:Findings
        }

        $parent = Split-Path -Parent $OutputPath
        if ($parent -and -not (Test-Path -LiteralPath $parent)) {
            New-Item -ItemType Directory -Path $parent -Force | Out-Null
        }

        $report | ConvertTo-Json -Depth 6 -ErrorAction Stop |
            Set-Content -LiteralPath $OutputPath -Encoding UTF8 -ErrorAction Stop
        Write-Host "[+] Findings written to $OutputPath" -ForegroundColor Green
    }
    catch {
        Write-Host "[!] Failed to write ${OutputPath}: $_" -ForegroundColor Yellow
    }
}

# ===========================================================================
# Main
# ===========================================================================

Initialize-IdentityContext
Show-Banner

$modules = @(
    'Get-SystemInfo',
    'Get-UserInfo',
    'Get-NetworkInfo',
    'Get-ServiceInfo',
    'Get-ExploitableServices',
    'Get-ScheduledTasks',
    'Get-RegistryChecks',
    'Get-SensitiveFiles',
    'Get-SensitiveAccess',
    'Get-SecurityInfo',
    'Get-ModifiablePaths',
    'Get-StartupInfo',
    'Get-WiFiPasswords',
    'Get-SpoolerInfo',
    'Get-AdvancedEnum',
    'Get-UpdateInfo',
    'Get-PSSecurity',
    'Get-PolicyRestrictions',
    'Get-StorageInfo',
    'Get-SessionContext',
    'Get-AppInfo'
)

foreach ($module in $modules) {
    try {
        & $module
    }
    catch {
        Write-Host "[!] $module failed: $_" -ForegroundColor Yellow
    }
}

Show-Summary
Export-Findings
