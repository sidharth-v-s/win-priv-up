# win-priv-up

Windows local privilege-escalation enumeration toolkit. It gathers host
context and highlights common escalation conditions; it does **not** exploit
them.

Use it only on systems you own or are explicitly authorized to test.

## Requirements

- Windows 7 SP1 / Server 2008 R2 or newer (best results on Windows 10/11)
- PowerShell 5.1 or PowerShell 7+
- An elevated prompt is optional but improves process, service, and registry coverage

## Usage

### PowerShell (main engine)

```powershell
# Standard sweep
.\enum.ps1

# Deeper checks + JSON report
.\enum.ps1 -Full -OutputPath .\findings.json
```

If script execution is blocked:

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File .\enum.ps1
```

### Batch launcher

`enum.bat` finds `enum.ps1` next to itself and forwards all arguments:

```bat
enum.bat
enum.bat -Full
enum.bat -Full -OutputPath findings.json
```

If PowerShell is unavailable, it runs a limited batch-only fallback
(`whoami`, `systeminfo`, services, autoruns, scheduled tasks, UAC/firewall
state, shares, and common sensitive-file locations).

### C# wrapper

Build `wrapper.cs` with any C# compiler and place the executable next to
`enum.ps1`:

```bat
csc /out:enum.exe wrapper.cs
enum.exe -Full -OutputPath findings.json
```

The wrapper streams PowerShell output live, forwards stdout/stderr, resolves
`enum.ps1` relative to the executable (or the current directory), and returns
the child process exit code.

## What it checks

- System build, hotfixes, architecture, domain/workgroup
- Current user, integrity level, token privileges, and group memberships
- Dangerous privileges (`SeImpersonate`, `SeBackup`, `SeDebug`, `SeLoadDriver`, etc.)
- Local users, local administrators, and active/RDP sessions
- Network configuration, listening ports, shares, and mapped drives
- Services:
  - unquoted service paths and writable path components
  - writable service binaries, directories, and registry keys
  - missing binaries in writable directories
  - weak service DACLs
- Scheduled tasks with writable binaries, directories, or task definitions
- Autoruns, IFEO debuggers, AppInit_DLLs, and writable HKLM autorun keys
- `AlwaysInstallElevated`, AutoLogon credentials, WDigest, UAC, LAPS
- Sensitive files and credential locations:
  - unattend/sysprep files, PowerShell history/transcripts
  - SSH keys, cloud credentials, browser credential stores, Windows Vault
  - PuTTY/VNC registry entries, IIS app-pool identities
- Defender/AV status, firewall profiles, PowerShell logging, AppLocker/SRP/WDAC
- Writable directories in `PATH` and common install roots (`-Full`)
- WiFi PSKs, Print Spooler / Point-and-Print settings, RDP, WSL, WinRM, SMB
- Domain SYSVOL Group Policy Preferences `cpassword` search (`-Full`)

## Output

Findings are printed with a severity label as they are discovered:

| Severity | Meaning |
| --- | --- |
| High | Likely direct privilege-escalation path |
| Medium | Risky configuration or credential exposure |
| Low | Weak hardening / needs investigation |
| Info | Context, not necessarily a weakness |

The final summary groups findings by severity. `-OutputPath` writes the same
findings as JSON (computer, user, elevated flag, timestamp, and findings).

## Notes

- Some checks are intentionally broad and can be noisy on hardened hosts.
  Treat output as leads, not proof of exploitability.
- `-Full` enables slower recursive searches and ACL checks against every
  service.
- Security products may flag enumeration scripts; run only in authorized
  environments.
