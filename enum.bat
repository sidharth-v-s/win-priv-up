@echo off
rem ===========================================================================
rem  Windows Privilege Escalation Enumeration - batch launcher
rem
rem  The main engine is enum.ps1. This launcher runs it with PowerShell and
rem  falls back to a limited batch-only sweep if PowerShell is unavailable.
rem
rem  Usage:
rem      enum.bat
rem      enum.bat -Full
rem      enum.bat -Full -OutputPath findings.json
rem ===========================================================================
setlocal EnableExtensions
title Windows Privilege Escalation Enumeration

set "SCRIPT_DIR=%~dp0"
set "PS_SCRIPT=%SCRIPT_DIR%enum.ps1"
set "PS="

where powershell.exe >nul 2>&1
if not errorlevel 1 set "PS=powershell.exe"

if not defined PS (
    where pwsh.exe >nul 2>&1
    if not errorlevel 1 set "PS=pwsh.exe"
)

if not defined PS goto :fallback

if not exist "%PS_SCRIPT%" (
    echo [!] enum.ps1 was not found next to this launcher.
    goto :end
)

echo [*] Running enum.ps1 with %PS% ...
"%PS%" -NoProfile -ExecutionPolicy Bypass -File "%PS_SCRIPT%" %*
if errorlevel 1 echo [!] Enumeration exited with a non-zero status.
goto :end

:fallback
echo.
echo ============================================================
echo   PowerShell unavailable - limited batch fallback
echo ============================================================
echo.
echo [+] System information
systeminfo 2>nul | findstr /B /C:"OS Name" /C:"OS Version" /C:"System Type" /C:"Host Name" /C:"Domain"
echo.
echo [+] Current user context
whoami
whoami /priv
whoami /groups
echo.
echo [+] Local users and administrators
net user 2>nul
net localgroup administrators 2>nul
echo.
echo [+] Listening ports
netstat -ano 2>nul | findstr /I "LISTENING"
echo.
echo [+] Services
if exist "%SystemRoot%\System32\wbem\wmic.exe" (
    wmic service get Name,DisplayName,PathName,StartMode,State 2>nul
) else (
    sc query state= all 2>nul
)
echo.
echo [+] Scheduled tasks
schtasks /query /fo LIST /v 2>nul | findstr /I "TaskName Task Run"
echo.
echo [+] AlwaysInstallElevated
reg query HKCU\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated 2>nul
reg query HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated 2>nul
echo.
echo [+] Autorun entries
reg query HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run 2>nul
reg query HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce 2>nul
reg query HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Run 2>nul
reg query HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce 2>nul
echo.
echo [+] Stored credential locations
reg query "HKCU\Software\SimonTatham\PuTTY\Sessions" /s 2>nul
reg query "HKCU\Software\ORL\WinVNC3" /s 2>nul
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" /v DefaultPassword 2>nul
echo.
echo [+] Startup folders
icacls "%ProgramData%\Microsoft\Windows\Start Menu\Programs\StartUp" 2>nul
icacls "%APPDATA%\Microsoft\Windows\Start Menu\Programs\StartUp" 2>nul
echo.
echo [+] UAC, firewall and Defender
reg query HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System /v EnableLUA 2>nul
reg query HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System /v ConsentPromptBehaviorAdmin 2>nul
netsh advfirewall show allprofiles state 2>nul
sc query WinDefend 2>nul
echo.
echo [+] Sessions, shares and mapped drives
query user 2>nul
net share 2>nul
net use 2>nul
echo.
echo [+] Sensitive files
for %%F in (
    "C:\unattend.xml"
    "C:\Windows\Panther\Unattend.xml"
    "C:\Windows\System32\Sysprep\sysprep.xml"
    "C:\Windows\System32\Sysprep\sysprep.inf"
) do if exist %%F echo [!] Found: %%F
if exist "%APPDATA%\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt" echo [!] Found PowerShell history
echo.
echo [+] Writable PATH entries
echo %PATH%
echo.
echo ============================================================
echo   Fallback enumeration complete
echo ============================================================

:end
echo.
pause
endlocal
