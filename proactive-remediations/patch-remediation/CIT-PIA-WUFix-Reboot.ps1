# CIT-PIA-WUFix-Reboot.ps1
# Handles pending-reboot remediation by checking logged-in user state.
# Author:  Kyle Etter
# Created: 2026-06-13
# Updated: 2026-06-13
# Tested:  Windows 10 22H2, Windows 11 23H2
# Intune:  Proactive Remediation — Remediation
# Notes:   Blast radius: may reboot the endpoint. If a user is logged in, the script
#          returns a JSON recommendation to schedule via Datto RMM instead of forcing.

[CmdletBinding()]
param(
    [switch]$Force
)

$ErrorActionPreference = 'Stop'
$WarningPreference     = 'Continue'

. "$PSScriptRoot\..\..\platform\CIT-Logging.ps1" -ScriptName 'CIT-PIA-WUFix-Reboot'

try {
    $computerSystem = Get-CimInstance -ClassName Win32_ComputerSystem -ErrorAction Stop
    $user = $computerSystem.UserName

    if ($user -and -not $Force) {
        Write-CITLog -Message "Logged-in user detected ($user); scheduling reboot via Datto RMM" -Level INFO -ScriptName 'CIT-PIA-WUFix-Reboot'

        [PSCustomObject]@{
            Action       = 'SCHEDULE_VIA_DATTO'
            LoggedInUser = $user
        } | ConvertTo-Json -Compress | Write-Output

        exit 0
    }

    Write-CITLog -Message 'No logged-in user or -Force specified; initiating immediate reboot' -Level INFO -ScriptName 'CIT-PIA-WUFix-Reboot'

    [PSCustomObject]@{
        Action       = 'IMMEDIATE_REBOOT'
        LoggedInUser = $user
    } | ConvertTo-Json -Compress | Write-Output

    Restart-Computer -Force

    exit 0
} catch {
    Write-CITLog -Message "Reboot remediation error: $($_.Exception.Message)" -Level ERROR -ScriptName 'CIT-PIA-WUFix-Reboot'
    exit 2
}
