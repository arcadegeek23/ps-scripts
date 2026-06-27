#Requires -Version 5.1
# CIT-PIA-WUFix-Reboot.ps1
# Handles pending-reboot remediation by checking logged-in user state.
# Author:  Kyle Etter
# Created: 2026-06-13
# Updated: 2026-06-27
# Tested:  Windows 10 22H2, Windows 11 23H2
# Intune:  Proactive Remediation - Remediation
# Notes:   Blast radius: may reboot the endpoint. If a user is logged in, the script
#          returns a JSON recommendation to schedule via Datto RMM instead of forcing.
#          Active-session detection uses the explorer.exe owner (Win32_Process +
#          GetOwner), which is reliable under SYSTEM / RDP where the legacy logged-on-user
#          query returns null. Detection is the authoritative logon source. Detection failures fail CLOSED (do NOT reboot).

[CmdletBinding()]
param(
    [switch]$Force
)

$ErrorActionPreference = 'Stop'
$WarningPreference     = 'Continue'

. "$PSScriptRoot\..\..\platform\CIT-Logging.ps1" -ScriptName 'CIT-PIA-WUFix-Reboot'

# Returns a hashtable: Active (bool) = a real interactive user session exists,
# Certain (bool) = detection completed without error, Users (string) = owners.
# The Win32_ComputerSystem logged-on-user property reads as null under SYSTEM and during RDP, so it
# cannot be trusted. The presence of an explorer.exe process owned by a real
# (non-SYSTEM) account is a reliable signal of an interactive session.
function Get-CitActiveSessionState {
    $state = @{
        Active  = $false
        Certain = $false
        Users   = ''
    }

    try {
        $explorers = @(Get-CimInstance -ClassName Win32_Process -Filter "Name='explorer.exe'" -ErrorAction Stop)
        $owners = @()

        foreach ($proc in $explorers) {
            try {
                $owner = Invoke-CimMethod -InputObject $proc -MethodName GetOwner -ErrorAction Stop
            } catch {
                # An owner we cannot resolve means we cannot prove the box is idle.
                Write-CITLog -Message "Could not resolve owner of explorer.exe PID $($proc.ProcessId); failing closed" -Level WARN -ScriptName 'CIT-PIA-WUFix-Reboot'
                $state.Active  = $true
                $state.Certain = $false
                return $state
            }

            if ($owner -and $owner.User) {
                $domain = ''
                if ($owner.Domain) { $domain = "$($owner.Domain)\" }
                $account = "$domain$($owner.User)"
                # Exclude machine/service accounts; a real user shell means in-use.
                if ($owner.User -notmatch '^(SYSTEM|LOCAL SERVICE|NETWORK SERVICE|DWM-\d+|UMFD-\d+)$') {
                    $owners += $account
                }
            }
        }

        $owners = @($owners | Select-Object -Unique)
        $state.Users   = ($owners -join ', ')
        $state.Active  = ($owners.Count -gt 0)
        $state.Certain = $true
        return $state
    } catch {
        # Detection itself failed: we do not know whether anyone is logged on.
        # Fail closed - treat as in-use so we never reboot an active machine.
        Write-CITLog -Message "Active-session detection failed ($($_.Exception.Message)); failing closed (assuming user present)" -Level WARN -ScriptName 'CIT-PIA-WUFix-Reboot'
        $state.Active  = $true
        $state.Certain = $false
        return $state
    }
}

try {
    $session = Get-CitActiveSessionState

    # Fail CLOSED: reboot only when -Force is set OR we are CERTAIN no
    # interactive user session is present. Uncertain detection => schedule.
    $safeToReboot = $Force -or ($session.Certain -and -not $session.Active)

    if (-not $safeToReboot) {
        $reason = 'user-present'
        if (-not $session.Certain) { $reason = 'detection-uncertain' }
        Write-CITLog -Message "Reboot deferred ($reason; users '$($session.Users)'); scheduling reboot via Datto RMM" -Level INFO -ScriptName 'CIT-PIA-WUFix-Reboot'

        [PSCustomObject]@{
            Action       = 'SCHEDULE_VIA_DATTO'
            LoggedInUser = $session.Users
            Reason       = $reason
        } | ConvertTo-Json -Compress | Write-Output

        exit 0
    }

    Write-CITLog -Message 'No interactive user detected or -Force specified; initiating immediate reboot' -Level INFO -ScriptName 'CIT-PIA-WUFix-Reboot'

    [PSCustomObject]@{
        Action       = 'IMMEDIATE_REBOOT'
        LoggedInUser = $session.Users
    } | ConvertTo-Json -Compress | Write-Output

    # Flush stdout so PIA/Datto reads the token before the box goes down, then
    # schedule the reboot with a short delay rather than racing the process exit.
    [Console]::Out.Flush()
    Start-Process -FilePath 'shutdown.exe' -ArgumentList '/r','/t','15','/c','CIT patch remediation reboot' -WindowStyle Hidden -ErrorAction Stop

    exit 0
} catch {
    Write-CITLog -Message "Reboot remediation error: $($_.Exception.Message)" -Level ERROR -ScriptName 'CIT-PIA-WUFix-Reboot'
    [PSCustomObject]@{
        Action = 'ERROR'
        Reason = 'unhandled-exception'
    } | ConvertTo-Json -Compress | Write-Output
    exit 2
}