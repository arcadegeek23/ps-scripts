#Requires -Version 5.1
# Detect-RebootPending.ps1
# Checks whether a device has a pending reboot from any of the standard
# Windows servicing signals. If a user recently postponed the reboot
# prompt, respects a cooldown so Intune doesn't re-trigger immediately.
#
# Exit 0 = compliant (no reboot needed OR within cooldown)
# Exit 1 = non-compliant (reboot needed and cooldown expired)
# Exit 2+ = error
#
# Author:  Kyle Etter / Zeus
# Created: 2026-06-30
# Intune:  Proactive Remediation - Detection

[CmdletBinding()]
param()

$ErrorActionPreference = 'Stop'
$ProgressPreference    = 'SilentlyContinue'

# --- Inline logging (avoids external dot-source that fails in IME cache) --------
function Write-CITLog {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] [string] $Message,
        [Parameter()] [ValidateSet('INFO','WARN','ERROR','DEBUG')] [string] $Level = 'INFO',
        [Parameter(Mandatory)] [string] $ScriptName
    )
    $logDir = 'C:\ProgramData\CIT\Logs'
    if (-not (Test-Path $logDir)) {
        try { New-Item -Path $logDir -ItemType Directory -Force | Out-Null } catch { return }
    }
    $ts   = (Get-Date).ToString('yyyy-MM-dd HH:mm:ss.fff')
    $line = "$ts [$Level] [$ScriptName] $Message"
    Add-Content -Path (Join-Path $logDir "$ScriptName.log") -Value $line -Encoding UTF8
}

# --- Configuration --------------------------------------------------------------
$ScriptName = 'Detect-RebootPending'

# Cooldown: after a user clicks "Postpone", skip detection for this many hours.
# Combined with the Intune schedule (every 4h), this means the prompt refires
# on the next scheduled tick AFTER the cooldown expires.
$CooldownHours = 4

# Registry paths
$CooldownRegPath = 'HKLM:\SOFTWARE\CIT\RebootPrompt'
$CooldownRegName = 'LastPostpone'

# --- Functions ------------------------------------------------------------------

function Test-CitPendingReboot {
    # Four standard pending-reboot signals:
    #   1. CBS RebootPending key
    #   2. WUfB RebootRequired key
    #   3. PendingFileRenameOperations value (non-empty)
    #   4. UpdateExeVolatile registry key
    try {
        if (Test-Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\RebootPending') {
            return $true, 'CBS RebootPending'
        }
        if (Test-Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\RebootRequired') {
            return $true, 'WUfB RebootRequired'
        }

        $sessionMgr = 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager'
        $pfro = (Get-ItemProperty -Path $sessionMgr -Name 'PendingFileRenameOperations' -ErrorAction SilentlyContinue).PendingFileRenameOperations
        if ($pfro) {
            foreach ($item in $pfro) {
                if (-not [string]::IsNullOrEmpty($item)) {
                    return $true, 'PendingFileRenameOperations'
                }
            }
        }

        $volatilePath = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update'
        $volatile = (Get-ItemProperty -Path $volatilePath -Name 'UpdateExeVolatile' -ErrorAction SilentlyContinue).UpdateExeVolatile
        if ($volatile) {
            return $true, 'UpdateExeVolatile'
        }

        return $false, 'None'
    } catch {
        return $false, "Error: $($_.Exception.Message)"
    }
}

function Get-CitCooldownRemaining {
    # Returns hours remaining in cooldown, or 0 if expired/none.
    try {
        if (-not (Test-Path $CooldownRegPath)) { return 0 }
        $ts = (Get-ItemProperty -Path $CooldownRegPath -Name $CooldownRegName -ErrorAction SilentlyContinue).$CooldownRegName
        if (-not $ts) { return 0 }
        $postponeTime = [datetime]::Parse($ts)
        $elapsed = ((Get-Date) - $postponeTime).TotalHours
        $remaining = $CooldownHours - $elapsed
        if ($remaining -gt 0) {
            return [math]::Round($remaining, 1)
        }
        return 0
    } catch {
        return 0
    }
}

# --- Main -----------------------------------------------------------------------

try {
    Write-CITLog -Message 'Starting reboot-pending detection' -Level INFO -ScriptName $ScriptName

    # 1. Check pending reboot signals
    $needsReboot, $signal = Test-CitPendingReboot

    if (-not $needsReboot) {
        # No reboot needed - clear any stale cooldown and exit compliant
        Write-CITLog -Message "No pending reboot (signal: $signal) - compliant" -Level INFO -ScriptName $ScriptName
        Write-Output "PendingReboot=0;Signal=$signal;Compliant=1"
        exit 0
    }

    # 2. Reboot is needed - check cooldown
    $cooldownRemaining = Get-CitCooldownRemaining
    if ($cooldownRemaining -gt 0) {
        Write-CITLog -Message "Reboot pending ($signal) but user postponed $cooldownRemaining hours ago - within $CooldownHours h cooldown, compliant" -Level INFO -ScriptName $ScriptName
        Write-Output "PendingReboot=1;Signal=$signal;CooldownRemaining=$cooldownRemaining;Compliant=1"
        exit 0
    }

    # 3. Reboot needed and cooldown expired
    Write-CITLog -Message "Reboot pending ($signal) and cooldown expired - non-compliant, will prompt user" -Level WARN -ScriptName $ScriptName
    Write-Output "PendingReboot=1;Signal=$signal;Compliant=0"
    exit 1

} catch {
    Write-CITLog -Message "Detection error: $($_.Exception.Message)" -Level ERROR -ScriptName $ScriptName
    exit 2
}