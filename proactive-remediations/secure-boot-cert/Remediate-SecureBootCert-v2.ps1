# Remediate-SecureBootCert.ps1
# Sets the AvailableUpdates registry bitmask to trigger the Windows Secure
# Boot certificate servicing task, which applies the 2023 UEFI CA certificates.
# Author:  Kyle Etter
# Created: 2026-06-19
# Version: 2.1 - 2026-06-23 - Fix PS 5.1 compat (ConvertTo-Json -Compress not available), add $ProgressPreference, remove dead function
# Updated: 2026-06-20 - Set AvailableUpdates=0x5944 instead of just triggering WU
# Tested:  Windows 10 22H2, Windows 11 23H2, Windows 11 24H2
# Intune:  Proactive Remediation - Remediation
# Notes:   The Windows servicing task runs ~every 12 hours and checks the
#          AvailableUpdates bitmask under
#          HKLM\SYSTEM\CurrentControlSet\Control\SecureBoot\Servicing.
#          Setting it to 0x5944 requests the full sequence:
#            - Add 2023 DB entries (UEFI CA 2023 + Option ROM UEFI CA 2023)
#            - Update KEK
#            - Update boot manager to the 2023-signed version
#          The task applies changes across multiple reboots. Do NOT expect
#          immediate completion - allow 24-48 hours for the full sequence.
#
#          This script does NOT force a reboot. The servicing task handles
#          reboots natively via the scheduled task.
#
#          Idempotent: if UEFICA2023Status is already "Updated", exits 0.
#
# Blast radius: Sets one registry DWORD under HKLM\SYSTEM\CurrentControlSet.
#              Does not clear WU cache, stop services, or force reboots.
#              The Windows scheduled task does the actual firmware writes.

[CmdletBinding()]
param()

$ErrorActionPreference = 'Stop'
$WarningPreference     = 'Continue'
$ProgressPreference    = 'SilentlyContinue'

# Inline logging function (avoids external dot-source that fails in IME cache)
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

# Registry path for Secure Boot certificate servicing.
$SecureBootServicingKey = 'HKLM:\SYSTEM\CurrentControlSet\Control\SecureBoot\Servicing'

# Bitmask to request the full certificate update sequence.
# 0x5944 = add DB entries + KEK update + boot manager update.
# This is the value Microsoft documents in the Secure Boot playbook.
$AvailableUpdatesBitmask = 0x5944

function Get-CitSecureBootRegValue {
    param([string]$Name)

    try {
        if (-not (Test-Path $SecureBootServicingKey)) {
            return $null
        }
        $item = Get-ItemProperty -Path $SecureBootServicingKey -Name $Name -ErrorAction SilentlyContinue
        if ($item -and $item.$Name -ne $null) {
            return $item.$Name
        }
        return $null
    } catch {
        return $null
    }
}

function Set-CitSecureBootRegValue {
    param(
        [string]$Name,
        $Value
    )

    try {
        if (-not (Test-Path $SecureBootServicingKey)) {
            New-Item -Path $SecureBootServicingKey -Force | Out-Null
            Write-CITLog -Message "Created SecureBoot\Servicing registry key" -Level INFO -ScriptName 'Remediate-SecureBootCert'
        }
        Set-ItemProperty -Path $SecureBootServicingKey -Name $Name -Value $Value -Type DWord -ErrorAction Stop
        Write-CITLog -Message "Set $Name = 0x$($Value.ToString('X'))" -Level INFO -ScriptName 'Remediate-SecureBootCert'
        return $true
    } catch {
        Write-CITLog -Message "Failed to set $Name : $($_.Exception.Message)" -Level ERROR -ScriptName 'Remediate-SecureBootCert'
        return $false
    }
}

try {
    Write-CITLog -Message 'Starting Secure Boot certificate remediation' -Level INFO -ScriptName 'Remediate-SecureBootCert'

    # 1. Idempotency check: if UEFICA2023Status is already Updated, exit.
    $status = Get-CitSecureBootRegValue -Name 'UEFICA2023Status'
    if ($status -eq 'Updated') {
        Write-CITLog -Message 'UEFICA2023Status=Updated - already compliant, no action needed (idempotent)' -Level INFO -ScriptName 'Remediate-SecureBootCert'
        Write-Output 'UEFICA2023Status=Updated;Status=AlreadyCompliant'
        exit 0
    }

    # Check for prior error state - if firmware rejected the write,
    # setting the bitmask again will not help. Surface it.
    $errorCode = Get-CitSecureBootRegValue -Name 'UEFICA2023Error'
    if ($errorCode -and $errorCode -ne 0) {
        Write-CITLog -Message "UEFICA2023Error=$errorCode - prior servicing failure, bitmask reset may help but firmware update may be needed" -Level WARN -ScriptName 'Remediate-SecureBootCert'
        # Continue anyway - a retry may succeed if the error was transient
    }

    # 2. Check if AvailableUpdates is already set to the right value.
    $currentAvailableUpdates = Get-CitSecureBootRegValue -Name 'AvailableUpdates'
    if ($currentAvailableUpdates -eq $AvailableUpdatesBitmask) {
        Write-CITLog -Message "AvailableUpdates already set to 0x$($AvailableUpdatesBitmask.ToString('X')) - waiting for servicing task to complete" -Level INFO -ScriptName 'Remediate-SecureBootCert'
        Write-Output "AvailableUpdates=0x$($AvailableUpdatesBitmask.ToString('X'));Status=AlreadySet;UEFICA2023Status=$status"
        exit 0
    }

    # 3. Set the AvailableUpdates bitmask. This tells the Windows scheduled
    #    task (runs ~every 12 hours) to perform the full cert update sequence.
    $setOk = Set-CitSecureBootRegValue -Name 'AvailableUpdates' -Value $AvailableUpdatesBitmask
    if (-not $setOk) {
        Write-CITLog -Message 'Failed to set AvailableUpdates bitmask - cannot proceed' -Level ERROR -ScriptName 'Remediate-SecureBootCert'
        exit 2
    }

    # 4. Optionally trigger the servicing task immediately rather than
    #    waiting up to 12 hours for the next scheduled run.
    #    The task name is "Secure Boot certificate update" under
    #    \Microsoft\Windows\SecureBoot\CertificateUpdate (if it exists).
    try {
        $taskPath = '\Microsoft\Windows\SecureBoot\CertificateUpdate'
        $task = Get-ScheduledTask -TaskPath $taskPath -ErrorAction SilentlyContinue | Select-Object -First 1
        if ($task) {
            Start-ScheduledTask -TaskPath $taskPath -TaskName $task.TaskName -ErrorAction SilentlyContinue
            Write-CITLog -Message "Triggered scheduled task: $($task.TaskName)" -Level INFO -ScriptName 'Remediate-SecureBootCert'
        } else {
            Write-CITLog -Message 'SecureBoot servicing scheduled task not found - will run on next 12h cycle' -Level INFO -ScriptName 'Remediate-SecureBootCert'
        }
    } catch {
        Write-CITLog -Message "Could not trigger scheduled task (non-fatal): $($_.Exception.Message)" -Level WARN -ScriptName 'Remediate-SecureBootCert'
    }

    Write-CITLog -Message "Remediation triggered: AvailableUpdates=0x$($AvailableUpdatesBitmask.ToString('X')). Servicing task will apply certs over next 24-48h with reboots." -Level INFO -ScriptName 'Remediate-SecureBootCert'

    Write-Output "Status=BITMASK_SET;AvailableUpdates=0x$($AvailableUpdatesBitmask.ToString('X'));UEFICA2023Status=$status;NextStep=ServicingTaskWithin12h"

    Write-CITLog -Message 'Secure Boot certificate remediation complete' -Level INFO -ScriptName 'Remediate-SecureBootCert'
    exit 0

} catch {
    Write-CITLog -Message "Remediation error: $($_.Exception.Message)" -Level ERROR -ScriptName 'Remediate-SecureBootCert'
    exit 2
}