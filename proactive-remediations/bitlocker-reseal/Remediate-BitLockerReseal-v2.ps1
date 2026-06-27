# Remediate-BitLockerReseal.ps1
# Re-seals BitLocker to the current boot measurements after the Secure Boot
# certificate transition. Suspends BitLocker for one reboot so it re-seals
# to the new PCR values on the next restart.
#
# Fire-once: writes a registry sentinel after running so the detect script
# never flags this device again.
#
# Author:  Kyle Etter / Zeus
# Created: 2026-06-21
# Version: 2.2 - 2026-06-27 - Add SysNative re-launch guard (BitLocker module is
#                             unavailable to the 32-bit IME host), guard BitLocker
#                             cmdlet presence, and harden idempotency (no-op when
#                             already suspended for reboot)
# Version: 2.1 - 2026-06-23 - Fix PS 5.1 compat (ConvertTo-Json -Compress not available), add $ProgressPreference
# Version: 2.0 - 2026-06-22 - Inlined Write-CITLog (fixes IME cache dot-source failure)
# Intune:  Proactive Remediation - Remediation
#
# What it does:
#   1. Re-launches under 64-bit PowerShell if started 32-bit on a 64-bit OS
#   2. Idempotency: checks sentinel first, exits 0 if already done
#   3. Verifies the BitLocker module/cmdlets are available (contract error if not)
#   4. Verifies BitLocker is active on C:
#   5. Idempotency: if already suspended for a reboot, writes sentinel and no-ops
#   6. Runs Suspend-BitLocker -MountPoint C: -RebootCount 1
#      (suspends for exactly ONE reboot, then auto-resumes)
#   7. Writes sentinel: HKLM:\SOFTWARE\CIT\BitLockerReseal\ResealApplied = 1
#   8. The user reboots, BitLocker re-seals to current PCR values, done
#
# Blast radius: suspends BitLocker on C: for one reboot only. BitLocker
# auto-resumes after the next restart. No data exposure risk beyond the
# single reboot window. No forced reboot - user reboots naturally.

[CmdletBinding()]
param()

$ErrorActionPreference = 'Stop'
$WarningPreference     = 'Continue'
$ProgressPreference    = 'SilentlyContinue'

# --- SysNative re-launch guard -------------------------------------------------
# The Intune Management Extension hosts a 32-bit PowerShell on 64-bit Windows.
# In that WOW64 process the BitLocker module and manage-bde are redirected and
# effectively unavailable, so Suspend-BitLocker / Get-BitLockerVolume cannot run.
# If we are a 32-bit process on a 64-bit OS, re-launch this same script via the
# native 64-bit PowerShell under %WINDIR%\SysNative and propagate the exit code.
if ([Environment]::Is64BitOperatingSystem -and -not [Environment]::Is64BitProcess) {
    $sysNativePsh = Join-Path $env:WINDIR 'SysNative\WindowsPowerShell\v1.0\powershell.exe'
    if (Test-Path $sysNativePsh) {
        $childArgs = @(
            '-NoProfile'
            '-NonInteractive'
            '-ExecutionPolicy', 'Bypass'
            '-File', $PSCommandPath
        )
        $proc = Start-Process -FilePath $sysNativePsh -ArgumentList $childArgs -Wait -PassThru -WindowStyle Hidden
        exit $proc.ExitCode
    }
    # SysNative not present (genuine 32-bit OS, or path missing) - fall through and
    # run in-process; on a true 32-bit OS there is no redirection to escape.
}
# ------------------------------------------------------------------------------

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

$SentinelKey = 'HKLM:\SOFTWARE\CIT\BitLockerReseal'

function Test-CitResealSentinel {
    try {
        if (-not (Test-Path $SentinelKey)) {
            return $false
        }
        $item = Get-ItemProperty -Path $SentinelKey -Name 'ResealApplied' -ErrorAction SilentlyContinue
        if ($item -and $item.ResealApplied -eq 1) {
            return $true
        }
        return $false
    } catch {
        return $false
    }
}

function Set-CitResealSentinel {
    try {
        if (-not (Test-Path $SentinelKey)) {
            New-Item -Path $SentinelKey -Force | Out-Null
        }
        Set-ItemProperty -Path $SentinelKey -Name 'ResealApplied' -Value 1 -Type DWord -ErrorAction Stop
        # Also record the date for audit
        Set-ItemProperty -Path $SentinelKey -Name 'ResealDate' -Value (Get-Date).ToString('o') -Type String -ErrorAction SilentlyContinue
        Write-CITLog -Message 'Reseal sentinel written (ResealApplied=1)' -Level INFO -ScriptName 'Remediate-BitLockerReseal'
        return $true
    } catch {
        Write-CITLog -Message "Failed to write sentinel: $($_.Exception.Message)" -Level ERROR -ScriptName 'Remediate-BitLockerReseal'
        return $false
    }
}

function Test-CitBitLockerAvailable {
    # The BitLocker cmdlets live in the BitLocker module, which is present only on
    # 64-bit Windows client/server SKUs with the feature. Under the 32-bit IME host
    # (when no SysNative relaunch happened) or on an SKU without BitLocker, the
    # cmdlets are missing. Verify before use so we emit a clear contract error
    # instead of a confusing CommandNotFoundException.
    try {
        $cmd = Get-Command -Name 'Get-BitLockerVolume' -ErrorAction SilentlyContinue
        if ($cmd) {
            return $true
        }
        return $false
    } catch {
        return $false
    }
}

function Get-CitBitLockerStatus {
    try {
        $bl = Get-BitLockerVolume -MountPoint 'C:' -ErrorAction Stop
        return $bl
    } catch {
        Write-CITLog -Message "Cannot read BitLocker status: $($_.Exception.Message)" -Level ERROR -ScriptName 'Remediate-BitLockerReseal'
        return $null
    }
}

try {
    Write-CITLog -Message 'Starting BitLocker re-seal remediation' -Level INFO -ScriptName 'Remediate-BitLockerReseal'

    # 1. Idempotency: if sentinel already set, exit
    if (Test-CitResealSentinel) {
        Write-CITLog -Message 'Reseal sentinel already set - already fixed, no action (idempotent)' -Level INFO -ScriptName 'Remediate-BitLockerReseal'
        Write-Output 'Status=AlreadyResealed;Sentinel=1'
        exit 0
    }

    # 2. Dependency guard: the BitLocker cmdlets must be present. If we got here as
    #    a 32-bit process (no SysNative relaunch possible) or on an SKU without the
    #    BitLocker feature, fail with a clear contract error rather than crashing.
    if (-not (Test-CitBitLockerAvailable)) {
        Write-CITLog -Message 'BitLocker cmdlets not available in this host (module missing or 32-bit context) - cannot remediate' -Level ERROR -ScriptName 'Remediate-BitLockerReseal'
        Write-Output 'Status=ERROR;Reason=BitLockerModuleUnavailable'
        exit 2
    }

    # 3. Verify BitLocker is active on C:
    $bl = Get-CitBitLockerStatus
    if (-not $bl) {
        Write-CITLog -Message 'Cannot determine BitLocker status - exiting with error' -Level ERROR -ScriptName 'Remediate-BitLockerReseal'
        exit 2
    }

    # Idempotency: detect an already-suspended-for-reboot volume and no-op FIRST.
    # When Suspend-BitLocker -RebootCount has already run but the sentinel write
    # failed (or the device has not yet rebooted), Get-BitLockerVolume reports the
    # volume fully encrypted with protection Off. Re-running must NOT issue a second
    # Suspend-BitLocker (which would reset the reboot countdown) and must NOT be
    # mistaken for "BitLocker is off". Just (re-)write the sentinel and succeed.
    if ($bl.ProtectionStatus -eq 'Off' -and "$($bl.VolumeStatus)" -eq 'FullyEncrypted') {
        Write-CITLog -Message 'BitLocker already suspended on an encrypted volume - no second suspend (idempotent no-op)' -Level INFO -ScriptName 'Remediate-BitLockerReseal'
        $sentinelOk = Set-CitResealSentinel
        $sentinelStr = if ($sentinelOk) { 'Written' } else { 'Failed' }
        Write-Output "Status=ALREADY_SUSPENDED;MountPoint=C:;Sentinel=$sentinelStr;NextStep=UserMustRebootOnce"
        exit 0
    }

    if ($bl.ProtectionStatus -ne 'On') {
        Write-CITLog -Message "BitLocker protection is $($bl.ProtectionStatus) on C: - not On and not suspended-encrypted, skipping re-seal" -Level WARN -ScriptName 'Remediate-BitLockerReseal'
        Write-Output "BitLockerStatus=$($bl.ProtectionStatus);Status=Skipped;Reason=BitLockerNotOn"
        # Still write sentinel so we do not keep checking
        Set-CitResealSentinel | Out-Null
        exit 0
    }

    Write-CITLog -Message "BitLocker is On, EncryptionStatus=$($bl.EncryptionStatus), VolumeStatus=$($bl.VolumeStatus)" -Level INFO -ScriptName 'Remediate-BitLockerReseal'

    # 4. Suspend BitLocker for one reboot
    #    After the next reboot, BitLocker auto-resumes and re-seals to the
    #    current PCR values (which now include the 2023 cert boot manager).
    try {
        Suspend-BitLocker -MountPoint 'C:' -RebootCount 1 -ErrorAction Stop
        Write-CITLog -Message 'Suspended BitLocker on C: for 1 reboot - will auto-resume on next restart' -Level INFO -ScriptName 'Remediate-BitLockerReseal'
    } catch {
        Write-CITLog -Message "Failed to suspend BitLocker: $($_.Exception.Message)" -Level ERROR -ScriptName 'Remediate-BitLockerReseal'
        exit 2
    }

    # 4. Write the sentinel so this never fires again
    $sentinelOk = Set-CitResealSentinel
    if (-not $sentinelOk) {
        Write-CITLog -Message 'Sentinel write failed - but BitLocker suspension already applied. Device will re-seal on next reboot but may be re-detected.' -Level WARN -ScriptName 'Remediate-BitLockerReseal'
        # Still exit 0 - the suspension worked, just the sentinel failed
    }

    Write-CITLog -Message 'BitLocker re-seal remediation complete - user should reboot to finalize' -Level INFO -ScriptName 'Remediate-BitLockerReseal'

    $sentinelStr = if ($sentinelOk) { 'Written' } else { 'Failed' }
    Write-Output "Status=SUSPENDED_FOR_REBOOT;MountPoint=C:;RebootCount=1;Sentinel=$sentinelStr;NextStep=UserMustRebootOnce"

    exit 0

} catch {
    Write-CITLog -Message "Remediation error: $($_.Exception.Message)" -Level ERROR -ScriptName 'Remediate-BitLockerReseal'
    exit 2
}