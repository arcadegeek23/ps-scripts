# Detect-BitLockerReseal.ps1
# Detects whether a device needs a BitLocker re-seal after the Secure Boot
# certificate transition. After the 2011-to-2023 cert update changes the
# boot manager, BitLocker may remain sealed to the old PCR measurements,
# causing a recovery key prompt on every reboot.
#
# This script checks:
#   1. Cert transition is complete (UEFICA2023Status = Updated)
#   2. A BitLocker recovery key has been used recently (event log evidence)
#   3. We have not already re-sealed this device (sentinel not set)
#
# If all three are true -> non-compliant -> needs Suspend-BitLocker.
# If the cert transition is not complete, the Secure Boot remediation
# handles that -- this script does nothing (different problem).
#
# Author:  Kyle Etter / Zeus
# Created: 2026-06-21
# Version: 2.2 - 2026-06-27 - Add SysNative re-launch guard so detection runs in
#                             64-bit context (BitLocker event channel / cmdlets are
#                             invisible to the 32-bit IME host)
# Version: 2.1 - 2026-06-23 - Add $ProgressPreference, fix Get-WinEvent error handling for PS 5.1
# Version: 2.0 - 2026-06-22 - Inlined Write-CITLog (fixes IME cache dot-source failure)
# Intune:  Proactive Remediation - Detection
# Exit 0 = compliant, 1 = non-compliant (needs re-seal), 2+ = error

[CmdletBinding()]
param()

$ErrorActionPreference = 'Stop'
$WarningPreference     = 'Continue'
$ProgressPreference    = 'SilentlyContinue'

# --- SysNative re-launch guard -------------------------------------------------
# The Intune Management Extension hosts a 32-bit PowerShell on 64-bit Windows.
# In that WOW64 process the BitLocker module and the BitLocker event channels are
# redirected/unavailable, so detection can see a false state. If we are a 32-bit
# process on a 64-bit OS, re-launch this same script via the native 64-bit
# PowerShell under %WINDIR%\SysNative and propagate the child's exit code.
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

# Registry paths
$SecureBootServicingKey = 'HKLM:\SYSTEM\CurrentControlSet\Control\SecureBoot\Servicing'
$SentinelKey = 'HKLM:\SOFTWARE\CIT\BitLockerReseal'

function Get-CitSecureBootRegValue {
    param([string]$Name)

    try {
        if (-not (Test-Path $SecureBootServicingKey)) {
            return $null
        }
        $item = Get-ItemProperty -Path $SecureBootServicingKey -Name $Name -ErrorAction SilentlyContinue
        if ($item -and $null -ne $item.$Name) {
            return $item.$Name
        }
        return $null
    } catch {
        return $null
    }
}

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

function Get-CitBitLockerRecoveryEventCount {
    # Count BitLocker recovery key entry events in the System event log.
    # Event ID 767 = recovery key was used to unlock the OS volume.
    # We look back up to 30 days for evidence of repeated recovery prompts.
    #
    # If we see 1+ recovery events AND the cert transition is complete,
    # BitLocker is sealed to the wrong measurements and needs re-sealing.

    try {
        $cutoff = (Get-Date).AddDays(-30)
        # In PS 5.1, Get-WinEvent throws "No events were found" when the filter
        # matches zero events. We use -ErrorAction SilentlyContinue and also
        # wrap in try/catch to handle both the thrown error and the null return.
        $events = $null
        $events = Get-WinEvent -FilterHashtable @{
            LogName = 'System'
            Id = 767
            StartTime = $cutoff
        } -ErrorAction SilentlyContinue 2>$null

        if ($events -and $events.Count -gt 0) {
            return $events.Count
        }
        return 0
    } catch {
        # No events found is not an error
        return 0
    }
}

try {
    Write-CITLog -Message 'Starting BitLocker re-seal detection' -Level INFO -ScriptName 'Detect-BitLockerReseal'

    # 1. Check if we already re-sealed this device (fire-once sentinel)
    if (Test-CitResealSentinel) {
        Write-CITLog -Message 'Reseal sentinel already set - already fixed, compliant' -Level INFO -ScriptName 'Detect-BitLockerReseal'
        Write-Output 'ResealSentinel=1;Compliant=1'
        exit 0
    }

    # 2. Check if cert transition is complete
    $certStatus = Get-CitSecureBootRegValue -Name 'UEFICA2023Status'
    if ($certStatus -ne 'Updated') {
        # Cert transition not done yet - different problem, Secure Boot remediation handles it
        Write-CITLog -Message "UEFICA2023Status=$certStatus (not Updated) - cert transition not complete, not a re-seal issue" -Level INFO -ScriptName 'Detect-BitLockerReseal'
        Write-Output "UEFICA2023Status=$certStatus;Compliant=1;Reason=CertTransitionIncomplete"
        exit 0
    }

    # 3. Check for BitLocker recovery key entry events
    $recoveryCount = Get-CitBitLockerRecoveryEventCount
    Write-CITLog -Message "BitLocker recovery events (30 days): $recoveryCount" -Level INFO -ScriptName 'Detect-BitLockerReseal'

    if ($recoveryCount -gt 0) {
        Write-CITLog -Message "Certs updated + $recoveryCount recovery event(s) + no sentinel = needs re-seal" -Level WARN -ScriptName 'Detect-BitLockerReseal'
        Write-Output "UEFICA2023Status=Updated;RecoveryEvents=$recoveryCount;Sentinel=0;Compliant=0;Reason=NeedsReseal"
        exit 1
    }

    # Certs updated, no recovery events, no sentinel needed - device is fine
    Write-CITLog -Message 'Certs updated, no recovery events - compliant' -Level INFO -ScriptName 'Detect-BitLockerReseal'
    Write-Output 'UEFICA2023Status=Updated;RecoveryEvents=0;Sentinel=0;Compliant=1'
    exit 0

} catch {
    Write-CITLog -Message "Detection error: $($_.Exception.Message)" -Level ERROR -ScriptName 'Detect-BitLockerReseal'
    exit 2
}