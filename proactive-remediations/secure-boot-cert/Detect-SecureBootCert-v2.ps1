#Requires -Version 5.1
# Detect-SecureBootCert.ps1
# Detects whether a device has completed the Secure Boot 2011-to-2023
# certificate transition by reading the UEFICA2023Status registry value.
# Author:  Kyle Etter
# Created: 2026-06-19
# Version: 2.2 - 2026-06-23 - Fix AvailableUpdates registry path (must be under SecureBoot parent, not Servicing subkey) + add $ProgressPreference
# Version: 2.0 - 2026-06-22 - Inlined Write-CITLog (fixes IME cache dot-source failure)
# Updated: 2026-06-20 - Replaced KB-only check with registry-status check
# Tested:  Windows 10 22H2, Windows 11 23H2, Windows 11 24H2
# Intune:  Proactive Remediation - Detection
# Notes:   Microsoft announced a Secure Boot certificate expiration fix
#          starting June 2026. The 2011 UEFI CA certificates expire mid-2026.
#          Windows applies the 2023 replacements via a servicing task that
#          runs ~every 12 hours when the AvailableUpdates registry bitmask
#          is set. The KB alone does NOT apply the certs - the registry key
#          is what triggers the OS-side servicing flow.
#
#          Compliance is determined by UEFICA2023Status = "Updated".
#          Exit 0 = compliant, 1 = non-compliant (needs update), 2+ = error.
#
# Key registry paths (Microsoft official):
#   HKLM\SYSTEM\CurrentControlSet\Control\SecureBoot\Servicing
#     - AvailableUpdates    (DWORD)  bitmask; 0x5944 = full sequence
#     - UEFICA2023Status     (string) NotStarted / InProgress / Updated
#     - UEFICA2023Error      (DWORD)  non-zero = failure code
#     - HighConfidenceOptOut (DWORD)  1 = block auto monthly deploy
#     - MicrosoftUpdateManagedOptIn (DWORD) CFR opt-in
#
# Event log IDs (System log):
#   1808 = success (certs applied + boot manager updated)
#   1801 = failure during cert apply
#   1795 = firmware rejected variable write (needs OEM firmware update)

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

# Registry path for Secure Boot certificate servicing status.
$SecureBootKey = 'HKLM:\SYSTEM\CurrentControlSet\Control\SecureBoot'
$SecureBootServicingKey = 'HKLM:\SYSTEM\CurrentControlSet\Control\SecureBoot\Servicing'

function Test-CitSecureBootEnabled {
    try {
        $result = Confirm-SecureBootUEFI -ErrorAction Stop
        return $result
    } catch {
        Write-CITLog -Message "Cannot determine Secure Boot status: $($_.Exception.Message)" -Level WARN -ScriptName 'Detect-SecureBootCert'
        return $null
    }
}

function Get-CitSecureBootRegValue {
    param(
        [string]$Name,
        [string]$KeyPath = $SecureBootServicingKey
    )

    try {
        if (-not (Test-Path $KeyPath)) {
            return $null
        }
        $item = Get-ItemProperty -Path $KeyPath -Name $Name -ErrorAction SilentlyContinue
        if ($item -and $item.$Name -ne $null) {
            return $item.$Name
        }
        return $null
    } catch {
        Write-CITLog -Message "Cannot read registry $Name : $($_.Exception.Message)" -Level WARN -ScriptName 'Detect-SecureBootCert'
        return $null
    }
}

try {
    Write-CITLog -Message 'Starting Secure Boot certificate detection' -Level INFO -ScriptName 'Detect-SecureBootCert'

    # 1. Check if Secure Boot is enabled. If not, this PIA does not apply.
    $secureBootOn = Test-CitSecureBootEnabled
    if ($secureBootOn -eq $false) {
        Write-CITLog -Message 'Secure Boot is disabled - device is compliant (cert expiration does not apply)' -Level INFO -ScriptName 'Detect-SecureBootCert'
        Write-Output 'SecureBoot=Disabled;Compliant=1'
        exit 0
    }
    if ($secureBootOn -eq $null) {
        Write-CITLog -Message 'Secure Boot status unknown - proceeding with registry check' -Level WARN -ScriptName 'Detect-SecureBootCert'
    }

    # 2. Read UEFICA2023Status from registry. This is the primary
    #    compliance marker per Microsoft guidance.
    $status = Get-CitSecureBootRegValue -Name 'UEFICA2023Status'

    if ($status -eq 'Updated') {
        Write-CITLog -Message 'UEFICA2023Status=Updated - device is compliant' -Level INFO -ScriptName 'Detect-SecureBootCert'
        Write-Output 'UEFICA2023Status=Updated;Compliant=1'
        exit 0
    }

    if ($status -eq 'InProgress') {
        Write-CITLog -Message 'UEFICA2023Status=InProgress - servicing task is running, not yet complete' -Level INFO -ScriptName 'Detect-SecureBootCert'
        Write-Output 'UEFICA2023Status=InProgress;Compliant=0'
        exit 1
    }

    if ($status -eq 'NotStarted') {
        Write-CITLog -Message 'UEFICA2023Status=NotStarted - device needs remediation (set AvailableUpdates bitmask)' -Level WARN -ScriptName 'Detect-SecureBootCert'
        Write-Output 'UEFICA2023Status=NotStarted;Compliant=0'
        exit 1
    }

    # Status is null or unexpected value. Check if AvailableUpdates has been
    # set already - if so, the task may not have run yet (give it time).
    # If AvailableUpdates is not set, device needs remediation.
    $availableUpdates = Get-CitSecureBootRegValue -Name 'AvailableUpdates' -KeyPath $SecureBootKey
    $errorCode = Get-CitSecureBootRegValue -Name 'UEFICA2023Error'

    if ($errorCode -and $errorCode -ne 0) {
        Write-CITLog -Message "UEFICA2023Error=$errorCode - servicing failed, may need firmware update or OEM support" -Level ERROR -ScriptName 'Detect-SecureBootCert'
        Write-Output "UEFICA2023Error=$errorCode;Compliant=0;Reason=ServicingFailed"
        exit 1
    }

    if ($availableUpdates -and $availableUpdates -ne 0) {
        # AvailableUpdates is set but status is not yet Updated.
        # The servicing task runs ~every 12 hours. Give it time.
        Write-CITLog -Message "AvailableUpdates=0x$($availableUpdates.ToString('X')) but UEFICA2023Status is null/unknown - waiting for servicing task" -Level INFO -ScriptName 'Detect-SecureBootCert'
        Write-Output "AvailableUpdates=0x$($availableUpdates.ToString('X'));Compliant=0;Reason=PendingServicingTask"
        exit 1
    }

    # No status, no AvailableUpdates set - device needs remediation.
    Write-CITLog -Message 'No UEFICA2023Status and AvailableUpdates not set - device needs remediation' -Level WARN -ScriptName 'Detect-SecureBootCert'
    Write-Output 'UEFICA2023Status=NotSet;Compliant=0;Reason=NeedsAvailableUpdates'
    exit 1

} catch {
    Write-CITLog -Message "Detection error: $($_.Exception.Message)" -Level ERROR -ScriptName 'Detect-SecureBootCert'
    exit 2
}