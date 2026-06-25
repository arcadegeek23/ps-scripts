# Detect-HPBIOS.ps1
# Detects HP devices that have a Secure Boot UEFI CA 2023 servicing failure
# (Event ID 1797, UEFICA2023Error=0x80004005) where the firmware is rejecting
# the DB write. These devices need an HP BIOS update before the existing
# Secure Boot cert PIA can complete.
#
# Fire-once: writes a registry sentinel after BIOS flash so the detect script
# never flags this device again (regardless of whether the flash succeeded or
# returned an actionable error like BIOS_PASSWORD_REQUIRED).
#
# Author:  Kyle Etter / Zeus
# Created: 2026-06-24
# Version: 1.0 - 2026-06-24 - Initial version
# Intune:  Proactive Remediation - Detection
# Notes:   This PIA sits UPSTREAM of the Secure Boot cert PIA (118af8e1) and
#          the BitLocker re-seal PIA (ba7f7923). It fixes the root cause
#          (outdated HP firmware) so the downstream PIAs can complete.
#
#          Only triggers on HP devices with:
#            1. UEFICA2023Error = 0x80004005 (E_FAIL)
#            2. Latest Secure Boot event ID = 1797 (DB write rejected)
#            3. No prior BIOS update sentinel
#
#          Non-HP devices exit compliant immediately - zero impact on
#          Dell/Lenovo/other fleets.
#
# Key registry paths:
#   HKLM\SYSTEM\CurrentControlSet\Control\SecureBoot\Servicing
#     - UEFICA2023Error   (DWORD) non-zero = failure code
#   HKLM\SOFTWARE\CIT\HPBIOSUpdate
#     - Applied            (DWORD) 1 = BIOS flash already attempted
#
# Event log IDs (System log):
#   1797 = "The Secure Boot update failed as the Windows UEFI CA 2023
#           certificate is not present in Db" (firmware rejected DB write)

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
    try { Add-Content -Path (Join-Path $logDir "$ScriptName.log") -Value $line -Encoding UTF8 } catch { return }
}

$SecureBootServicingKey = 'HKLM:\SYSTEM\CurrentControlSet\Control\SecureBoot\Servicing'
$SentinelKey = 'HKLM:\SOFTWARE\CIT\HPBIOSUpdate'

function Get-CitManufacturer {
    try {
        $cs = Get-CimInstance -ClassName Win32_ComputerSystem -ErrorAction Stop
        return $cs.Manufacturer
    } catch {
        Write-CITLog -Message "Cannot read manufacturer: $($_.Exception.Message)" -Level WARN -ScriptName 'Detect-HPBIOS'
        return $null
    }
}

function Test-CitHPDevice {
    param([string]$Manufacturer)
    if (-not $Manufacturer) { return $false }
    # HP manufacturers: "HP", "Hewlett-Packard", "HP Inc."
    return ($Manufacturer -match 'HP' -or $Manufacturer -match 'Hewlett-Packard')
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
        return $null
    }
}

function ConvertTo-CitUInt32 {
    param($Value)
    if ($null -eq $Value) { return $null }
    try {
        $asInt64 = [int64]$Value
        if ($asInt64 -lt 0) {
            $asInt64 = $asInt64 + 4294967296
        }
        return [uint32]$asInt64
    } catch {
        return $null
    }
}

function Format-CitDwordHex {
    param($Value)
    $uintValue = ConvertTo-CitUInt32 -Value $Value
    if ($null -eq $uintValue) { return 'Unknown' }
    return ('0x{0:X8}' -f $uintValue)
}

function Get-CitLatestSecureBootEvent {
    try {
        $events = Get-WinEvent -FilterHashtable @{
            LogName   = 'System'
            Id        = @(1795, 1796, 1797, 1798, 1801, 1802, 1803)
            StartTime = (Get-Date).AddDays(-30)
        } -MaxEvents 1 -ErrorAction SilentlyContinue

        if ($events) {
            $event = @($events)[0]
            return [PSCustomObject]@{
                Id          = [int]$event.Id
                TimeCreated = $event.TimeCreated
            }
        }
    } catch {
        return $null
    }
    return $null
}

function Test-CitBIOSUpdateSentinel {
    try {
        if (-not (Test-Path $SentinelKey)) {
            return $false
        }
        $item = Get-ItemProperty -Path $SentinelKey -Name 'Applied' -ErrorAction SilentlyContinue
        if ($item -and $item.Applied -eq 1) {
            return $true
        }
        return $false
    } catch {
        return $false
    }
}

try {
    Write-CITLog -Message 'Starting HP BIOS update detection' -Level INFO -ScriptName 'Detect-HPBIOS'

    # 1. Check if sentinel already set (fire-once)
    if (Test-CitBIOSUpdateSentinel) {
        Write-CITLog -Message 'BIOS update sentinel already set - already attempted, no action needed' -Level INFO -ScriptName 'Detect-HPBIOS'
        Write-Output 'Status=AlreadyFlashed;Sentinel=1;Compliant=1'
        exit 0
    }

    # 2. Check if this is an HP device
    $manufacturer = Get-CitManufacturer
    if (-not (Test-CitHPDevice -Manufacturer $manufacturer)) {
        Write-CITLog -Message "Manufacturer=$manufacturer - not HP, device is compliant" -Level INFO -ScriptName 'Detect-HPBIOS'
        Write-Output "Manufacturer=$manufacturer;Compliant=1;Reason=NotHP"
        exit 0
    }

    Write-CITLog -Message "HP device detected (Manufacturer=$manufacturer)" -Level INFO -ScriptName 'Detect-HPBIOS'

    # 3. Check for Secure Boot servicing error
    $errorCode = Get-CitSecureBootRegValue -Name 'UEFICA2023Error'
    if (-not $errorCode -or $errorCode -eq 0) {
        Write-CITLog -Message 'No UEFICA2023Error - no BIOS update needed' -Level INFO -ScriptName 'Detect-HPBIOS'
        Write-Output 'UEFICA2023Error=0;Compliant=1;Reason=NoServicingError'
        exit 0
    }

    $errorHex = Format-CitDwordHex -Value $errorCode

    # 4. Check if the error is 0x80004005 (E_FAIL / firmware rejected write)
    $errorUint = ConvertTo-CitUInt32 -Value $errorCode
    if ($errorUint -ne 2147500037) {
        Write-CITLog -Message "UEFICA2023Error=$errorCode ($errorHex) - not 0x80004005, different error - no BIOS update needed" -Level INFO -ScriptName 'Detect-HPBIOS'
        Write-Output "UEFICA2023Error=$errorCode;ErrorHex=$errorHex;Compliant=1;Reason=DifferentError"
        exit 0
    }

    # 5. Check for Event ID 1797 in System log (confirms firmware DB rejection)
    $latestEvent = Get-CitLatestSecureBootEvent
    $latestEventId = $null
    $latestEventTime = 'NotFound'
    if ($latestEvent) {
        $latestEventId = $latestEvent.Id
        $latestEventTime = $latestEvent.TimeCreated.ToString('s')
    }

    if ($latestEventId -ne 1797) {
        Write-CITLog -Message "UEFICA2023Error=$errorCode ($errorHex) but latest event is $latestEventId (not 1797) - different failure mode" -Level INFO -ScriptName 'Detect-HPBIOS'
        Write-Output "UEFICA2023Error=$errorCode;ErrorHex=$errorHex;Compliant=1;Reason=EventNot1797;LatestEventId=$latestEventId"
        exit 0
    }

    # 6. All conditions met: HP + 0x80004005 + Event 1797 + no sentinel
    Write-CITLog -Message "HP device with UEFICA2023Error=$errorCode ($errorHex) and Event 1797 - needs BIOS update" -Level WARN -ScriptName 'Detect-HPBIOS'
    Write-Output "UEFICA2023Error=$errorCode;ErrorHex=$errorHex;Compliant=0;Reason=FirmwareRejectingDBWrite;LatestEventId=1797;LatestEventTime=$latestEventTime;NextStep=FlashBIOS"
    exit 1

} catch {
    Write-CITLog -Message "Detection error: $($_.Exception.Message)" -Level ERROR -ScriptName 'Detect-HPBIOS'
    Write-Output "DetectionError=$($_.Exception.Message)"
    exit 2
}