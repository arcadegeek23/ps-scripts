# Detect-SecureBootCert.ps1
# Detects whether a device has the Secure Boot DBX certificate refresh applied.
# Author:  Kyle Etter
# Created: 2026-06-19
# Tested:  Windows 10 22H2, Windows 11 23H2, Windows 11 24H2
# Intune:  Proactive Remediation - Detection
# Notes:   Microsoft announced a Secure Boot certificate expiration fix starting
#          June 2026. The fix ships in the monthly cumulative update as a DBX
#          revocation list refresh. This script checks whether the required KB
#          is installed for the device's OS build. If Secure Boot is disabled,
#          the device is considered compliant (the cert expiration does not apply).
#          Exit 0 = compliant, 1 = non-compliant (needs update), 2+ = error.

[CmdletBinding()]
param()

$ErrorActionPreference = 'Stop'
$WarningPreference     = 'Continue'

. "$PSScriptRoot\..\..\platform\CIT-Logging.ps1" -ScriptName 'Detect-SecureBootCert'

# ---------------------------------------------------------------------------
# KB mapping: OS build number -> KB that carries the Secure Boot DBX refresh.
# Update this table when Microsoft releases new KBs for additional builds.
# The build numbers below are the major-minor platform versions:
#   19045 = Win10 22H2
#   22631 = Win11 23H2
#   26100 = Win11 24H2
#   26200 = Win11 25H2
# When you confirm the exact June 2026 KBs, update the values here.
# ---------------------------------------------------------------------------
$SecureBootKbMap = @{
    '19045' = 'KB5063610'   # Win10 22H2 - June 2026 cumulative
    '22631' = 'KB5063917'   # Win11 23H2 - June 2026 cumulative
    '26100' = 'KB5063915'   # Win11 24H2 - June 2026 cumulative
    '26200' = 'KB5063915'   # Win11 25H2 - same KB family as 24H2
}

function Get-CitOsBuildNumber {
    try {
        $os = Get-WmiObject -Class Win32_OperatingSystem -ErrorAction Stop
        $version = $os.Version  # e.g. "10.0.19045"
        $parts = $version -split '\.'
        return $parts[2]
    } catch {
        Write-CITLog -Message "Unable to determine OS build: $($_.Exception.Message)" -Level WARN -ScriptName 'Detect-SecureBootCert'
        return $null
    }
}

function Test-CitSecureBootEnabled {
    try {
        # Confirm-SecureBootUEFI is available on Win8+ with UEFI.
        # Returns $true if Secure Boot is on, $false if off or not supported.
        $result = Confirm-SecureBootUEFI -ErrorAction Stop
        return $result
    } catch {
        # If the cmdlet is unavailable (legacy BIOS, or older PS), assume
        # Secure Boot is not applicable and skip the check.
        Write-CITLog -Message "Cannot determine Secure Boot status: $($_.Exception.Message)" -Level WARN -ScriptName 'Detect-SecureBootCert'
        return $null
    }
}

function Test-CitKbInstalled {
    param([string]$KbNumber)

    try {
        $hotfix = Get-HotFix -Id $KbNumber -ErrorAction SilentlyContinue
        if ($hotfix) {
            return $true
        }

        # Fallback: check via WMI (some environments don't surface all KBs via Get-HotFix)
        $wmiQuery = "SELECT * FROM Win32_QuickFixEngineering WHERE HotFixID = '$KbNumber'"
        $wmiResult = Get-WmiObject -Query $wmiQuery -ErrorAction SilentlyContinue
        if ($wmiResult) {
            return $true
        }

        return $false
    } catch {
        Write-CITLog -Message "Unable to check KB $KbNumber : $($_.Exception.Message)" -Level WARN -ScriptName 'Detect-SecureBootCert'
        return $false
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
        Write-CITLog -Message 'Secure Boot status unknown - proceeding with KB check' -Level WARN -ScriptName 'Detect-SecureBootCert'
    }

    # 2. Get OS build number and find the expected KB.
    $buildNumber = Get-CitOsBuildNumber
    if (-not $buildNumber) {
        Write-CITLog -Message 'Could not determine OS build number - exiting with error' -Level ERROR -ScriptName 'Detect-SecureBootCert'
        exit 2
    }

    Write-CITLog -Message "OS build: $buildNumber" -Level INFO -ScriptName 'Detect-SecureBootCert'

    $expectedKb = $SecureBootKbMap[$buildNumber]
    if (-not $expectedKb) {
        Write-CITLog -Message "No KB mapping for build $buildNumber - device is compliant (unknown build, no action defined)" -Level INFO -ScriptName 'Detect-SecureBootCert'
        Write-Output "Build=$buildNumber;Compliant=1;Reason=NoKbMapping"
        exit 0
    }

    Write-CITLog -Message "Expected KB for build $buildNumber : $expectedKb" -Level INFO -ScriptName 'Detect-SecureBootCert'

    # 3. Check if the KB is installed.
    $kbInstalled = Test-CitKbInstalled -KbNumber $expectedKb
    if ($kbInstalled) {
        Write-CITLog -Message "KB $expectedKb is installed - device is compliant" -Level INFO -ScriptName 'Detect-SecureBootCert'
        Write-Output "Build=$buildNumber;Kb=$expectedKb;Compliant=1"
        exit 0
    } else {
        Write-CITLog -Message "KB $expectedKb is NOT installed - device is non-compliant" -Level WARN -ScriptName 'Detect-SecureBootCert'
        Write-Output "Build=$buildNumber;Kb=$expectedKb;Compliant=0"
        exit 1
    }
} catch {
    Write-CITLog -Message "Detection error: $($_.Exception.Message)" -Level ERROR -ScriptName 'Detect-SecureBootCert'
    exit 2
}