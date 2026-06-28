# Remediate-HPBIOS.ps1
# Flashes the latest HP BIOS on devices where Secure Boot UEFI CA 2023
# servicing is failing (Event 1797, 0x80004005) because the firmware is
# rejecting the DB write. Uses HP Client Management Script Library (HPCMSL)
# to download and flash the latest BIOS silently.
#
# Fire-once: writes a registry sentinel after running so the detect script
# never flags this device again.
#
# Author:  Kyle Etter / Zeus
# Created: 2026-06-24
# Version: 1.0 - 2026-06-24 - Initial version
# Intune:  Proactive Remediation - Remediation
# Tested:  Windows 10 22H2, Windows 11 22H2/23H2/24H2
# Notes:   Requires PowerShell 5.1+ (HPCMSL constraint). Runs as SYSTEM.
#          HPCMSL is installed if not present. BitLocker is suspended for
#          exactly 1 reboot before the flash. The flash stages silently -
#          the actual BIOS update applies on the NEXT reboot.
#
#          After reboot, the existing Secure Boot cert PIA detects
#          UEFICA2023Status != Updated and sets AvailableUpdates=0x5944.
#          With updated firmware, the Windows servicing task succeeds,
#          writes the 2023 cert to Db, and the device goes green.
#
# Blast radius: Flashes BIOS firmware. BitLocker suspended for 1 reboot
#               (auto-resumes). No forced reboot - user reboots naturally.
#               HP dual-BIOS redundancy provides rollback safety.

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

$SentinelKey = 'HKLM:\SOFTWARE\CIT\HPBIOSUpdate'

function Test-CitResealSentinel {
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

function Set-CitBIOSUpdateSentinel {
    param(
        [int]$Status = 1,
        [string]$Note = ''
    )
    try {
        if (-not (Test-Path $SentinelKey)) {
            New-Item -Path $SentinelKey -Force | Out-Null
        }
        New-ItemProperty -Path $SentinelKey -Name 'Applied' -Value $Status -PropertyType DWord -Force -ErrorAction Stop | Out-Null
        New-ItemProperty -Path $SentinelKey -Name 'Date' -Value (Get-Date).ToString('o') -PropertyType String -Force -ErrorAction SilentlyContinue | Out-Null
        if ($Note) {
            New-ItemProperty -Path $SentinelKey -Name 'Note' -Value $Note -PropertyType String -Force -ErrorAction SilentlyContinue | Out-Null
        }
        Write-CITLog -Message "BIOS update sentinel written (Applied=$Status)" -Level INFO -ScriptName 'Remediate-HPBIOS'
        return $true
    } catch {
        Write-CITLog -Message "Failed to write sentinel: $($_.Exception.Message)" -Level ERROR -ScriptName 'Remediate-HPBIOS'
        return $false
    }
}

function Test-CitHPCMSLInstalled {
    try {
        $mod = Get-Module -Name 'HPCMSL' -ListAvailable -ErrorAction SilentlyContinue
        return ($null -ne $mod)
    } catch {
        return $false
    }
}

function Install-CitHPCMSL {
    try {
        Write-CITLog -Message 'Installing HPCMSL from PowerShell Gallery' -Level INFO -ScriptName 'Remediate-HPBIOS'
        # Ensure NuGet provider is available
        if (-not (Get-PackageProvider -Name NuGet -ListAvailable -ErrorAction SilentlyContinue)) {
            Install-PackageProvider -Name NuGet -MinimumVersion 2.8.5.201 -Force -ErrorAction SilentlyContinue | Out-Null
        }
        # Set PSGallery as trusted to avoid prompts
        Set-PSRepository -Name PSGallery -InstallationPolicy Trusted -ErrorAction SilentlyContinue
        Install-Module -Name HPCMSL -Force -Scope AllUsers -AcceptLicense -ErrorAction Stop
        Write-CITLog -Message 'HPCMSL installed successfully' -Level INFO -ScriptName 'Remediate-HPBIOS'
        return $true
    } catch {
        Write-CITLog -Message "Failed to install HPCMSL: $($_.Exception.Message)" -Level ERROR -ScriptName 'Remediate-HPBIOS'
        return $false
    }
}

function Get-CitBitLockerStatus {
    try {
        return Get-BitLockerVolume -MountPoint 'C:' -ErrorAction Stop
    } catch {
        Write-CITLog -Message "Cannot read BitLocker status: $($_.Exception.Message)" -Level WARN -ScriptName 'Remediate-HPBIOS'
        return $null
    }
}

function Get-CitHPBIOSPassword {
    # Check if BIOS password is set via HPCMSL
    try {
        $settings = Get-HPBIOSSetting -ErrorAction SilentlyContinue | Where-Object { $_.Name -eq 'Setup Password' -or $_.Name -eq 'Power-On Password' }
        if ($settings) {
            $hasPassword = $false
            foreach ($s in $settings) {
                if ($s.Value -and $s.Value -ne '') {
                    $hasPassword = $true
                    break
                }
            }
            return $hasPassword
        }
        return $false
    } catch {
        # If we cannot determine, assume no password (HPCMSL will handle it)
        return $false
    }
}

try {
    Write-CITLog -Message 'Starting HP BIOS update remediation' -Level INFO -ScriptName 'Remediate-HPBIOS'

    # 1. Idempotency: if sentinel already set, exit
    if (Test-CitResealSentinel) {
        Write-CITLog -Message 'BIOS update sentinel already set - already attempted, no action (idempotent)' -Level INFO -ScriptName 'Remediate-HPBIOS'
        Write-Output 'Status=AlreadyFlashed;Sentinel=1'
        exit 0
    }

    # 2. Verify HPCMSL is installed; install if not
    if (-not (Test-CitHPCMSLInstalled)) {
        $installed = Install-CitHPCMSL
        if (-not $installed) {
            Write-CITLog -Message 'Cannot install HPCMSL - cannot proceed with BIOS flash' -Level ERROR -ScriptName 'Remediate-HPBIOS'
            Set-CitBIOSUpdateSentinel -Status 2 -Note 'HPCMSLInstallFailed' | Out-Null
            Write-Output 'Status=ERROR;Reason=HPCMSLInstallFailed;NextStep=ManualHPCMSLInstall'
            exit 2
        }
    }

    # Import HPCMSL
    Import-Module HPCMSL -ErrorAction Stop
    Write-CITLog -Message 'HPCMSL imported successfully' -Level INFO -ScriptName 'Remediate-HPBIOS'

    # 3. Check for BIOS password
    $hasBIOSPassword = Get-CitHPBIOSPassword
    if ($hasBIOSPassword) {
        Write-CITLog -Message 'BIOS password is set - cannot flash automatically' -Level WARN -ScriptName 'Remediate-HPBIOS'
        Set-CitBIOSUpdateSentinel -Status 3 -Note 'BIOSPasswordSet' | Out-Null
        Write-Output 'Status=MANUAL;Reason=BIOSPasswordSet;NextStep=EnterPasswordAndFlashManually'
        exit 0
    }

    # 4. Suspend BitLocker for 1 reboot (BIOS flash changes measured boot state)
    $bl = Get-CitBitLockerStatus
    if ($bl -and $bl.ProtectionStatus -eq 'On') {
        try {
            Suspend-BitLocker -MountPoint 'C:' -RebootCount 1 -ErrorAction Stop
            Write-CITLog -Message 'BitLocker suspended on C: for 1 reboot (auto-resumes on next restart)' -Level INFO -ScriptName 'Remediate-HPBIOS'
        } catch {
            Write-CITLog -Message "Failed to suspend BitLocker: $($_.Exception.Message)" -Level WARN -ScriptName 'Remediate-HPBIOS'
            # Continue anyway - flash may still work, BitLocker recovery may prompt
        }
    } else {
        Write-CITLog -Message "BitLocker not On (status=$($bl.ProtectionStatus)) - skipping suspension" -Level INFO -ScriptName 'Remediate-HPBIOS'
    }

    # 5. Flash the latest BIOS
    Write-CITLog -Message 'Downloading and flashing latest HP BIOS' -Level INFO -ScriptName 'Remediate-HPBIOS'
    try {
        Get-HPBIOSUpdates -Flash -BitLocker Suspend -Force -Yes -ErrorAction Stop
        Write-CITLog -Message 'HP BIOS flash completed successfully' -Level INFO -ScriptName 'Remediate-HPBIOS'
    } catch {
        $errMsg = $_.Exception.Message
        Write-CITLog -Message "HP BIOS flash failed: $errMsg" -Level ERROR -ScriptName 'Remediate-HPBIOS'
        Set-CitBIOSUpdateSentinel -Status 4 -Note "FlashFailed:$errMsg" | Out-Null
        Write-Output "Status=ERROR;Reason=FlashFailed;Error=$errMsg;NextStep=ManualBIOSUpdate"
        exit 2
    }

    # 6. Write sentinel so this never fires again
    $sentinelOk = Set-CitBIOSUpdateSentinel -Status 1 -Note 'FlashedSuccessfully'
    if (-not $sentinelOk) {
        Write-CITLog -Message 'Sentinel write failed - but BIOS flash succeeded. Device may be re-detected.' -Level WARN -ScriptName 'Remediate-HPBIOS'
    }

    Write-CITLog -Message 'HP BIOS update remediation complete - user should reboot to finalize' -Level INFO -ScriptName 'Remediate-HPBIOS'

    $sentinelStr = if ($sentinelOk) { 'Written' } else { 'Failed' }
    Write-Output "Status=BIOS_FLASHED;Sentinel=$sentinelStr;NextStep=UserMustRebootOnce"
    exit 0

} catch {
    Write-CITLog -Message "Remediation error: $($_.Exception.Message)" -Level ERROR -ScriptName 'Remediate-HPBIOS'
    # Write sentinel with error status so we do not loop
    Set-CitBIOSUpdateSentinel -Status 5 -Note "UnhandledError:$($_.Exception.Message)" | Out-Null
    Write-Output "Status=ERROR;Reason=$($_.Exception.Message)"
    exit 2
}