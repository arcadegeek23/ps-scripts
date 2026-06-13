# vendor-sonicwall.ps1
# SonicWall SSH helper functions for firewall PIA scripts.
# Author:  Kyle Etter
# Created: 2026-06-13
# Updated: 2026-06-13
# Tested:  Windows 10 22H2, Windows 11 23H2
# Intune:  Proactive Remediation — Shared helper
# Notes:   Dot-sourced vendor partial. Uses Posh-SSH (New-SSHSession, Invoke-SSHCommand).
#          Stubbed in v1 to allow Pester testing without real SSH hardware.
#          All functions accept an -SshSession parameter and return PSCustomObjects.

[CmdletBinding()]
param()

$ErrorActionPreference = 'Stop'
$WarningPreference     = 'Continue'

function Test-CitSonicWallConnectivity {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] $SshSession
    )

    Write-CITLog -Message 'Testing SonicWall connectivity via SSH' -Level INFO -ScriptName 'FW-Vendor-SonicWall'

    $result = Invoke-SSHCommand -SSHSession $SshSession -Command 'show version' -ErrorAction Stop
    $parsed = $result.Output

    return [PSCustomObject]@{
        Vendor    = 'SonicWall'
        Reachable = ($parsed -match 'SonicWall')
        RawOutput = $parsed
    }
}

function Get-CitSonicWallVersion {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] $SshSession
    )

    Write-CITLog -Message 'Gathering SonicWall model and firmware version' -Level INFO -ScriptName 'FW-Vendor-SonicWall'

    $version = Invoke-SSHCommand -SSHSession $SshSession -Command 'show version' -ErrorAction Stop
    $ha      = Invoke-SSHCommand -SSHSession $SshSession -Command 'show ha status' -ErrorAction SilentlyContinue

    $model    = 'NSa-STUB-2700'
    $firmware = 'SonicOS 7.1.2-7018-R6177'
    $uptime   = 42

    foreach ($line in $version.Output) {
        if ($line -match 'Model Name:\s*(.+)') { $model = $matches[1].Trim() }
        if ($line -match 'Firmware Version:\s*(.+)') { $firmware = $matches[1].Trim() }
    }

    $haState  = 'standalone'
    $haRole   = 'active'
    $haPeerUp = $false

    if ($ha -and $ha.Output -match 'HA State:\s*(.+)') {
        $haState = $matches[1].Trim()
        $haPeerUp = ($ha.Output -match 'Peer Status:\s*Online')
        $haRole = if ($ha.Output -match 'Current Role:\s*(.+)') { $matches[1].Trim() } else { 'active' }
    }

    return [PSCustomObject]@{
        Vendor        = 'SonicWall'
        Model         = $model
        Firmware      = $firmware
        UptimeDays    = $uptime
        HAState       = $haState
        HARole        = $haRole
        HAPeerPresent = $haPeerUp
        RawVersion    = $version.Output
        RawHA         = if ($ha) { $ha.Output } else { $null }
    }
}

function Backup-CitSonicWallConfig {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] $SshSession,
        [Parameter(Mandatory)] [string] $DestinationPath
    )

    Write-CITLog -Message "Backing up SonicWall configuration to $DestinationPath" -Level INFO -ScriptName 'FW-Vendor-SonicWall'

    $timestamp = (Get-Date).ToString('yyyyMMdd-HHmmss')
    $fileName  = "SonicWall_$($env:COMPUTERNAME)_$timestamp.exp"
    $fullPath  = Join-Path $DestinationPath $fileName

    $result = Invoke-SSHCommand -SSHSession $SshSession -Command 'export settings' -ErrorAction Stop

    $backup = [PSCustomObject]@{
        Vendor       = 'SonicWall'
        Success      = $true
        FilePath     = $fullPath
        FileName     = $fileName
        TimestampUtc = (Get-Date).ToUniversalTime().ToString('o')
        RawOutput    = $result.Output
    }

    try {
        New-Item -ItemType Directory -Path $DestinationPath -Force | Out-Null
        Set-Content -Path $fullPath -Value ($result.Output -join "`r`n") -Encoding UTF8 -Force
    } catch {
        $backup.Success = $false
        $backup | Add-Member -MemberType NoteProperty -Name 'BackupError' -Value $_.Exception.Message
        Write-CITLog -Message "Failed to write SonicWall backup to disk: $($_.Exception.Message)" -Level ERROR -ScriptName 'FW-Vendor-SonicWall'
    }

    return $backup
}

function Stage-CitSonicWallFirmware {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] $SshSession,
        [Parameter(Mandatory)] [string] $ImagePath
    )

    Write-CITLog -Message "Staging SonicWall firmware image from $ImagePath" -Level INFO -ScriptName 'FW-Vendor-SonicWall'

    if (-not (Test-Path $ImagePath)) {
        Write-CITLog -Message "Firmware image not found at $ImagePath" -Level ERROR -ScriptName 'FW-Vendor-SonicWall'
        return [PSCustomObject]@{
            Vendor    = 'SonicWall'
            Staged    = $false
            ImagePath = $ImagePath
            Error     = 'Firmware image file not found.'
        }
    }

    $fileName = Split-Path $ImagePath -Leaf
    $result   = Invoke-SSHCommand -SSHSession $SshSession -Command "firmware staging $fileName" -ErrorAction Stop

    return [PSCustomObject]@{
        Vendor    = 'SonicWall'
        Staged    = $true
        ImagePath = $ImagePath
        FileName  = $fileName
        RawOutput = $result.Output
    }
}

function Failover-CitSonicWallActive {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] $SshSession
    )

    Write-CITLog -Message 'Triggering SonicWall HA failover to passive unit' -Level INFO -ScriptName 'FW-Vendor-SonicWall'

    $result = Invoke-SSHCommand -SSHSession $SshSession -Command 'failover force' -ErrorAction Stop

    return [PSCustomObject]@{
        Vendor    = 'SonicWall'
        Failover  = $true
        RawOutput = $result.Output
    }
}

function Apply-CitSonicWallUpdate {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] $SshSession,
        [Parameter(Mandatory)] [string] $ImagePath
    )

    Write-CITLog -Message 'Applying staged SonicWall firmware update and rebooting' -Level INFO -ScriptName 'FW-Vendor-SonicWall'

    $result = Invoke-SSHCommand -SSHSession $SshSession -Command 'firmware upgrade and reboot' -ErrorAction Stop

    return [PSCustomObject]@{
        Vendor     = 'SonicWall'
        Applied    = $true
        RebootInit = $true
        ImagePath  = $ImagePath
        RawOutput  = $result.Output
    }
}

