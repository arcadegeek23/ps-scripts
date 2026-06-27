#Requires -Version 5.1
# vendor-sonicwall.ps1
# SonicWall SSH helper functions for firewall PIA scripts.
# Author:  Kyle Etter
# Created: 2026-06-13
# Updated: 2026-06-13
# Tested:  Windows 10 22H2, Windows 11 23H2
# Intune:  Proactive Remediation - Shared helper
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

    # Posh-SSH returns .Output as a STRING ARRAY. Running -match against the
    # array does NOT populate $matches with a usable capture, so reading
    # $matches[1] yields stale/garbage from a prior match. Join to one string
    # first, then match. Init parsed vars to $null and only set ParseOk when a
    # real value is read - never return fabricated defaults as telemetry.
    $versionText = ($version.Output -join "`n")
    $haText      = if ($ha) { ($ha.Output -join "`n") } else { '' }

    $model     = $null
    $firmware  = $null
    $uptime    = $null
    $parseOk   = $true
    $parseErr  = $null

    if ($versionText -match 'Model Name:\s*(.+)') { $model = $matches[1].Trim() }
    if ($versionText -match 'Firmware Version:\s*(.+)') { $firmware = $matches[1].Trim() }
    if ($versionText -match 'Up Time:\s*(\d+)\s*Days') { $uptime = [int]$matches[1] }

    if (-not $firmware) {
        $parseOk  = $false
        $parseErr = 'Could not parse Firmware Version from SonicWall "show version" output.'
    }

    $haState  = $null
    $haRole   = $null
    $haPeerUp = $false

    if ($haText -match 'HA State:\s*(.+)') {
        $haState = $matches[1].Trim()
        $haPeerUp = ($haText -match 'Peer Status:\s*Online')
        if ($haText -match 'Current Role:\s*(.+)') { $haRole = $matches[1].Trim() }
    } else {
        $haState = 'standalone'
    }

    return [PSCustomObject]@{
        Vendor        = 'SonicWall'
        Model         = $model
        Firmware      = $firmware
        UptimeDays    = $uptime
        HAState       = $haState
        HARole        = $haRole
        HAPeerPresent = $haPeerUp
        ParseOk       = $parseOk
        ParseError    = $parseErr
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

    # Do not assume the export succeeded. Gate Success on the remote command's
    # ExitStatus (0 = ok) and only flip to true after we have also written the
    # config to disk. A non-zero ExitStatus or empty output means no real backup.
    $backup = [PSCustomObject]@{
        Vendor       = 'SonicWall'
        Success      = $false
        FilePath     = $fullPath
        FileName     = $fileName
        TimestampUtc = (Get-Date).ToUniversalTime().ToString('o')
        RawOutput    = $result.Output
        BackupError  = $null
    }

    $exitStatus = $result.ExitStatus
    if ($null -ne $exitStatus -and $exitStatus -ne 0) {
        $backup.BackupError = "SonicWall 'export settings' returned non-zero ExitStatus $exitStatus."
        Write-CITLog -Message $backup.BackupError -Level ERROR -ScriptName 'FW-Vendor-SonicWall'
        return $backup
    }

    if (-not $result.Output) {
        $backup.BackupError = "SonicWall 'export settings' returned no output; nothing to back up."
        Write-CITLog -Message $backup.BackupError -Level ERROR -ScriptName 'FW-Vendor-SonicWall'
        return $backup
    }

    try {
        New-Item -ItemType Directory -Path $DestinationPath -Force | Out-Null
        Set-Content -Path $fullPath -Value ($result.Output -join "`r`n") -Encoding UTF8 -Force
        $backup.Success = $true
    } catch {
        $backup.BackupError = $_.Exception.Message
        Write-CITLog -Message "Failed to write SonicWall backup to disk: $($_.Exception.Message)" -Level ERROR -ScriptName 'FW-Vendor-SonicWall'
    }

    return $backup
}

function Save-CitSonicWallFirmware {
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

    # Gate Staged on the remote ExitStatus instead of assuming success; a
    # falsely-staged image would later be applied against nothing.
    $staged     = $true
    $stageError = $null
    $exitStatus = $result.ExitStatus
    if ($null -ne $exitStatus -and $exitStatus -ne 0) {
        $staged     = $false
        $stageError = "SonicWall 'firmware staging' returned non-zero ExitStatus $exitStatus."
        Write-CITLog -Message $stageError -Level ERROR -ScriptName 'FW-Vendor-SonicWall'
    }

    return [PSCustomObject]@{
        Vendor    = 'SonicWall'
        Staged    = $staged
        Error     = $stageError
        ImagePath = $ImagePath
        FileName  = $fileName
        RawOutput = $result.Output
    }
}

function Switch-CitSonicWallActive {
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

function Install-CitSonicWallUpdate {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] $SshSession,
        [Parameter(Mandatory)] [string] $ImagePath
    )

    Write-CITLog -Message 'Applying staged SonicWall firmware update and rebooting' -Level INFO -ScriptName 'FW-Vendor-SonicWall'

    $result = Invoke-SSHCommand -SSHSession $SshSession -Command 'firmware upgrade and reboot' -ErrorAction Stop

    # Gate Applied/RebootInit on the remote ExitStatus; reporting success when
    # the upgrade command failed would let the workflow proceed to verify (and
    # eventually auto-resolve) a firewall that never upgraded.
    $applied    = $true
    $applyError = $null
    $exitStatus = $result.ExitStatus
    if ($null -ne $exitStatus -and $exitStatus -ne 0) {
        $applied    = $false
        $applyError = "SonicWall 'firmware upgrade and reboot' returned non-zero ExitStatus $exitStatus."
        Write-CITLog -Message $applyError -Level ERROR -ScriptName 'FW-Vendor-SonicWall'
    }

    return [PSCustomObject]@{
        Vendor     = 'SonicWall'
        Applied    = $applied
        RebootInit = $applied
        Error      = $applyError
        ImagePath  = $ImagePath
        RawOutput  = $result.Output
    }
}

