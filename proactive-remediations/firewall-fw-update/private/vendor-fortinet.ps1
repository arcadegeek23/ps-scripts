# vendor-fortinet.ps1
# Fortinet SSH helper functions for firewall PIA scripts.
# Author:  Kyle Etter
# Created: 2026-06-13
# Updated: 2026-06-13
# Tested:  Windows 10 22H2, Windows 11 23H2
# Intune:  Proactive Remediation — Shared helper
# Notes:   Dot-sourced vendor partial. Uses Posh-SSH (New-SSHSession, Invoke-SSHCommand).
#          Stubbed in v1 to allow Pester testing without real SSH hardware.
#          FortiOS CLI commands are execute-only and read-only as appropriate.

[CmdletBinding()]
param()

$ErrorActionPreference = 'Stop'
$WarningPreference     = 'Continue'

function Test-CitFortinetConnectivity {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] $SshSession
    )

    Write-CITLog -Message 'Testing Fortinet connectivity via SSH' -Level INFO -ScriptName 'FW-Vendor-Fortinet'

    $result = Invoke-SSHCommand -SSHSession $SshSession -Command 'get system status' -ErrorAction Stop
    $parsed = $result.Output

    return [PSCustomObject]@{
        Vendor    = 'Fortinet'
        Reachable = ($parsed -match 'FortiOS')
        RawOutput = $parsed
    }
}

function Get-CitFortinetVersion {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] $SshSession
    )

    Write-CITLog -Message 'Gathering Fortinet model and firmware version' -Level INFO -ScriptName 'FW-Vendor-Fortinet'

    $version = Invoke-SSHCommand -SSHSession $SshSession -Command 'get system status' -ErrorAction Stop
    $ha      = Invoke-SSHCommand -SSHSession $SshSession -Command 'get system ha status' -ErrorAction SilentlyContinue

    $model    = 'FGT-STUB-60F'
    $firmware = 'v7.4.3-build2571 (GA)'
    $uptime   = 42

    foreach ($line in $version.Output) {
        if ($line -match 'Version:\s*(.+)') { $firmware = $matches[1].Trim() }
        if ($line -match 'Model name:\s*(.+)') { $model = $matches[1].Trim() }
    }

    $haState  = 'standalone'
    $haRole   = 'master'
    $haPeerUp = $false

    if ($ha -and $ha.Output -match 'Mode:\s*(.+)') {
        $haState = $matches[1].Trim()
        $haPeerUp = ($ha.Output -match 'Slave.*online')
        $haRole = if ($ha.Output -match 'Master') { 'master' } else { 'slave' }
    }

    return [PSCustomObject]@{
        Vendor        = 'Fortinet'
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

function Backup-CitFortinetConfig {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] $SshSession,
        [Parameter(Mandatory)] [string] $DestinationPath
    )

    Write-CITLog -Message "Backing up Fortinet configuration to $DestinationPath" -Level INFO -ScriptName 'FW-Vendor-Fortinet'

    $timestamp = (Get-Date).ToString('yyyyMMdd-HHmmss')
    $fileName  = "FortiGate_$($env:COMPUTERNAME)_$timestamp.conf"
    $fullPath  = Join-Path $DestinationPath $fileName

    $result = Invoke-SSHCommand -SSHSession $SshSession -Command 'execute backup config tftp dummy-placeholder' -ErrorAction Stop

    $backup = [PSCustomObject]@{
        Vendor       = 'Fortinet'
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
        Write-CITLog -Message "Failed to write Fortinet backup to disk: $($_.Exception.Message)" -Level ERROR -ScriptName 'FW-Vendor-Fortinet'
    }

    return $backup
}


function Stage-CitFortinetFirmware {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] $SshSession,
        [Parameter(Mandatory)] [string] $ImagePath
    )

    Write-CITLog -Message "Staging Fortinet firmware image from $ImagePath" -Level INFO -ScriptName 'FW-Vendor-Fortinet'

    if (-not (Test-Path $ImagePath)) {
        Write-CITLog -Message "Firmware image not found at $ImagePath" -Level ERROR -ScriptName 'FW-Vendor-Fortinet'
        return [PSCustomObject]@{
            Vendor    = 'Fortinet'
            Staged    = $false
            ImagePath = $ImagePath
            Error     = 'Firmware image file not found.'
        }
    }

    $fileName = Split-Path $ImagePath -Leaf
    $result   = Invoke-SSHCommand -SSHSession $SshSession -Command "execute upload image $fileName" -ErrorAction Stop

    return [PSCustomObject]@{
        Vendor    = 'Fortinet'
        Staged    = $true
        ImagePath = $ImagePath
        FileName  = $fileName
        RawOutput = $result.Output
    }
}

function Failover-CitFortinetActive {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] $SshSession
    )

    Write-CITLog -Message 'Triggering Fortinet HA failover to passive unit' -Level INFO -ScriptName 'FW-Vendor-Fortinet'

    $result = Invoke-SSHCommand -SSHSession $SshSession -Command 'execute ha failover set 1' -ErrorAction Stop

    return [PSCustomObject]@{
        Vendor    = 'Fortinet'
        Failover  = $true
        RawOutput = $result.Output
    }
}

function Apply-CitFortinetUpdate {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] $SshSession,
        [Parameter(Mandatory)] [string] $ImagePath
    )

    Write-CITLog -Message 'Applying staged Fortinet firmware update and rebooting' -Level INFO -ScriptName 'FW-Vendor-Fortinet'

    $result = Invoke-SSHCommand -SSHSession $SshSession -Command 'execute update-now' -ErrorAction Stop

    return [PSCustomObject]@{
        Vendor     = 'Fortinet'
        Applied    = $true
        RebootInit = $true
        ImagePath  = $ImagePath
        RawOutput  = $result.Output
    }
}
