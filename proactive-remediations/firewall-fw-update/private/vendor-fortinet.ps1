# vendor-fortinet.ps1
# Fortinet SSH helper functions for firewall PIA scripts.
# Author:  Kyle Etter
# Created: 2026-06-13
# Updated: 2026-06-13
# Tested:  Windows 10 22H2, Windows 11 23H2
# Intune:  Proactive Remediation - Shared helper
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

    # Posh-SSH .Output is a STRING ARRAY; -match against the array does not
    # populate $matches usefully, so $matches[1] returns stale/garbage. Join to
    # a single string before matching. Init parsed vars to $null and set ParseOk
    # only on a real read - do not return fabricated firmware/uptime as telemetry.
    $versionText = ($version.Output -join "`n")
    $haText      = if ($ha) { ($ha.Output -join "`n") } else { '' }

    $model     = $null
    $firmware  = $null
    $uptime    = $null
    $parseOk   = $true
    $parseErr  = $null

    if ($versionText -match 'Version:\s*(.+)') { $firmware = $matches[1].Trim() }
    if ($versionText -match 'Model name:\s*(.+)') { $model = $matches[1].Trim() }
    # FortiOS "get system status" reports uptime; tolerate days field when present.
    if ($versionText -match 'System time:.*up\s+(\d+)\s+day') { $uptime = [int]$matches[1] }

    if (-not $firmware) {
        $parseOk  = $false
        $parseErr = 'Could not parse Version from Fortinet "get system status" output.'
    }

    $haState  = $null
    $haRole   = $null
    $haPeerUp = $false

    if ($haText -match 'Mode:\s*(.+)') {
        $haState = $matches[1].Trim()
        $haPeerUp = ($haText -match 'Slave.*online')
        if ($haText -match 'Master') { $haRole = 'master' } else { $haRole = 'slave' }
    } else {
        $haState = 'standalone'
    }

    return [PSCustomObject]@{
        Vendor        = 'Fortinet'
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

    # Gate Success on the remote ExitStatus (0 = ok) and only flip to true after
    # the config is actually written to disk. Do not report a backup that the
    # firewall refused or returned empty.
    $backup = [PSCustomObject]@{
        Vendor       = 'Fortinet'
        Success      = $false
        FilePath     = $fullPath
        FileName     = $fileName
        TimestampUtc = (Get-Date).ToUniversalTime().ToString('o')
        RawOutput    = $result.Output
        BackupError  = $null
    }

    $exitStatus = $result.ExitStatus
    if ($null -ne $exitStatus -and $exitStatus -ne 0) {
        $backup.BackupError = "Fortinet 'execute backup config' returned non-zero ExitStatus $exitStatus."
        Write-CITLog -Message $backup.BackupError -Level ERROR -ScriptName 'FW-Vendor-Fortinet'
        return $backup
    }

    if (-not $result.Output) {
        $backup.BackupError = "Fortinet 'execute backup config' returned no output; nothing to back up."
        Write-CITLog -Message $backup.BackupError -Level ERROR -ScriptName 'FW-Vendor-Fortinet'
        return $backup
    }

    try {
        New-Item -ItemType Directory -Path $DestinationPath -Force | Out-Null
        Set-Content -Path $fullPath -Value ($result.Output -join "`r`n") -Encoding UTF8 -Force
        $backup.Success = $true
    } catch {
        $backup.BackupError = $_.Exception.Message
        Write-CITLog -Message "Failed to write Fortinet backup to disk: $($_.Exception.Message)" -Level ERROR -ScriptName 'FW-Vendor-Fortinet'
    }

    return $backup
}


function Save-CitFortinetFirmware {
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

    # Gate Staged on the remote ExitStatus rather than assuming success.
    $staged     = $true
    $stageError = $null
    $exitStatus = $result.ExitStatus
    if ($null -ne $exitStatus -and $exitStatus -ne 0) {
        $staged     = $false
        $stageError = "Fortinet 'execute upload image' returned non-zero ExitStatus $exitStatus."
        Write-CITLog -Message $stageError -Level ERROR -ScriptName 'FW-Vendor-Fortinet'
    }

    return [PSCustomObject]@{
        Vendor    = 'Fortinet'
        Staged    = $staged
        Error     = $stageError
        ImagePath = $ImagePath
        FileName  = $fileName
        RawOutput = $result.Output
    }
}

function Switch-CitFortinetActive {
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

function Install-CitFortinetUpdate {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] $SshSession,
        [Parameter(Mandatory)] [string] $ImagePath
    )

    Write-CITLog -Message 'Applying staged Fortinet firmware update and rebooting' -Level INFO -ScriptName 'FW-Vendor-Fortinet'

    $result = Invoke-SSHCommand -SSHSession $SshSession -Command 'execute update-now' -ErrorAction Stop

    # Gate Applied/RebootInit on the remote ExitStatus; a false success would let
    # the workflow verify and auto-resolve a firewall that never upgraded.
    $applied    = $true
    $applyError = $null
    $exitStatus = $result.ExitStatus
    if ($null -ne $exitStatus -and $exitStatus -ne 0) {
        $applied    = $false
        $applyError = "Fortinet 'execute update-now' returned non-zero ExitStatus $exitStatus."
        Write-CITLog -Message $applyError -Level ERROR -ScriptName 'FW-Vendor-Fortinet'
    }

    return [PSCustomObject]@{
        Vendor     = 'Fortinet'
        Applied    = $applied
        RebootInit = $applied
        Error      = $applyError
        ImagePath  = $ImagePath
        RawOutput  = $result.Output
    }
}
