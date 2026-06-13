# FW-Diag.ps1
# SSH to firewall, gather model/firmware/HA/uptime JSON.
# Author:  Kyle Etter
# Created: 2026-06-13
# Updated: 2026-06-13
# Tested:  Windows 10 22H2, Windows 11 23H2
# Intune:  Proactive Remediation — Diagnostic
# Notes:   No mutation. Exit 0 = healthy firmware, 1 = upgrade needed, 2+ = error.
#          Supports SonicWall and Fortinet; WatchGuard is phase 2.

[CmdletBinding()]
param(
    [Parameter(Mandatory)] [string] $FirewallAddress,
    [Parameter(Mandatory)] [ValidateSet('SonicWall','Fortinet','WatchGuard')] [string] $Vendor,
    [Parameter()] [string] $KeyPath = '',
    [Parameter()] [string] $TargetFirmware = ''
)

$ErrorActionPreference = 'Stop'
$WarningPreference     = 'Continue'

. "$PSScriptRoot\..\..\platform\CIT-Logging.ps1" -ScriptName 'FW-Diag'
. "$PSScriptRoot\private\credential-resolution.ps1"

try {
    Write-CITLog -Message "Starting firewall diagnostic for $Vendor at $FirewallAddress" -Level INFO -ScriptName 'FW-Diag'

    $credential = Get-CitFirewallCredential -KeyPath $KeyPath
    if ($credential.Source -eq 'NO_CREDENTIAL_SOURCE') {
        [PSCustomObject]@{
            Action      = 'NO_CREDENTIAL_SOURCE'
            Message     = $credential.ErrorMessage
            Vendor      = $Vendor
            Firewall    = $FirewallAddress
            Timestamp   = (Get-Date).ToString('o')
        } | ConvertTo-Json -Compress | Write-Output
        exit 2
    }

    $vendorPartial = "$PSScriptRoot\private\vendor-$($Vendor.ToLower()).ps1"
    if (-not (Test-Path $vendorPartial)) {
        Write-CITLog -Message "Vendor partial not found: $vendorPartial" -Level ERROR -ScriptName 'FW-Diag'
        exit 2
    }

    . $vendorPartial

    $sessionParams = @{
        ComputerName = $FirewallAddress
        Port         = 22
        ErrorAction  = 'Stop'
    }
    if ($credential.Source -eq 'SSH_KEY') {
        $sessionParams['KeyFile'] = $credential.KeyPath
    } else {
        $sessionParams['Credential'] = $credential.Credential
    }

    $session = New-SSHSession @sessionParams

    $diag = $null
    switch ($Vendor) {
        'SonicWall' { $diag = Get-CitSonicWallVersion -SshSession $session }
        'Fortinet'  { $diag = Get-CitFortinetVersion -SshSession $session }
        default     { throw "Unsupported vendor: $Vendor" }
    }

    Remove-SSHSession -SSHSession $session | Out-Null

    $upgradeNeeded = $false
    if ($TargetFirmware -and $diag.Firmware -ne $TargetFirmware) {
        $upgradeNeeded = $true
    }

    $result = [PSCustomObject]@{
        Vendor        = $diag.Vendor
        Model         = $diag.Model
        Firmware      = $diag.Firmware
        UptimeDays    = $diag.UptimeDays
        HAState       = $diag.HAState
        HARole        = $diag.HARole
        HAPeerPresent = $diag.HAPeerPresent
        UpgradeNeeded = $upgradeNeeded
        TargetFirmware = $TargetFirmware
        Timestamp     = (Get-Date).ToString('o')
    }

    $result | ConvertTo-Json -Compress | Write-Output

    if ($upgradeNeeded) {
        Write-CITLog -Message "Upgrade needed: current $($diag.Firmware), target $TargetFirmware" -Level INFO -ScriptName 'FW-Diag'
        exit 1
    }

    Write-CITLog -Message 'Diagnostic complete: firewall healthy' -Level INFO -ScriptName 'FW-Diag'
    exit 0
} catch {
    Write-CITLog -Message "Diagnostic error: $($_.Exception.Message)" -Level ERROR -ScriptName 'FW-Diag'
    [PSCustomObject]@{
        Action    = 'DIAG_ERROR'
        Message   = $_.Exception.Message
        Vendor    = $Vendor
        Firewall  = $FirewallAddress
        Timestamp = (Get-Date).ToString('o')
    } | ConvertTo-Json -Compress | Write-Output
    exit 2
}
