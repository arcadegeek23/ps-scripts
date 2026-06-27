#Requires -Version 5.1
# FW-Diag.ps1
# SSH to firewall, gather model/firmware/HA/uptime JSON.
# Author:  Kyle Etter
# Created: 2026-06-13
# Updated: 2026-06-13
# Tested:  Windows 10 22H2, Windows 11 23H2
# Intune:  Proactive Remediation - Diagnostic
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

    if (-not $TargetFirmware) {
        # An empty TargetFirmware (the default) must NEVER be interpreted as
        # "firmware healthy / exit 0". With no baseline to compare against the
        # diagnostic cannot judge compliance, so report a contract error and a
        # non-success exit instead of silently passing every firewall.
        Write-CITLog -Message 'No TargetFirmware supplied; cannot establish a baseline.' -Level ERROR -ScriptName 'FW-Diag'
        [PSCustomObject]@{
            Action    = 'NO_TARGET_BASELINE'
            Message   = 'No TargetFirmware was supplied; cannot determine whether an upgrade is needed. Pass -TargetFirmware with the approved baseline version.'
            Vendor    = $Vendor
            Firewall  = $FirewallAddress
            Timestamp = (Get-Date).ToString('o')
        } | ConvertTo-Json -Compress | Write-Output
        exit 2
    }

    if (-not (Assert-CitPoshSsh -ScriptName 'FW-Diag')) {
        [PSCustomObject]@{
            Action    = 'POSH_SSH_UNAVAILABLE'
            Message   = 'Posh-SSH module is not available to this process. Install it machine-wide: Install-Module Posh-SSH -Scope AllUsers.'
            Vendor    = $Vendor
            Firewall  = $FirewallAddress
            Timestamp = (Get-Date).ToString('o')
        } | ConvertTo-Json -Compress | Write-Output
        exit 2
    }

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
        AcceptKey    = $true
        ErrorAction  = 'Stop'
    }
    if ($credential.Source -eq 'SSH_KEY') {
        $sessionParams['KeyFile'] = $credential.KeyPath
        $securePassword = New-Object System.Security.SecureString
        $sessionParams['Credential'] = New-Object System.Management.Automation.PSCredential($credential.Username, $securePassword)
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

    # If the read was not implemented / could not be parsed, do not pretend the
    # firewall is healthy. Report that we cannot verify and exit non-success.
    if (-not $diag.ParseOk) {
        Write-CITLog -Message "Could not parse firmware/version from device: $($diag.ParseError)" -Level ERROR -ScriptName 'FW-Diag'
        [PSCustomObject]@{
            Action    = 'NOT_IMPLEMENTED'
            Message   = "Vendor telemetry could not be read or parsed: $($diag.ParseError)"
            Vendor    = $Vendor
            Firewall  = $FirewallAddress
            Timestamp = (Get-Date).ToString('o')
        } | ConvertTo-Json -Compress | Write-Output
        exit 2
    }

    $upgradeNeeded = $false
    if ($diag.Firmware -ne $TargetFirmware) {
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
