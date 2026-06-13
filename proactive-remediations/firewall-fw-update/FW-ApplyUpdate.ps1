# FW-ApplyUpdate.ps1
# Triggers install of staged firmware image and reboots firewall.
# Author:  Kyle Etter
# Created: 2026-06-13
# Updated: 2026-06-13
# Tested:  Windows 10 22H2, Windows 11 23H2
# Intune:  Proactive Remediation — Remediation
# Notes:   Pre-flight gate: requires -MaintenanceWindow or outside business hours.
#          HA-aware: active unit fails over to passive before upgrade.
#          Single-unit firewalls abort with NEEDS_CHANGE_WINDOW unless flagged.

[CmdletBinding()]
param(
    [Parameter(Mandatory)] [string] $FirewallAddress,
    [Parameter(Mandatory)] [ValidateSet('SonicWall','Fortinet')] [string] $Vendor,
    [Parameter(Mandatory)] [string] $ImagePath,
    [Parameter()] [switch] $MaintenanceWindow,
    [Parameter()] [int] $BusinessHoursStart = 6,
    [Parameter()] [int] $BusinessHoursEnd   = 22,
    [Parameter()] [string] $KeyPath = '',
    [Parameter()] [switch] $AllowSingleUnitWithoutWindow
)

$ErrorActionPreference = 'Stop'
$WarningPreference     = 'Continue'

. "$PSScriptRoot\..\..\platform\CIT-Logging.ps1" -ScriptName 'FW-ApplyUpdate'
. "$PSScriptRoot\private\credential-resolution.ps1"

function Test-CitMaintenanceWindow {
    param(
        [Parameter(Mandatory)] [int] $StartHour,
        [Parameter(Mandatory)] [int] $EndHour
    )

    $now = Get-Date
    $hour = $now.Hour
    return ($hour -lt $StartHour -or $hour -ge $EndHour)
}

try {
    Write-CITLog -Message "Starting firmware apply for $Vendor at $FirewallAddress" -Level INFO -ScriptName 'FW-ApplyUpdate'

    if (-not $MaintenanceWindow -and -not (Test-CitMaintenanceWindow -StartHour $BusinessHoursStart -EndHour $BusinessHoursEnd)) {
        [PSCustomObject]@{
            Action         = 'SCHEDULE_VIA_HALOPSA'
            Message        = 'Current time is within business hours. Use -MaintenanceWindow or schedule via HaloPSA.'
            BusinessWindow = "$BusinessHoursStart`:00 - $BusinessHoursEnd`:00"
            Timestamp      = (Get-Date).ToString('o')
        } | ConvertTo-Json -Compress | Write-Output
        Write-CITLog -Message 'Apply aborted: outside maintenance window' -Level WARN -ScriptName 'FW-ApplyUpdate'
        exit 0
    }

    $credential = Get-CitFirewallCredential -KeyPath $KeyPath
    if ($credential.Source -eq 'NO_CREDENTIAL_SOURCE') {
        [PSCustomObject]@{
            Action    = 'NO_CREDENTIAL_SOURCE'
            Message   = $credential.ErrorMessage
            Vendor    = $Vendor
            Firewall  = $FirewallAddress
            Timestamp = (Get-Date).ToString('o')
        } | ConvertTo-Json -Compress | Write-Output
        exit 2
    }

    . "$PSScriptRoot\private\vendor-$($Vendor.ToLower()).ps1"

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
    }

    if ($diag.HARole -eq 'active' -and $diag.HAPeerPresent) {
        Write-CITLog -Message 'HA active unit with peer present; failing over before upgrade' -Level INFO -ScriptName 'FW-ApplyUpdate'
        switch ($Vendor) {
            'SonicWall' { $null = Failover-CitSonicWallActive -SshSession $session }
            'Fortinet'  { $null = Failover-CitFortinetActive -SshSession $session }
        }
    }

    if (-not $diag.HAPeerPresent -and -not $AllowSingleUnitWithoutWindow) {
        Remove-SSHSession -SSHSession $session | Out-Null
        [PSCustomObject]@{
            Action    = 'NEEDS_CHANGE_WINDOW'
            Message   = 'Single-unit firewall requires an explicit change window. Use -AllowSingleUnitWithoutWindow after customer approval.'
            Vendor    = $Vendor
            Firewall  = $FirewallAddress
            Timestamp = (Get-Date).ToString('o')
        } | ConvertTo-Json -Compress | Write-Output
        Write-CITLog -Message 'Apply aborted: single-unit firewall needs change window' -Level WARN -ScriptName 'FW-ApplyUpdate'
        exit 0
    }

    $applyResult = $null
    switch ($Vendor) {
        'SonicWall' { $applyResult = Apply-CitSonicWallUpdate -SshSession $session -ImagePath $ImagePath }
        'Fortinet'  { $applyResult = Apply-CitFortinetUpdate -SshSession $session -ImagePath $ImagePath }
    }

    Remove-SSHSession -SSHSession $session | Out-Null

    $applyResult | ConvertTo-Json -Compress | Write-Output
    Write-CITLog -Message 'Firmware apply initiated; firewall rebooting' -Level INFO -ScriptName 'FW-ApplyUpdate'
    exit 0
} catch {
    Write-CITLog -Message "Apply update error: $($_.Exception.Message)" -Level ERROR -ScriptName 'FW-ApplyUpdate'
    [PSCustomObject]@{
        Action    = 'APPLY_ERROR'
        Message   = $_.Exception.Message
        Vendor    = $Vendor
        Firewall  = $FirewallAddress
        Timestamp = (Get-Date).ToString('o')
    } | ConvertTo-Json -Compress | Write-Output
    exit 2
}
