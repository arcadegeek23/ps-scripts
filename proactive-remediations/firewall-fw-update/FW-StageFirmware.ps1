# FW-StageFirmware.ps1
# SCP firmware image to firewall without installing.
# Author:  Kyle Etter
# Created: 2026-06-13
# Updated: 2026-06-13
# Tested:  Windows 10 22H2, Windows 11 23H2
# Intune:  Proactive Remediation — Remediation
# Notes:   Uploads image to firewall storage only. Does not trigger install or reboot.
#          Idempotent: re-upload overwrites same filename on the firewall.

[CmdletBinding()]
param(
    [Parameter(Mandatory)] [string] $FirewallAddress,
    [Parameter(Mandatory)] [ValidateSet('SonicWall','Fortinet')] [string] $Vendor,
    [Parameter(Mandatory)] [string] $ImagePath,
    [Parameter()] [string] $KeyPath = ''
)

$ErrorActionPreference = 'Stop'
$WarningPreference     = 'Continue'

. "$PSScriptRoot\..\..\platform\CIT-Logging.ps1" -ScriptName 'FW-StageFirmware'
. "$PSScriptRoot\private\credential-resolution.ps1"

try {
    Write-CITLog -Message "Starting firmware staging for $Vendor at $FirewallAddress" -Level INFO -ScriptName 'FW-StageFirmware'

    if (-not (Test-Path $ImagePath)) {
        Write-CITLog -Message "Firmware image not found at $ImagePath" -Level ERROR -ScriptName 'FW-StageFirmware'
        [PSCustomObject]@{
            Action    = 'IMAGE_NOT_FOUND'
            ImagePath = $ImagePath
            Timestamp = (Get-Date).ToString('o')
        } | ConvertTo-Json -Compress | Write-Output
        exit 2
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

    $stageResult = $null
    switch ($Vendor) {
        'SonicWall' { $stageResult = Stage-CitSonicWallFirmware -SshSession $session -ImagePath $ImagePath }
        'Fortinet'  { $stageResult = Stage-CitFortinetFirmware -SshSession $session -ImagePath $ImagePath }
    }

    Remove-SSHSession -SSHSession $session | Out-Null

    $stageResult | ConvertTo-Json -Compress | Write-Output

    if (-not $stageResult.Staged) {
        Write-CITLog -Message "Firmware staging failed: $($stageResult.Error)" -Level ERROR -ScriptName 'FW-StageFirmware'
        exit 2
    }

    Write-CITLog -Message "Firmware staged successfully: $($stageResult.FileName)" -Level INFO -ScriptName 'FW-StageFirmware'
    exit 0
} catch {
    Write-CITLog -Message "Firmware staging error: $($_.Exception.Message)" -Level ERROR -ScriptName 'FW-StageFirmware'
    [PSCustomObject]@{
        Action    = 'STAGE_ERROR'
        Message   = $_.Exception.Message
        Vendor    = $Vendor
        Firewall  = $FirewallAddress
        ImagePath = $ImagePath
        Timestamp = (Get-Date).ToString('o')
    } | ConvertTo-Json -Compress | Write-Output
    exit 2
}
