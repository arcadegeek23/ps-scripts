# FW-Backup.ps1
# Pre-upgrade config backup to probe share.
# Author:  Kyle Etter
# Created: 2026-06-13
# Updated: 2026-06-13
# Tested:  Windows 10 22H2, Windows 11 23H2
# Intune:  Proactive Remediation - Remediation
# Notes:   Writes backup to \\<probe>\FWBackups\<site>\<model>_<timestamp>.cfg|conf.
#          Aborts with exit 2 on backup failure. Idempotent: timestamped filenames.

[CmdletBinding()]
param(
    [Parameter(Mandatory)] [string] $FirewallAddress,
    [Parameter(Mandatory)] [ValidateSet('SonicWall','Fortinet')] [string] $Vendor,
    [Parameter(Mandatory)] [string] $SiteCode,
    [Parameter(Mandatory)] [string] $BackupRoot,
    [Parameter()] [string] $KeyPath = ''
)

$ErrorActionPreference = 'Stop'
$WarningPreference     = 'Continue'

. "$PSScriptRoot\..\..\platform\CIT-Logging.ps1" -ScriptName 'FW-Backup'
. "$PSScriptRoot\private\credential-resolution.ps1"

try {
    Write-CITLog -Message "Starting firewall backup for $Vendor at $FirewallAddress" -Level INFO -ScriptName 'FW-Backup'

    if (-not (Assert-CitPoshSsh -ScriptName 'FW-Backup')) {
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

    $session      = New-SSHSession @sessionParams
    $destination  = Join-Path $BackupRoot $SiteCode
    $backupResult = $null

    switch ($Vendor) {
        'SonicWall' { $backupResult = Backup-CitSonicWallConfig -SshSession $session -DestinationPath $destination }
        'Fortinet'  { $backupResult = Backup-CitFortinetConfig -SshSession $session -DestinationPath $destination }
    }

    Remove-SSHSession -SSHSession $session | Out-Null

    if (-not $backupResult.Success) {
        Write-CITLog -Message "Backup failed: $($backupResult.BackupError)" -Level ERROR -ScriptName 'FW-Backup'
        $backupResult | ConvertTo-Json -Compress | Write-Output
        exit 2
    }

    $backupResult | ConvertTo-Json -Compress | Write-Output
    Write-CITLog -Message "Backup complete: $($backupResult.FilePath)" -Level INFO -ScriptName 'FW-Backup'
    exit 0
} catch {
    Write-CITLog -Message "Backup error: $($_.Exception.Message)" -Level ERROR -ScriptName 'FW-Backup'
    [PSCustomObject]@{
        Action    = 'BACKUP_ERROR'
        Message   = $_.Exception.Message
        Vendor    = $Vendor
        Firewall  = $FirewallAddress
        Timestamp = (Get-Date).ToString('o')
    } | ConvertTo-Json -Compress | Write-Output
    exit 2
}
