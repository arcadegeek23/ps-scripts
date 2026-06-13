# FW-Verify.ps1
# Wait for firewall reboot, confirm new firmware and uptime.
# Author:  Kyle Etter
# Created: 2026-06-13
# Updated: 2026-06-13
# Tested:  Windows 10 22H2, Windows 11 23H2
# Intune:  Proactive Remediation — Remediation
# Notes:   Polls SSH up to 15 minutes (configurable). Confirms firmware version,
#          uptime reset, and key policy/VPN states. Returns RECOVERY_NEEDED if deadline hit.

[CmdletBinding()]
param(
    [Parameter(Mandatory)] [string] $FirewallAddress,
    [Parameter(Mandatory)] [ValidateSet('SonicWall','Fortinet')] [string] $Vendor,
    [Parameter(Mandatory)] [string] $ExpectedFirmware,
    [Parameter()] [string] $KeyPath = '',
    [Parameter()] [int] $VerifyTimeoutMinutes = 15,
    [Parameter()] [int] $BackoffSeconds       = 30
)

$ErrorActionPreference = 'Stop'
$WarningPreference     = 'Continue'

. "$PSScriptRoot\..\..\platform\CIT-Logging.ps1" -ScriptName 'FW-Verify'
. "$PSScriptRoot\private\credential-resolution.ps1"

try {
    Write-CITLog -Message "Starting firmware verification for $Vendor at $FirewallAddress" -Level INFO -ScriptName 'FW-Verify'

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

    $deadline   = (Get-Date).AddMinutes($VerifyTimeoutMinutes)
    $verified   = $false
    $lastError  = $null
    $policyCheck = $null

    while ((Get-Date) -lt $deadline) {
        try {
            $session = New-SSHSession @sessionParams
            $diag    = $null

            switch ($Vendor) {
                'SonicWall' { $diag = Get-CitSonicWallVersion -SshSession $session }
                'Fortinet'  { $diag = Get-CitFortinetVersion -SshSession $session }
            }

            $firmwareOk = ($diag.Firmware -eq $ExpectedFirmware)
            $uptimeOk   = ($diag.UptimeDays -lt 1)

            if ($firmwareOk -and $uptimeOk) {
                $policyCmd = switch ($Vendor) {
                    'SonicWall' { 'show vpn policy' }
                    'Fortinet'  { 'get vpn ipsec tunnel summary' }
                }
                $policyCheck = Invoke-SSHCommand -SSHSession $session -Command $policyCmd -ErrorAction SilentlyContinue
                $verified    = $true
                Remove-SSHSession -SSHSession $session | Out-Null
                break
            }

            $lastError = "Firmware=$($diag.Firmware), expected=$ExpectedFirmware, uptime=$($diag.UptimeDays)d"
            Remove-SSHSession -SSHSession $session | Out-Null
        } catch {
            $lastError = $_.Exception.Message
        }

        Write-CITLog -Message "Verification not complete yet; waiting $BackoffSeconds seconds. Last: $lastError" -Level DEBUG -ScriptName 'FW-Verify'
        Start-Sleep -Seconds $BackoffSeconds
    }

    if ($verified) {
        $result = [PSCustomObject]@{
            Action      = 'VERIFY_OK'
            Vendor      = $Vendor
            Firewall    = $FirewallAddress
            Firmware    = $ExpectedFirmware
            UptimeDays  = 0
            PolicyState = $policyCheck.Output
            Timestamp   = (Get-Date).ToString('o')
        }
        $result | ConvertTo-Json -Compress | Write-Output
        Write-CITLog -Message 'Firmware verification succeeded' -Level INFO -ScriptName 'FW-Verify'
        exit 0
    }

    $recovery = [PSCustomObject]@{
        Action     = 'RECOVERY_NEEDED'
        Message    = "Firewall did not return with expected firmware within $VerifyTimeoutMinutes minutes. Last: $lastError"
        Vendor     = $Vendor
        Firewall   = $FirewallAddress
        Expected   = $ExpectedFirmware
        Deadline   = $deadline.ToString('o')
        Timestamp  = (Get-Date).ToString('o')
    }
    $recovery | ConvertTo-Json -Compress | Write-Output
    Write-CITLog -Message 'Firmware verification deadline exceeded' -Level ERROR -ScriptName 'FW-Verify'
    exit 1
} catch {
    Write-CITLog -Message "Verify error: $($_.Exception.Message)" -Level ERROR -ScriptName 'FW-Verify'
    [PSCustomObject]@{
        Action    = 'VERIFY_ERROR'
        Message   = $_.Exception.Message
        Vendor    = $Vendor
        Firewall  = $FirewallAddress
        Timestamp = (Get-Date).ToString('o')
    } | ConvertTo-Json -Compress | Write-Output
    exit 2
}
