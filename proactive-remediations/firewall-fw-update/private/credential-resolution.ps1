# credential-resolution.ps1
# Shared SSH credential resolver for firewall PIA scripts.
# Author:  Kyle Etter
# Created: 2026-06-13
# Updated: 2026-06-13
# Tested:  Windows 10 22H2, Windows 11 23H2
# Intune:  Proactive Remediation — Shared helper
# Notes:   Dot-sourced by FW-*.ps1. Resolution order: per-probe SSH key,
#          PIA secret env var, ITGlue API, then abort with NO_CREDENTIAL_SOURCE JSON.
#          This helper performs no network mutation; it only selects a credential source.

[CmdletBinding()]
param()

$ErrorActionPreference = 'Stop'
$WarningPreference     = 'Continue'

function Get-CitFirewallCredential {
    [CmdletBinding()]
    param(
        [Parameter()] [string] $KeyPath = ''
    )

    if (-not $KeyPath) {
        $defaultKey = Join-Path $env:USERPROFILE '.cit\fw-ssh.key'
        if (Test-Path $defaultKey) {
            $KeyPath = $defaultKey
        }
    }

    if ($KeyPath -and (Test-Path $KeyPath)) {
        Write-CITLog -Message "Credential source: per-probe SSH key at $KeyPath" -Level INFO -ScriptName 'FW-CredentialResolution'
        return [PSCustomObject]@{
            Source       = 'SSH_KEY'
            KeyPath      = $KeyPath
            Credential   = $null
            ErrorMessage = $null
        }
    }

    $piaCredential = $env:PIA_FW_CREDENTIAL
    if ($piaCredential) {
        try {
            $decodedBytes = [System.Convert]::FromBase64String($piaCredential)
            $decodedText  = [System.Text.Encoding]::UTF8.GetString($decodedBytes)
            $parts        = $decodedText -split ':', 2

            if ($parts.Length -ne 2 -or -not $parts[0] -or -not $parts[1]) {
                throw 'PIA_FW_CREDENTIAL decoded value is not in username:password format.'
            }

            $securePassword = ConvertTo-SecureString -String $parts[1] -AsPlainText -Force
            $credential     = New-Object System.Management.Automation.PSCredential($parts[0], $securePassword)

            Write-CITLog -Message 'Credential source: PIA_FW_CREDENTIAL env var' -Level INFO -ScriptName 'FW-CredentialResolution'
            return [PSCustomObject]@{
                Source       = 'PIA_SECRET'
                KeyPath      = $null
                Credential   = $credential
                ErrorMessage = $null
            }
        } catch {
            Write-CITLog -Message "Failed to decode PIA_FW_CREDENTIAL: $($_.Exception.Message)" -Level WARN -ScriptName 'FW-CredentialResolution'
        }
    }

    $itGlueToken = $env:ITGLUE_API_TOKEN
    $itGlueSub   = $env:ITGLUE_SUBDOMAIN
    if ($itGlueToken -and $itGlueSub) {
        Write-CITLog -Message 'Credential source: ITGlue requested but not implemented in v1' -Level WARN -ScriptName 'FW-CredentialResolution'
        throw 'ITGlue fallback not yet implemented; see .deploy-notes.md.'
    }

    Write-CITLog -Message 'No credential source available for firewall SSH' -Level ERROR -ScriptName 'FW-CredentialResolution'
    return [PSCustomObject]@{
        Source       = 'NO_CREDENTIAL_SOURCE'
        KeyPath      = $null
        Credential   = $null
        ErrorMessage = 'No SSH key, PIA_FW_CREDENTIAL, or ITGlue source available.'
    }
}
