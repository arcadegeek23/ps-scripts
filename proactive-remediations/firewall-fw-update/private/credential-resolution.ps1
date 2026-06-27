# credential-resolution.ps1
# Shared SSH credential resolver for firewall PIA scripts.
# Author:  Kyle Etter
# Created: 2026-06-13
# Updated: 2026-06-13
# Tested:  Windows 10 22H2, Windows 11 23H2
# Intune:  Proactive Remediation - Shared helper
# Notes:   Dot-sourced by FW-*.ps1. Resolution order: per-probe SSH key,
#          PIA secret env var, ITGlue API, then abort with NO_CREDENTIAL_SOURCE JSON.
#          This helper performs no network mutation; it only selects a credential source.

[CmdletBinding()]
param()

$ErrorActionPreference = 'Stop'
$WarningPreference     = 'Continue'

function Assert-CitPoshSsh {
    # Verify Posh-SSH is available to THIS process and import it. Under the Intune
    # agent (NT AUTHORITY\SYSTEM, non-interactive, sometimes 32-bit) a module
    # installed -Scope CurrentUser is invisible: it lives in the operator's
    # profile, not the SYSTEM profile. Posh-SSH must be installed AllUsers
    # (Install-Module Posh-SSH -Scope AllUsers). Detect and report rather than
    # crash with an opaque "New-SSHSession is not recognized" error.
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] [string] $ScriptName
    )

    if (Get-Command -Name 'New-SSHSession' -ErrorAction SilentlyContinue) {
        return $true
    }

    $available = Get-Module -ListAvailable -Name 'Posh-SSH' -ErrorAction SilentlyContinue
    if (-not $available) {
        Write-CITLog -Message 'Posh-SSH module not found for this context. Install it machine-wide: Install-Module Posh-SSH -Scope AllUsers (CurrentUser scope is invisible to the SYSTEM account the Intune agent runs as).' -Level ERROR -ScriptName $ScriptName
        return $false
    }

    try {
        Import-Module -Name 'Posh-SSH' -ErrorAction Stop
    } catch {
        Write-CITLog -Message "Posh-SSH is installed but failed to import: $($_.Exception.Message)" -Level ERROR -ScriptName $ScriptName
        return $false
    }

    if (Get-Command -Name 'New-SSHSession' -ErrorAction SilentlyContinue) {
        return $true
    }

    Write-CITLog -Message 'Posh-SSH imported but New-SSHSession is still unavailable.' -Level ERROR -ScriptName $ScriptName
    return $false
}

function Get-CitFirewallCredential {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSAvoidUsingConvertToSecureStringWithPlainText','',Justification='Secret is retrieved from a protected source (CIT_FW_SSH_* env var or a ProgramData credential file) and must be converted to a SecureString to construct the PSCredential required by Posh-SSH; no plaintext secret is hardcoded or persisted.')]
    [CmdletBinding()]
    param(
        [Parameter()] [string] $KeyPath = ''
    )

    if (-not $KeyPath) {
        # Resolve the default key from a SYSTEM-stable location. Under the Intune
        # agent the script runs as NT AUTHORITY\SYSTEM, where $env:USERPROFILE
        # resolves to ...\config\systemprofile and any operator key placed in a
        # real user profile is invisible. Use C:\ProgramData\CIT (machine-wide,
        # readable by SYSTEM) and allow an explicit env-var override for probes
        # that stage the key elsewhere. The layered model below is unchanged.
        $defaultKey = $env:CIT_FW_SSH_KEY
        if (-not $defaultKey) {
            $programData = $env:ProgramData
            if (-not $programData) { $programData = 'C:\ProgramData' }
            $defaultKey = Join-Path $programData 'CIT\fw-ssh.key'
        }
        if (Test-Path $defaultKey) {
            $KeyPath = $defaultKey
        }
    }

    if ($KeyPath -and (Test-Path $KeyPath)) {
        # Posh-SSH key auth still needs a username; New-SSHSession -KeyFile must
        # be paired with -Credential (or -Username) or the SSH handshake fails
        # non-interactively. Default to 'admin' and allow a probe override via
        # CIT_FW_SSH_USER so callers can attach the username to the key file.
        $keyUser = $env:CIT_FW_SSH_USER
        if (-not $keyUser) { $keyUser = 'admin' }
        Write-CITLog -Message "Credential source: per-probe SSH key at $KeyPath (user $keyUser)" -Level INFO -ScriptName 'FW-CredentialResolution'
        return [PSCustomObject]@{
            Source       = 'SSH_KEY'
            KeyPath      = $KeyPath
            Username     = $keyUser
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
