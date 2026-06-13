# CIT-PIA-WUFix-Generic.ps1
# Performs a soft reset of Windows Update for generic patch-install failures.
# Author:  Kyle Etter
# Created: 2026-06-13
# Updated: 2026-06-13
# Tested:  Windows 10 22H2, Windows 11 23H2
# Intune:  Proactive Remediation — Remediation
# Notes:   Blast radius: clears the WU download cache and re-triggers scan/download/install.
#          Safer than the full component reset; try this before Branch C.

[CmdletBinding()]
param()

$ErrorActionPreference = 'Stop'
$WarningPreference     = 'Continue'

. "$PSScriptRoot\..\..\platform\CIT-Logging.ps1" -ScriptName 'CIT-PIA-WUFix-Generic'

function Stop-CitWuauserv {
    try {
        if ((Get-Service -Name 'wuauserv' -ErrorAction SilentlyContinue).Status -eq 'Running') {
            Stop-Service -Name 'wuauserv' -Force -ErrorAction Stop
            Write-CITLog -Message 'Stopped wuauserv' -Level INFO -ScriptName 'CIT-PIA-WUFix-Generic'
        }
        return $true
    } catch {
        Write-CITLog -Message "Failed to stop wuauserv: $($_.Exception.Message)" -Level WARN -ScriptName 'CIT-PIA-WUFix-Generic'
        return $false
    }
}

function Remove-CitWUDownloadCache {
    try {
        $downloadPath = 'C:\Windows\SoftwareDistribution\Download'
        if (Test-Path $downloadPath) {
            Get-ChildItem $downloadPath -Recurse -ErrorAction SilentlyContinue |
                Remove-Item -Recurse -Force -ErrorAction SilentlyContinue
            Write-CITLog -Message 'Cleared WU download cache' -Level INFO -ScriptName 'CIT-PIA-WUFix-Generic'
        }
        return $true
    } catch {
        Write-CITLog -Message "Failed to clear WU download cache: $($_.Exception.Message)" -Level WARN -ScriptName 'CIT-PIA-WUFix-Generic'
        return $false
    }
}

function Start-CitWuauserv {
    try {
        if ((Get-Service -Name 'wuauserv' -ErrorAction SilentlyContinue).Status -ne 'Running') {
            Start-Service -Name 'wuauserv' -ErrorAction Stop
            Write-CITLog -Message 'Started wuauserv' -Level INFO -ScriptName 'CIT-PIA-WUFix-Generic'
        }
        return $true
    } catch {
        Write-CITLog -Message "Failed to start wuauserv: $($_.Exception.Message)" -Level WARN -ScriptName 'CIT-PIA-WUFix-Generic'
        return $false
    }
}

function Invoke-CitUsoClientAction {
    param([string]$Action)

    try {
        $usoClient = Join-Path $env:windir 'System32\UsoClient.exe'
        if (Test-Path $usoClient) {
            Start-Process -FilePath $usoClient -ArgumentList $Action -Wait -WindowStyle Hidden -ErrorAction Stop
            Write-CITLog -Message "Triggered UsoClient $Action" -Level INFO -ScriptName 'CIT-PIA-WUFix-Generic'
        }
        return $true
    } catch {
        Write-CITLog -Message "UsoClient $Action failed: $($_.Exception.Message)" -Level WARN -ScriptName 'CIT-PIA-WUFix-Generic'
        return $false
    }
}

try {
    Write-CITLog -Message 'Starting generic WU reset remediation' -Level INFO -ScriptName 'CIT-PIA-WUFix-Generic'

    $stopped = Stop-CitWuauserv
    $cache   = Remove-CitWUDownloadCache
    $started = Start-CitWuauserv

    if (-not $started) {
        Write-CITLog -Message 'wuauserv could not be restarted' -Level ERROR -ScriptName 'CIT-PIA-WUFix-Generic'
        exit 2
    }

    Invoke-CitUsoClientAction -Action 'StartScan'
    Start-Sleep -Seconds 30
    Invoke-CitUsoClientAction -Action 'StartDownload'
    Invoke-CitUsoClientAction -Action 'StartInstall'

    Write-CITLog -Message 'Generic WU reset remediation complete' -Level INFO -ScriptName 'CIT-PIA-WUFix-Generic'

    [PSCustomObject]@{
        Status = 'COMPLETE'
    } | ConvertTo-Json -Compress | Write-Output

    exit 0
} catch {
    Write-CITLog -Message "Generic WU reset remediation error: $($_.Exception.Message)" -Level ERROR -ScriptName 'CIT-PIA-WUFix-Generic'
    exit 2
}
