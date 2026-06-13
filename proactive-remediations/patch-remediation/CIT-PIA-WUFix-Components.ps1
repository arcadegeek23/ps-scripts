# CIT-PIA-WUFix-Components.ps1
# Resets Windows Update components, repairs the component store, and re-scans.
# Author:  Kyle Etter
# Created: 2026-06-13
# Updated: 2026-06-13
# Tested:  Windows 10 22H2, Windows 11 23H2
# Intune:  Proactive Remediation — Remediation
# Notes:   Blast radius: renames SoftwareDistribution and catroot2 (forces WU cache rebuild).
#          DISM/SFC may take 15-30 minutes. A reboot is recommended after completion.

[CmdletBinding()]
param()

$ErrorActionPreference = 'Stop'
$WarningPreference     = 'Continue'

. "$PSScriptRoot\..\..\platform\CIT-Logging.ps1" -ScriptName 'CIT-PIA-WUFix-Components'

$services = @('cryptsvc', 'bits', 'msiserver', 'wuauserv')

function Stop-CitWUServices {
    try {
        foreach ($service in $services) {
            if ((Get-Service -Name $service -ErrorAction SilentlyContinue).Status -eq 'Running') {
                Stop-Service -Name $service -Force -ErrorAction Stop
                Write-CITLog -Message "Stopped service: $service" -Level INFO -ScriptName 'CIT-PIA-WUFix-Components'
            }
        }
        return $true
    } catch {
        Write-CITLog -Message "Failed to stop WU services: $($_.Exception.Message)" -Level WARN -ScriptName 'CIT-PIA-WUFix-Components'
        return $false
    }
}

function Rename-CitWUFolders {
    try {
        $folders = @(
            @{ Path = 'C:\Windows\SoftwareDistribution'; NewName = 'SoftwareDistribution.old' },
            @{ Path = 'C:\Windows\System32\catroot2'; NewName = 'catroot2.old' }
        )

        foreach ($folder in $folders) {
            if (Test-Path $folder.Path) {
                $newPath = Join-Path (Split-Path $folder.Path -Parent) $folder.NewName
                if (Test-Path $newPath) {
                    Remove-Item $newPath -Recurse -Force -ErrorAction Stop
                }
                Rename-Item -Path $folder.Path -NewName $folder.NewName -Force -ErrorAction Stop
                Write-CITLog -Message "Renamed $($folder.Path) to $($folder.NewName)" -Level INFO -ScriptName 'CIT-PIA-WUFix-Components'
            }
        }
        return $true
    } catch {
        Write-CITLog -Message "Failed to rename WU folders: $($_.Exception.Message)" -Level WARN -ScriptName 'CIT-PIA-WUFix-Components'
        return $false
    }
}

function Start-CitWUServices {
    try {
        foreach ($service in $services) {
            if ((Get-Service -Name $service -ErrorAction SilentlyContinue).Status -ne 'Running') {
                Start-Service -Name $service -ErrorAction Stop
                Write-CITLog -Message "Started service: $service" -Level INFO -ScriptName 'CIT-PIA-WUFix-Components'
            }
        }
        return $true
    } catch {
        Write-CITLog -Message "Failed to start WU services: $($_.Exception.Message)" -Level WARN -ScriptName 'CIT-PIA-WUFix-Components'
        return $false
    }
}

function Invoke-CitDismRestoreHealth {
    try {
        $dism = Start-Process -FilePath 'Dism.exe' -ArgumentList '/Online','/Cleanup-Image','/RestoreHealth' -Wait -WindowStyle Hidden -PassThru -ErrorAction Stop
        if ($dism.ExitCode -ne 0) {
            Write-CITLog -Message "DISM /RestoreHealth returned exit code $($dism.ExitCode)" -Level WARN -ScriptName 'CIT-PIA-WUFix-Components'
            return $false
        }
        return $true
    } catch {
        Write-CITLog -Message "DISM /RestoreHealth failed: $($_.Exception.Message)" -Level WARN -ScriptName 'CIT-PIA-WUFix-Components'
        return $false
    }
}

function Invoke-CitSFC {
    try {
        $sfc = Start-Process -FilePath 'sfc.exe' -ArgumentList '/scannow' -Wait -WindowStyle Hidden -PassThru -ErrorAction Stop
        if ($sfc.ExitCode -ne 0) {
            Write-CITLog -Message "SFC /scannow returned exit code $($sfc.ExitCode)" -Level WARN -ScriptName 'CIT-PIA-WUFix-Components'
            return $false
        }
        return $true
    } catch {
        Write-CITLog -Message "SFC /scannow failed: $($_.Exception.Message)" -Level WARN -ScriptName 'CIT-PIA-WUFix-Components'
        return $false
    }
}

function Invoke-CitWUScan {
    try {
        $usoClient = Join-Path $env:windir 'System32\UsoClient.exe'
        if (Test-Path $usoClient) {
            Start-Process -FilePath $usoClient -ArgumentList 'StartScan' -Wait -WindowStyle Hidden -ErrorAction Stop
            Write-CITLog -Message 'Triggered WU scan via UsoClient' -Level INFO -ScriptName 'CIT-PIA-WUFix-Components'
        }
        return $true
    } catch {
        Write-CITLog -Message "UsoClient StartScan failed: $($_.Exception.Message)" -Level WARN -ScriptName 'CIT-PIA-WUFix-Components'
        return $false
    }
}

try {
    Write-CITLog -Message 'Starting WU component reset remediation' -Level INFO -ScriptName 'CIT-PIA-WUFix-Components'

    $stopped = Stop-CitWUServices
    $renamed = Rename-CitWUFolders
    $dism    = Invoke-CitDismRestoreHealth
    $sfc     = Invoke-CitSFC
    $started = Start-CitWUServices
    $scan    = Invoke-CitWUScan

    if (-not $started) {
        Write-CITLog -Message 'WU services could not be restarted' -Level ERROR -ScriptName 'CIT-PIA-WUFix-Components'
        exit 2
    }

    Write-CITLog -Message 'WU component reset remediation complete' -Level INFO -ScriptName 'CIT-PIA-WUFix-Components'

    [PSCustomObject]@{
        Status           = 'COMPLETE'
        RebootRecommended = $true
    } | ConvertTo-Json -Compress | Write-Output

    exit 0
} catch {
    Write-CITLog -Message "WU component reset remediation error: $($_.Exception.Message)" -Level ERROR -ScriptName 'CIT-PIA-WUFix-Components'
    exit 2
}
