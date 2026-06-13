# CIT-PIA-WUFix-DiskClean.ps1
# Frees disk space by running Disk Cleanup, DISM component cleanup, and temp folder cleanup.
# Author:  Kyle Etter
# Created: 2026-06-13
# Updated: 2026-06-13
# Tested:  Windows 10 22H2, Windows 11 23H2
# Intune:  Proactive Remediation — Remediation
# Notes:   Blast radius: removes temporary files and compacts the component store.
#          May delete old update files; subsequent patch scans may take longer.

[CmdletBinding()]
param()

$ErrorActionPreference = 'Stop'
$WarningPreference     = 'Continue'

. "$PSScriptRoot\..\..\platform\CIT-Logging.ps1" -ScriptName 'CIT-PIA-WUFix-DiskClean'

function Invoke-CitDiskCleanup {
    try {
        $keys = Get-ChildItem 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\VolumeCaches\*' -ErrorAction Stop
        foreach ($key in $keys) {
            New-ItemProperty -Path $key.PSPath -Name 'StateFlags0001' -Value 2 -PropertyType DWord -Force -ErrorAction SilentlyContinue | Out-Null
        }

        Start-Process -FilePath 'cleanmgr.exe' -ArgumentList '/sagerun:1' -Wait -WindowStyle Hidden -ErrorAction Stop
        return $true
    } catch {
        Write-CITLog -Message "Disk Cleanup failed: $($_.Exception.Message)" -Level WARN -ScriptName 'CIT-PIA-WUFix-DiskClean'
        return $false
    }
}

function Invoke-CitComponentCleanup {
    try {
        $dism = Start-Process -FilePath 'Dism.exe' -ArgumentList '/Online','/Cleanup-Image','/StartComponentCleanup','/ResetBase' -Wait -WindowStyle Hidden -PassThru -ErrorAction Stop
        if ($dism.ExitCode -ne 0) {
            Write-CITLog -Message "DISM component cleanup returned exit code $($dism.ExitCode)" -Level WARN -ScriptName 'CIT-PIA-WUFix-DiskClean'
            return $false
        }
        return $true
    } catch {
        Write-CITLog -Message "DISM component cleanup failed: $($_.Exception.Message)" -Level WARN -ScriptName 'CIT-PIA-WUFix-DiskClean'
        return $false
    }
}

function Remove-CitTempFiles {
    try {
        $paths = @("$env:WINDIR\Temp", $env:TEMP)
        foreach ($path in $paths) {
            if (Test-Path $path) {
                Get-ChildItem $path -Recurse -ErrorAction SilentlyContinue |
                    Remove-Item -Recurse -Force -ErrorAction SilentlyContinue
            }
        }
        return $true
    } catch {
        Write-CITLog -Message "Temp file cleanup encountered an error: $($_.Exception.Message)" -Level WARN -ScriptName 'CIT-PIA-WUFix-DiskClean'
        return $false
    }
}

try {
    Write-CITLog -Message 'Starting disk cleanup remediation' -Level INFO -ScriptName 'CIT-PIA-WUFix-DiskClean'

    $diskCleanResult = Invoke-CitDiskCleanup
    $componentResult = Invoke-CitComponentCleanup
    $tempResult      = Remove-CitTempFiles

    if (-not $diskCleanResult -and -not $componentResult -and -not $tempResult) {
        Write-CITLog -Message 'All cleanup attempts failed' -Level ERROR -ScriptName 'CIT-PIA-WUFix-DiskClean'
        exit 2
    }

    $freeAfter = [math]::Round((Get-PSDrive -Name C -ErrorAction Stop).Free / 1GB, 2)
    Write-CITLog -Message "Disk cleanup complete. Free space after: $freeAfter GB" -Level INFO -ScriptName 'CIT-PIA-WUFix-DiskClean'

    [PSCustomObject]@{
        FreeSpaceAfterGB = $freeAfter
        Status           = 'COMPLETE'
    } | ConvertTo-Json -Compress | Write-Output

    exit 0
} catch {
    Write-CITLog -Message "Disk cleanup remediation error: $($_.Exception.Message)" -Level ERROR -ScriptName 'CIT-PIA-WUFix-DiskClean'
    exit 2
}
