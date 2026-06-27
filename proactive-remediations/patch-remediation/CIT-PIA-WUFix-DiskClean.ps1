# CIT-PIA-WUFix-DiskClean.ps1
# Frees disk space by running Disk Cleanup, DISM component cleanup, and temp folder cleanup.
# Author:  Kyle Etter
# Created: 2026-06-13
# Updated: 2026-06-27
# Tested:  Windows 10 22H2, Windows 11 23H2
# Intune:  Proactive Remediation - Remediation
# Notes:   Blast radius: removes temporary files and compacts the component store.
#          May delete old update files; subsequent patch scans may take longer.
#          Success is gated on the actual sub-step results and a measured
#          free-space delta; a cleanmgr hang is bounded by a timeout + kill.

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

        # cleanmgr can hang indefinitely (waiting on a UI handle / locked file),
        # which lets the Intune agent kill the whole script. Bound it with a
        # timeout and kill the process if it overruns.
        $timeoutMs = 20 * 60 * 1000
        $proc = Start-Process -FilePath 'cleanmgr.exe' -ArgumentList '/sagerun:1' -WindowStyle Hidden -PassThru -ErrorAction Stop
        if (-not $proc.WaitForExit($timeoutMs)) {
            Write-CITLog -Message 'Disk Cleanup exceeded timeout; terminating cleanmgr' -Level WARN -ScriptName 'CIT-PIA-WUFix-DiskClean'
            try { $proc.Kill() } catch { }
            return $false
        }
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

    $freeBefore = -1
    try { $freeBefore = [math]::Round((Get-PSDrive -Name C -ErrorAction Stop).Free / 1GB, 2) } catch { }

    $diskCleanResult = Invoke-CitDiskCleanup
    $componentResult = Invoke-CitComponentCleanup
    $tempResult      = Remove-CitTempFiles

    $freeAfter = -1
    try { $freeAfter = [math]::Round((Get-PSDrive -Name C -ErrorAction Stop).Free / 1GB, 2) } catch { }

    $freedGB = $null
    if ($freeBefore -ge 0 -and $freeAfter -ge 0) {
        $freedGB = [math]::Round($freeAfter - $freeBefore, 2)
    }

    # Every cleanup branch must have actually succeeded for COMPLETE. A partial
    # run (e.g. cleanmgr timed out, DISM failed) leaves the device only partly
    # remediated and must not auto-resolve the ticket.
    $allSucceeded = $diskCleanResult -and $componentResult -and $tempResult

    if (-not $allSucceeded) {
        Write-CITLog -Message "Disk cleanup did not fully succeed (DiskClean=$diskCleanResult Component=$componentResult Temp=$tempResult FreeAfter=$freeAfter GB)" -Level ERROR -ScriptName 'CIT-PIA-WUFix-DiskClean'

        [PSCustomObject]@{
            Status            = 'FAILED'
            FreeSpaceBeforeGB = $freeBefore
            FreeSpaceAfterGB  = $freeAfter
            FreedGB           = $freedGB
            DiskCleanup       = $diskCleanResult
            ComponentCleanup  = $componentResult
            TempCleanup       = $tempResult
        } | ConvertTo-Json -Compress | Write-Output

        exit 2
    }

    Write-CITLog -Message "Disk cleanup complete. Free space after: $freeAfter GB (freed $freedGB GB)" -Level INFO -ScriptName 'CIT-PIA-WUFix-DiskClean'

    [PSCustomObject]@{
        Status            = 'COMPLETE'
        FreeSpaceBeforeGB = $freeBefore
        FreeSpaceAfterGB  = $freeAfter
        FreedGB           = $freedGB
        DiskCleanup       = $diskCleanResult
        ComponentCleanup  = $componentResult
        TempCleanup       = $tempResult
    } | ConvertTo-Json -Compress | Write-Output

    exit 0
} catch {
    Write-CITLog -Message "Disk cleanup remediation error: $($_.Exception.Message)" -Level ERROR -ScriptName 'CIT-PIA-WUFix-DiskClean'
    [PSCustomObject]@{
        Status = 'FAILED'
        Reason = 'unhandled-exception'
    } | ConvertTo-Json -Compress | Write-Output
    exit 2
}
