# CIT-PIA-WUDiag.ps1
# Diagnoses Windows Update patch-install failure mode and recommends a fix branch.
# Author:  Kyle Etter
# Created: 2026-06-13
# Updated: 2026-06-13
# Tested:  Windows 10 22H2, Windows 11 23H2
# Intune:  Proactive Remediation — Diagnostic
# Notes:   Emits structured JSON to stdout for PIA workflow branching.
#          Exit 0 = no fix needed; 1 = fix recommended; 2+ = error.

[CmdletBinding()]
param()

$ErrorActionPreference = 'Stop'
$WarningPreference     = 'Continue'

. "$PSScriptRoot\..\..\platform\CIT-Logging.ps1" -ScriptName 'CIT-PIA-WUDiag'

function Get-CitFreeSpaceGB {
    try {
        $drive = Get-PSDrive -Name C -ErrorAction Stop
        return [math]::Round($drive.Free / 1GB, 2)
    } catch {
        Write-CITLog -Message "Unable to determine free space: $($_.Exception.Message)" -Level WARN -ScriptName 'CIT-PIA-WUDiag'
        return -1
    }
}

function Test-CitPendingReboot {
    try {
        return (Test-Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\RebootPending') -or
               (Test-Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\RebootRequired')
    } catch {
        Write-CITLog -Message "Unable to determine pending reboot state: $($_.Exception.Message)" -Level WARN -ScriptName 'CIT-PIA-WUDiag'
        return $false
    }
}

function Get-CitServiceStatus {
    param([string]$Name)

    try {
        return (Get-Service -Name $Name -ErrorAction Stop).Status.ToString()
    } catch {
        Write-CITLog -Message "Unable to determine $Name status: $($_.Exception.Message)" -Level WARN -ScriptName 'CIT-PIA-WUDiag'
        return 'UNKNOWN'
    }
}

function Get-CitLastWUErrorCode {
    try {
        $lastErr = Get-WinEvent -LogName 'System' -MaxEvents 200 -ErrorAction Stop |
            Where-Object { $_.ProviderName -eq 'Microsoft-Windows-WindowsUpdateClient' -and $_.LevelDisplayName -eq 'Error' } |
            Select-Object -First 1

        if ($lastErr) {
            $split = $lastErr.Message -split 'Error ' | Select-Object -Last 1
            return $split.Substring(0, [Math]::Min(12, $split.Length))
        }

        return 'NONE'
    } catch {
        Write-CITLog -Message "Unable to read last WU error code: $($_.Exception.Message)" -Level WARN -ScriptName 'CIT-PIA-WUDiag'
        return 'UNKNOWN'
    }
}

function Get-CitSoftwareDistributionSizeGB {
    try {
        $path = 'C:\Windows\SoftwareDistribution'
        if (-not (Test-Path $path)) {
            return 0
        }

        $size = (Get-ChildItem $path -Recurse -ErrorAction Stop | Measure-Object -Property Length -Sum).Sum
        return [math]::Round($size / 1GB, 2)
    } catch {
        Write-CITLog -Message "Unable to determine SoftwareDistribution size: $($_.Exception.Message)" -Level WARN -ScriptName 'CIT-PIA-WUDiag'
        return -1
    }
}

try {
    Write-CITLog -Message 'Starting Windows Update diagnostic' -Level INFO -ScriptName 'CIT-PIA-WUDiag'

    $freeGB        = Get-CitFreeSpaceGB
    $pendingReboot = Test-CitPendingReboot
    $wuService     = Get-CitServiceStatus -Name 'wuauserv'
    $bitsService   = Get-CitServiceStatus -Name 'bits'
    $lastErrCode   = Get-CitLastWUErrorCode
    $sdSize        = Get-CitSoftwareDistributionSizeGB

    $fix = 'GENERIC'
    if ($freeGB -ge 0 -and $freeGB -lt 10) {
        $fix = 'DISKCLEAN'
    } elseif ($pendingReboot) {
        $fix = 'REBOOT'
    } elseif ($sdSize -ge 0 -and $sdSize -gt 10) {
        $fix = 'WUCOMPONENTS'
    }

    $result = [PSCustomObject]@{
        Hostname       = $env:COMPUTERNAME
        Timestamp      = (Get-Date).ToString('o')
        FreeSpaceGB    = $freeGB
        LowDiskSpace   = ($freeGB -ge 0 -and $freeGB -lt 10)
        PendingReboot  = $pendingReboot
        WUService      = $wuService
        BITSService    = $bitsService
        LastErrorCode  = $lastErrCode
        SoftwareDistGB = $sdSize
        RecommendedFix = $fix
    }

    $result | ConvertTo-Json -Compress | Write-Output

    Write-CITLog -Message "Diagnostic complete. Recommended fix: $fix" -Level INFO -ScriptName 'CIT-PIA-WUDiag'

    if ($fix -eq 'GENERIC' -and -not $pendingReboot -and $freeGB -ge 10 -and $sdSize -le 10) {
        exit 0
    }

    exit 1
} catch {
    Write-CITLog -Message "Diagnostic error: $($_.Exception.Message)" -Level ERROR -ScriptName 'CIT-PIA-WUDiag'
    exit 2
}
