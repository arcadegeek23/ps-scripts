#Requires -Version 5.1
# Remediate-WinRePartition.ps1
# Resizes the Windows Recovery (WinRE) partition to 1024 MB by shrinking C:.
# Based on Microsoft KB5028997 pattern.
#
# Author:  Kyle Etter / Warp
# Created: 2026-07-03
# Tested:  Windows 10 22H2, Windows 11 22H2-24H2 (GPT only)
# Intune:  Proactive Remediation - Remediation
# Run as:  System
#
# BLAST RADIUS:
#   - Shrinks C: by (TargetMB - current recovery size) MB. Reversible only
#     via disk recovery tools if something goes wrong.
#   - Only runs on GPT disks. Bails on MBR, dynamic disks, or layouts where
#     recovery partition is not the last partition on the disk.
#   - Requires C: to have at least (shrink_needed + 4096) MB free.
#   - WinRE is disabled for < 60 seconds during diskpart operations.
#   - Idempotent: if recovery partition >= TargetMB, exits 0 immediately.
#
# Exit 0 = success or already compliant
# Exit 1 = non-compliant but safe-bail (no action taken, re-run will retry)
# Exit 2 = error (unexpected failure - investigate logs)

[CmdletBinding()]
param()

$ErrorActionPreference = 'Stop'
$ProgressPreference    = 'SilentlyContinue'

$Script:ScriptName = 'Remediate-WinRePartition'

# ---------------------------------------------------------------------------
# Config
# ---------------------------------------------------------------------------

# Target recovery partition size in MB. 1024 MB = 1 GB gives headroom for
# future WinRE.wim growth beyond the current 500-750 MB typical size.
$TargetRecoveryMB = 1024

# Minimum free space required on C: beyond the shrink amount (safety buffer).
$MinCFreeMB = 4096   # 4 GB buffer

# Recovery partition GPT type GUID (Windows Recovery Environment)
$RecoveryTypeGuid = 'de94bba4-06d1-4d40-a16a-bfd50179d6ac'

# GPT attributes: bit 0 (Required) + bit 63 (No Automount)
$RecoveryGptAttributes = '0x8000000000000001'

# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------

function Write-CITLog {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] [string] $Message,
        [ValidateSet('INFO','WARN','ERROR','DEBUG')] [string] $Level = 'INFO',
        [string] $ScriptName = $Script:ScriptName
    )
    $logDir = 'C:\ProgramData\CIT\Logs'
    if (-not (Test-Path $logDir)) {
        try { New-Item -Path $logDir -ItemType Directory -Force | Out-Null } catch { return }
    }
    $ts   = (Get-Date).ToString('yyyy-MM-dd HH:mm:ss.fff')
    $line = "$ts [$Level] [$ScriptName] $Message"
    Add-Content -Path (Join-Path $logDir "$ScriptName.log") -Value $line -Encoding UTF8
}

# ---------------------------------------------------------------------------
# Parse reagentc /info
# ---------------------------------------------------------------------------

function Get-WinReInfo {
    $raw = & reagentc /info 2>&1 | Out-String
    Write-CITLog "reagentc /info: $($raw.Trim())" -Level DEBUG

    $enabled = $raw -match 'Windows RE status:\s+Enabled'
    $diskNum = $null
    $partNum = $null

    if ($raw -match 'harddisk(\d+)\\partition(\d+)') {
        $diskNum = [int]$Matches[1]
        $partNum = [int]$Matches[2]
    }

    return @{ Enabled = $enabled; DiskNum = $diskNum; PartNum = $partNum }
}

# ---------------------------------------------------------------------------
# Run diskpart script from a temp file
# ---------------------------------------------------------------------------

function Invoke-Diskpart {
    param([string[]] $Commands)

    $tmpFile = Join-Path $env:TEMP "winre_diskpart_$(Get-Random).txt"
    try {
        ($Commands + 'exit') -join "`r`n" | Out-File -FilePath $tmpFile -Encoding ASCII
        Write-CITLog "diskpart script:`r`n$(Get-Content $tmpFile -Raw)" -Level DEBUG

        $result = & diskpart /s $tmpFile 2>&1 | Out-String
        Write-CITLog "diskpart output: $result"
        return $result
    } finally {
        Remove-Item $tmpFile -Force -ErrorAction SilentlyContinue
    }
}

# ---------------------------------------------------------------------------
# Safety checks - return $null if safe to proceed, else a reason string
# ---------------------------------------------------------------------------

function Get-SafetyBlockReason {
    param(
        [int] $DiskNum,
        [int] $RecoveryPartNum,
        [int] $ShrinkNeededMB
    )

    # GPT only
    $disk = Get-Disk -Number $DiskNum
    if ($disk.PartitionStyle -ne 'GPT') {
        return "Disk $DiskNum is $($disk.PartitionStyle) - only GPT supported"
    }
    if ($disk.IsDynamic) {
        return "Disk $DiskNum is a dynamic disk - not supported"
    }

    # C: must be on the same disk
    $osPart = Get-Partition -DiskNumber $DiskNum | Where-Object { $_.DriveLetter -eq 'C' }
    if (-not $osPart) {
        return "C: drive not found on disk $DiskNum"
    }

    # Recovery partition must be the last partition on the disk (partition number > C:)
    $allParts = Get-Partition -DiskNumber $DiskNum | Sort-Object PartitionNumber
    $lastPart = $allParts | Select-Object -Last 1
    if ($lastPart.PartitionNumber -ne $RecoveryPartNum) {
        return "Recovery partition ($RecoveryPartNum) is not the last partition on disk $DiskNum (last is $($lastPart.PartitionNumber)) - layout not supported"
    }

    # C: must have enough free space
    $cDrive = Get-PSDrive C -ErrorAction SilentlyContinue
    if (-not $cDrive) {
        return 'Could not get C: drive info'
    }
    $cFreeMB = [Math]::Floor($cDrive.Free / 1MB)
    $requiredFreeMB = $ShrinkNeededMB + $MinCFreeMB
    if ($cFreeMB -lt $requiredFreeMB) {
        return "C: has ${cFreeMB}MB free; need ${requiredFreeMB}MB (${ShrinkNeededMB}MB shrink + ${MinCFreeMB}MB buffer)"
    }

    return $null  # all clear
}

# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

try {
    Write-CITLog "Starting WinRE partition remediation (target: ${TargetRecoveryMB}MB)"

    # 1. Get WinRE location
    $winre = Get-WinReInfo
    Write-CITLog "WinRE: enabled=$($winre.Enabled) disk=$($winre.DiskNum) partition=$($winre.PartNum)"

    if ($null -eq $winre.DiskNum -or $null -eq $winre.PartNum) {
        Write-CITLog 'Cannot determine WinRE disk/partition location' -Level ERROR
        exit 2
    }

    $diskNum    = $winre.DiskNum
    $recovPart  = $winre.PartNum

    # 2. Get current recovery partition size
    $recovPartObj  = Get-Partition -DiskNumber $diskNum -PartitionNumber $recovPart -ErrorAction Stop
    $currentSizeMB = [Math]::Round($recovPartObj.Size / 1MB)
    Write-CITLog "Current recovery partition size: ${currentSizeMB}MB"

    # 3. Already big enough? (idempotent check)
    if ($currentSizeMB -ge $TargetRecoveryMB) {
        Write-CITLog "Recovery partition already ${currentSizeMB}MB >= ${TargetRecoveryMB}MB - no action needed"
        exit 0
    }

    $shrinkNeededMB = $TargetRecoveryMB - $currentSizeMB
    Write-CITLog "Need to shrink C: by ${shrinkNeededMB}MB to reach ${TargetRecoveryMB}MB target"

    # 4. Safety checks
    $block = Get-SafetyBlockReason -DiskNum $diskNum -RecoveryPartNum $recovPart -ShrinkNeededMB $shrinkNeededMB
    if ($block) {
        Write-CITLog "Safe-bail: $block" -Level WARN
        # Exit 0 so Intune doesn't keep retrying on permanently unsupported layouts.
        # The detection script will continue to report non-compliant for tracking.
        exit 0
    }

    # 5. Find C: partition number on this disk
    $osPartObj  = Get-Partition -DiskNumber $diskNum | Where-Object { $_.DriveLetter -eq 'C' }
    $osPartNum  = $osPartObj.PartitionNumber
    Write-CITLog "C: is disk $diskNum partition $osPartNum"

    # 6. Disable WinRE (required before modifying recovery partition)
    Write-CITLog 'Disabling WinRE...'
    $disableOut = & reagentc /disable 2>&1 | Out-String
    Write-CITLog "reagentc /disable: $($disableOut.Trim())"

    if ($disableOut -notmatch 'REAGENTC.EXE: Operation Successful') {
        # Some locales/builds use different success strings - check for absence of error instead
        if ($disableOut -match 'error|failed|0x8' -and $disableOut -notmatch 'already disabled') {
            Write-CITLog "reagentc /disable may have failed - aborting to avoid data loss" -Level ERROR
            exit 2
        }
    }

    # 7. Shrink C:, delete old recovery, create new larger recovery
    Write-CITLog "Running diskpart: shrink C: by ${shrinkNeededMB}MB, resize recovery to ${TargetRecoveryMB}MB..."

    $dpCommands = @(
        "select disk $diskNum",
        "select partition $osPartNum",
        "shrink desired=$shrinkNeededMB minimum=$shrinkNeededMB",
        "select partition $recovPart",
        'delete partition override',
        'create partition primary',
        'format quick fs=ntfs label="Windows RE tools"',
        "set id=$RecoveryTypeGuid",
        "gpt attributes=$RecoveryGptAttributes"
    )

    $dpOut = Invoke-Diskpart -Commands $dpCommands

    # Check diskpart didn't error out
    if ($dpOut -match 'DiskPart has encountered an error') {
        Write-CITLog "diskpart reported an error - attempting to re-enable WinRE and exit" -Level ERROR
        & reagentc /enable 2>&1 | Out-Null
        exit 2
    }

    # 8. Re-enable WinRE
    Write-CITLog 'Re-enabling WinRE...'
    $enableOut = & reagentc /enable 2>&1 | Out-String
    Write-CITLog "reagentc /enable: $($enableOut.Trim())"

    # 9. Verify
    Start-Sleep -Seconds 3  # brief pause for reagentc to settle
    $verifyInfo = Get-WinReInfo

    if ($verifyInfo.Enabled) {
        $newPart    = Get-Partition -DiskNumber $diskNum -PartitionNumber $recovPart -ErrorAction SilentlyContinue
        $newSizeMB  = if ($newPart) { [Math]::Round($newPart.Size / 1MB) } else { 'unknown' }
        Write-CITLog "SUCCESS: WinRE enabled. Recovery partition now ~${newSizeMB}MB (was ${currentSizeMB}MB)"
        Write-Output "WinRePartitionResized=1;OldSizeMB=$currentSizeMB;NewSizeMB=$newSizeMB;ShrinkMB=$shrinkNeededMB"
        exit 0
    } else {
        Write-CITLog 'WinRE not enabled after resize - manual intervention may be required' -Level ERROR
        Write-Output "WinRePartitionResized=0;Reason=WinRENotReEnabled"
        exit 2
    }

} catch {
    Write-CITLog "Unhandled remediation error: $($_.Exception.Message)`n$($_.ScriptStackTrace)" -Level ERROR
    # Attempt re-enable if WinRE may have been disabled before the failure
    try { & reagentc /enable 2>&1 | Out-Null } catch {}
    Write-Output "Error=$($_.Exception.Message)"
    exit 2
}
