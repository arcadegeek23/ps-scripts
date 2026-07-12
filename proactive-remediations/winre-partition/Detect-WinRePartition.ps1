#Requires -Version 5.1
# Detect-WinRePartition.ps1
# Detects whether the Windows Recovery (WinRE) partition is large enough
# for feature updates. Feature updates require WinRE partition >= 600 MB
# with at least 250 MB free. Devices below threshold are flagged for resize.
#
# Author:  Kyle Etter / Warp
# Created: 2026-07-03
# Tested:  Windows 10 22H2, Windows 11 22H2-24H2 (GPT only)
# Intune:  Proactive Remediation - Detection
# Run as:  System
#
# Logic:
#   1. Parse reagentc /info to get WinRE status + disk/partition location
#   2. If WinRE is disabled or location unresolvable -> non-compliant
#   3. Get recovery partition size via Get-Partition
#   4. If size < 600 MB -> non-compliant (needs resize)
#   5. Otherwise -> compliant
#
# Exit 0 = compliant, 1 = non-compliant (remediate), 2+ = error (investigate)

[CmdletBinding()]
param()

$ErrorActionPreference = 'Stop'
$ProgressPreference    = 'SilentlyContinue'

$Script:ScriptName = 'Detect-WinRePartition'

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
# Minimum recovery partition size (bytes)
# Microsoft guidance: 600 MB minimum; < 600 MB risks feature update failure
# ---------------------------------------------------------------------------
$MinPartitionBytes = 600MB   # 629,145,600 bytes

# ---------------------------------------------------------------------------
# Parse reagentc /info output
# Returns hashtable: @{ Enabled=$bool; DiskNum=$int; PartNum=$int }
# ---------------------------------------------------------------------------
function Get-WinReInfo {
    try {
        $raw = & reagentc /info 2>&1 | Out-String
        Write-CITLog "reagentc output: $($raw.Trim())" -Level DEBUG

        $enabled = $raw -match 'Windows RE status:\s+Enabled'

        $diskNum = $null
        $partNum = $null

        # Location string: \\?\GLOBALROOT\device\harddisk0\partition4\Recovery\WindowsRE
        if ($raw -match 'harddisk(\d+)\\partition(\d+)') {
            $diskNum = [int]$Matches[1]
            $partNum = [int]$Matches[2]
        }

        return @{
            Enabled = $enabled
            DiskNum = $diskNum
            PartNum = $partNum
            Raw     = $raw.Trim()
        }
    } catch {
        Write-CITLog "reagentc query failed: $($_.Exception.Message)" -Level ERROR
        return $null
    }
}

# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

try {
    Write-CITLog 'Starting WinRE partition detection'

    # 1. Get WinRE info
    $winre = Get-WinReInfo
    if (-not $winre) {
        Write-Output 'WinRE=Unknown;Compliant=0;Reason=reagentc_failed'
        exit 2
    }

    Write-CITLog "WinRE enabled=$($winre.Enabled) disk=$($winre.DiskNum) partition=$($winre.PartNum)"

    # 2. WinRE disabled or location unknown
    if (-not $winre.Enabled) {
        Write-CITLog 'WinRE is disabled - non-compliant' -Level WARN
        Write-Output 'WinRE=Disabled;Compliant=0;Reason=WinREDisabled'
        exit 1
    }

    if ($null -eq $winre.DiskNum -or $null -eq $winre.PartNum) {
        Write-CITLog 'Could not parse WinRE disk/partition from reagentc output - non-compliant' -Level WARN
        Write-Output 'WinRE=Enabled;Compliant=0;Reason=LocationUnknown'
        exit 1
    }

    # 3. Get recovery partition size
    $recoveryPart = $null
    try {
        $recoveryPart = Get-Partition -DiskNumber $winre.DiskNum -PartitionNumber $winre.PartNum -ErrorAction Stop
    } catch {
        Write-CITLog "Get-Partition disk=$($winre.DiskNum) partition=$($winre.PartNum) failed: $($_.Exception.Message)" -Level ERROR
        Write-Output "WinRE=Enabled;Disk=$($winre.DiskNum);Partition=$($winre.PartNum);Compliant=0;Reason=PartitionNotFound"
        exit 2
    }

    $sizeMB     = [Math]::Round($recoveryPart.Size / 1MB, 1)
    $sizeBytes  = $recoveryPart.Size

    Write-CITLog "Recovery partition: disk=$($winre.DiskNum) partition=$($winre.PartNum) size=${sizeMB}MB ($sizeBytes bytes)"

    # 4. Evaluate
    if ($sizeBytes -ge $MinPartitionBytes) {
        Write-CITLog "Compliant: recovery partition ${sizeMB}MB >= 600MB minimum"
        Write-Output "WinRE=Enabled;Disk=$($winre.DiskNum);Partition=$($winre.PartNum);SizeMB=$sizeMB;Compliant=1"
        exit 0
    } else {
        Write-CITLog "Non-compliant: recovery partition ${sizeMB}MB < 600MB minimum - resize needed" -Level WARN
        Write-Output "WinRE=Enabled;Disk=$($winre.DiskNum);Partition=$($winre.PartNum);SizeMB=$sizeMB;Compliant=0;Reason=PartitionTooSmall"
        exit 1
    }

} catch {
    Write-CITLog "Unhandled detection error: $($_.Exception.Message)" -Level ERROR
    Write-Output "Compliant=0;Reason=UnhandledError;Error=$($_.Exception.Message)"
    exit 2
}
