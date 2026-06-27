# Detect-PatchCompliance.ps1
# Safety-net detection: checks whether a device is fully patched on both
# quality updates and feature updates. Designed to run alongside Datto RMM
# (which owns the approval/scheduling workflow). This script catches
# devices Datto missed or that were offline during the patch window.
#
# Author:  Kyle Etter / Zeus
# Created: 2026-06-20
# Version: 1.1 - 2026-06-23 - Inline Write-CITLog (fixes IME cache dot-source failure), add $ProgressPreference
# Tested:  Windows 10 22H2, Windows 11 22H2-25H2
# Intune:  Proactive Remediation - Detection
#
# Compliance logic:
#   1. Skip LTSC 2019 (17763) - thin clients/KVMs, different servicing channel
#   2. Check last successful quality update install date
#      - > 14 days = non-compliant (QualityUpdateStale)
#   3. Check feature update status against target build for OS family
#      - Win10 22H2 (19045) = non-compliant (Win10EOL - flag for manual upgrade)
#      - Win11 below target build = non-compliant (FeatureUpdateAvailable)
#   4. Check pending reboot (blocks update finalization)
#      - Pending reboot + stale quality = non-compliant (PendingReboot)
#   5. Otherwise = compliant
#
# Exit 0 = compliant, 1 = non-compliant, 2+ = error

[CmdletBinding()]
param()

$ErrorActionPreference = 'Stop'
$WarningPreference     = 'Continue'
$ProgressPreference    = 'SilentlyContinue'

# Inline logging function (avoids external dot-source that fails in IME cache)
function Write-CITLog {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] [string] $Message,
        [Parameter()] [ValidateSet('INFO','WARN','ERROR','DEBUG')] [string] $Level = 'INFO',
        [Parameter(Mandatory)] [string] $ScriptName
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
# Configuration
# ---------------------------------------------------------------------------

# Days without a quality update before flagging as stale.
$QualityUpdateStaleDays = 14

# Target feature update build per OS family.
# Devices below this build should be offered a feature update.
# Update when Microsoft releases a new feature update and CIT adopts it.
$FeatureUpdateTargets = @{
    '19045' = 26200   # Win10 22H2 -> target Win11 25H2 (flagged, not auto-triggered)
    '22621' = 26200   # Win11 22H2 -> target 25H2
    '22631' = 26200   # Win11 23H2 -> target 25H2
    '26100' = 26200   # Win11 24H2 -> target 25H2
    '26200' = 26200   # Win11 25H2 -> current target (compliant if on this build)
}

# Builds to skip entirely (LTSC, thin clients, KVMs)
$SkipBuilds = @(17763)

# ---------------------------------------------------------------------------
# Functions
# ---------------------------------------------------------------------------

function Get-CitOsBuildNumber {
    try {
        $os = Get-WmiObject -Class Win32_OperatingSystem -ErrorAction Stop
        $version = $os.Version
        $parts = $version -split '\.'
        return [int]$parts[2]
    } catch {
        Write-CITLog -Message "Unable to determine OS build: $($_.Exception.Message)" -Level WARN -ScriptName 'Detect-PatchCompliance'
        return 0
    }
}

function Get-CitOsBuildFull {
    try {
        $os = Get-WmiObject -Class Win32_OperatingSystem -ErrorAction Stop
        return $os.Version  # e.g. "10.0.26200.8655"
    } catch {
        return $null
    }
}

function Test-CitIsDefinitionUpdate {
    # Returns $true when an update-history title looks like a Defender /
    # antivirus / Security Intelligence definition update. These ship daily,
    # so keying freshness off them lets months-behind devices look current.
    param([string]$Title)
    if ([string]::IsNullOrWhiteSpace($Title)) { return $false }
    return ($Title -match 'Defender' -or
            $Title -match 'Antivirus' -or
            $Title -match 'Anti-virus' -or
            $Title -match 'Security Intelligence' -or
            $Title -match 'Definition Update')
}

function Get-CitLastQualityUpdateDate {
    # Check the last successful install date via the Windows Update Agent COM
    # API. Falls back to registry, then Get-HotFix, if COM is unavailable.
    #
    # IMPORTANT: query a deep slice of history (not just the newest one row) and
    # FILTER OUT Defender / definition updates, which install daily. The
    # newest single history row is almost always a Defender definition,
    # so taking it makes the staleness gate never fire. We compute freshness
    # from the most recent genuine cumulative / security / quality update.
    try {
        $session = New-Object -ComObject Microsoft.Update.Session -ErrorAction Stop
        $searcher = $session.CreateUpdateSearcher()

        $totalCount = 0
        try { $totalCount = [int]$searcher.GetTotalHistoryCount() } catch { $totalCount = 0 }
        if ($totalCount -le 0) { $totalCount = 200 }
        $fetch = [Math]::Min($totalCount, 200)

        $history = $searcher.QueryHistory(0, $fetch)
        if ($history -and $history.Count -gt 0) {
            for ($i = 0; $i -lt $history.Count; $i++) {
                $entry = $history.Item($i)
                # ResultCode 2 = Succeeded; 3 = Succeeded with errors. Only
                # count installs that actually applied (Operation 1 = Install).
                if ($entry.Operation -ne 1) { continue }
                if ($entry.ResultCode -ne 2 -and $entry.ResultCode -ne 3) { continue }
                if (Test-CitIsDefinitionUpdate -Title $entry.Title) { continue }
                # History is returned newest-first, so the first qualifying
                # row is the most recent genuine quality update.
                return $entry.Date
            }
            Write-CITLog -Message 'No genuine quality update found in WU history (only definition updates) - falling back' -Level WARN -ScriptName 'Detect-PatchCompliance'
        }
    } catch {
        Write-CITLog -Message "WUA COM query failed, trying registry: $($_.Exception.Message)" -Level WARN -ScriptName 'Detect-PatchCompliance'
    }

    # Fallback: check registry for last successful update install time
    try {
        $regPath = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\Results\Install'
        if (Test-Path $regPath) {
            $lastRun = (Get-ItemProperty -Path $regPath -Name 'LastSuccessTime' -ErrorAction SilentlyContinue).LastSuccessTime
            if ($lastRun) {
                return [datetime]::Parse($lastRun)
            }
        }
    } catch {
        Write-CITLog -Message "Registry fallback failed: $($_.Exception.Message)" -Level WARN -ScriptName 'Detect-PatchCompliance'
    }

    # Second fallback: check most recent hotfix install date
    try {
        $hotfixes = Get-HotFix -ErrorAction SilentlyContinue | Sort-Object InstalledOn -Descending | Select-Object -First 1
        if ($hotfixes -and $hotfixes.InstalledOn) {
            return $hotfixes.InstalledOn
        }
    } catch {
        # Get-HotFix can fail on some builds
    }

    return $null
}

function Test-CitPendingReboot {
    # Combine the three standard pending-reboot signals:
    #   1. Component Based Servicing RebootPending key (presence = pending)
    #   2. Windows Update Auto Update RebootRequired key (presence = pending)
    #   3. PendingFileRenameOperations - this is a VALUE under the Session
    #      Manager key, not a key. Test-Path on it is always false; we must
    #      read the value and check it is non-empty.
    try {
        if (Test-Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\RebootPending') {
            return $true
        }
        if (Test-Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\RebootRequired') {
            return $true
        }

        $sessionMgr = 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager'
        $pfro = (Get-ItemProperty -Path $sessionMgr -Name 'PendingFileRenameOperations' -ErrorAction SilentlyContinue).PendingFileRenameOperations
        if ($pfro) {
            # REG_MULTI_SZ comes back as a string array; any non-empty entry
            # means a file rename is queued for the next boot.
            foreach ($item in $pfro) {
                if (-not [string]::IsNullOrEmpty($item)) { return $true }
            }
        }

        return $false
    } catch {
        return $false
    }
}

# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

try {
    Write-CITLog -Message 'Starting patch compliance detection' -Level INFO -ScriptName 'Detect-PatchCompliance'

    $buildNumber = Get-CitOsBuildNumber
    $buildFull   = Get-CitOsBuildFull

    if ($buildNumber -eq 0) {
        Write-CITLog -Message 'Could not determine OS build number - exiting with error' -Level ERROR -ScriptName 'Detect-PatchCompliance'
        exit 2
    }

    Write-CITLog -Message "OS build: $buildFull (major: $buildNumber)" -Level INFO -ScriptName 'Detect-PatchCompliance'

    # 1. Skip LTSC / thin clients
    if ($buildNumber -in $SkipBuilds) {
        Write-CITLog -Message "Build $buildNumber is in skip list (LTSC/thin client) - compliant by exception" -Level INFO -ScriptName 'Detect-PatchCompliance'
        Write-Output "Build=$buildNumber;Compliant=1;Reason=SkipList"
        exit 0
    }

    $issues = @()
    $reasons = @()

    # 2. Check quality update freshness
    $lastUpdateDate = Get-CitLastQualityUpdateDate
    $daysSinceUpdate = -1

    if ($lastUpdateDate) {
        $daysSinceUpdate = [int]((Get-Date) - $lastUpdateDate).TotalDays
        Write-CITLog -Message "Last quality update: $lastUpdateDate ($daysSinceUpdate days ago)" -Level INFO -ScriptName 'Detect-PatchCompliance'

        if ($daysSinceUpdate -gt $QualityUpdateStaleDays) {
            $issues += 'QualityUpdateStale'
            $reasons += "QualityUpdateStale:$daysSinceUpdate days"
        }
    } else {
        Write-CITLog -Message 'Could not determine last quality update date - flagging as unknown' -Level WARN -ScriptName 'Detect-PatchCompliance'
        $issues += 'UnknownUpdateDate'
        $reasons += 'UnknownUpdateDate:cannot determine last patch date'
    }

    # 3. Check feature update status
    $targetBuild = $FeatureUpdateTargets[$buildNumber.ToString()]
    if ($targetBuild -and $buildNumber -lt $targetBuild) {
        if ($buildNumber -eq 19045) {
            # Win10 22H2 - EOL, needs Win11 upgrade (hardware compat check needed)
            $issues += 'Win10EOL'
            $reasons += "Win10EOL:needs Win11 upgrade (target build $targetBuild)"
        } else {
            # Win11 below target feature update
            $issues += 'FeatureUpdateAvailable'
            $reasons += "FeatureUpdateAvailable:current=$buildNumber target=$targetBuild"
        }
    }

    # 4. Check pending reboot (blocks update finalization)
    $pendingReboot = Test-CitPendingReboot
    if ($pendingReboot) {
        $reasons += 'PendingReboot:reboot required to finalize updates'
        # Pending reboot alone is not non-compliant if updates are current,
        # but if combined with stale updates it compounds the issue
        if ($issues -contains 'QualityUpdateStale') {
            $issues += 'PendingReboot'
        }
    }

    # 5. Evaluate compliance
    if ($issues.Count -eq 0) {
        Write-CITLog -Message "Device is compliant - build $buildNumber, $daysSinceUpdate days since last update, pendingReboot=$pendingReboot" -Level INFO -ScriptName 'Detect-PatchCompliance'
        Write-Output "Build=$buildNumber;LastUpdateDays=$daysSinceUpdate;PendingReboot=$pendingReboot;Compliant=1"
        exit 0
    } else {
        $issueStr = $issues -join ','
        $reasonStr = $reasons -join ';'
        Write-CITLog -Message "Device is non-compliant: $issueStr - $reasonStr" -Level WARN -ScriptName 'Detect-PatchCompliance'
        Write-Output "Build=$buildNumber;LastUpdateDays=$daysSinceUpdate;PendingReboot=$pendingReboot;Compliant=0;Issues=$issueStr;Reasons=$reasonStr"
        exit 1
    }

} catch {
    Write-CITLog -Message "Detection error: $($_.Exception.Message)" -Level ERROR -ScriptName 'Detect-PatchCompliance'
    exit 2
}