# Remediate-PatchCompliance.ps1
# Safety-net remediation: triggers Windows Update to scan, download, and
# install missing quality updates and feature updates. Runs alongside
# Datto RMM as a catch-all for devices Datto missed.
#
# Author:  Kyle Etter / Zeus
# Created: 2026-06-20
# Version: 1.1 - 2026-06-23 - Fix PS 5.1 compat (ConvertTo-Json -Compress), inline Write-CITLog, add $ProgressPreference
# Tested:  Windows 10 22H2, Windows 11 22H2-25H2
# Intune:  Proactive Remediation - Remediation
#
# Remediation behavior by issue type:
#   QualityUpdateStale -> WU cache clear + UsoClient scan/download/install
#   FeatureUpdateAvailable -> triggers feature update scan + download
#   Win10EOL -> no auto-remediation (Win10->Win11 needs hardware compat check)
#   PendingReboot -> no action (reboot is user/Datto's call)
#
# The script does NOT force a reboot. Windows Update prompts natively.
# Idempotent: re-checks conditions before acting.
#
# Blast radius: clears WU download cache, restarts wuauserv, triggers WU
# scan/download/install. No registry mutations, no service deletions,
# no forced reboots. Same proven pattern as CIT-PIA-WUFix-Generic.ps1.

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
# Configuration (must match Detect-PatchCompliance.ps1)
# ---------------------------------------------------------------------------

$FeatureUpdateTargets = @{
    '19045' = 26200
    '22621' = 26200
    '22631' = 26200
    '26100' = 26200
    '26200' = 26200
}

$SkipBuilds = @(17763)

# ---------------------------------------------------------------------------
# Functions
# ---------------------------------------------------------------------------

function Get-CitOsBuildNumber {
    try {
        $os = Get-WmiObject -Class Win32_OperatingSystem -ErrorAction Stop
        $parts = $os.Version -split '\.'
        return [int]$parts[2]
    } catch {
        return 0
    }
}

function Stop-CitWuauserv {
    try {
        if ((Get-Service -Name 'wuauserv' -ErrorAction SilentlyContinue).Status -eq 'Running') {
            Stop-Service -Name 'wuauserv' -Force -ErrorAction Stop
            Write-CITLog -Message 'Stopped wuauserv' -Level INFO -ScriptName 'Remediate-PatchCompliance'
        }
        return $true
    } catch {
        Write-CITLog -Message "Failed to stop wuauserv: $($_.Exception.Message)" -Level WARN -ScriptName 'Remediate-PatchCompliance'
        return $false
    }
}

function Remove-CitWUDownloadCache {
    try {
        $downloadPath = 'C:\Windows\SoftwareDistribution\Download'
        if (Test-Path $downloadPath) {
            Get-ChildItem $downloadPath -Recurse -ErrorAction SilentlyContinue |
                Remove-Item -Recurse -Force -ErrorAction SilentlyContinue
            Write-CITLog -Message 'Cleared WU download cache' -Level INFO -ScriptName 'Remediate-PatchCompliance'
        }
        return $true
    } catch {
        Write-CITLog -Message "Failed to clear WU download cache: $($_.Exception.Message)" -Level WARN -ScriptName 'Remediate-PatchCompliance'
        return $false
    }
}

function Start-CitWuauserv {
    try {
        if ((Get-Service -Name 'wuauserv' -ErrorAction SilentlyContinue).Status -ne 'Running') {
            Start-Service -Name 'wuauserv' -ErrorAction Stop
            Write-CITLog -Message 'Started wuauserv' -Level INFO -ScriptName 'Remediate-PatchCompliance'
        }
        return $true
    } catch {
        Write-CITLog -Message "Failed to start wuauserv: $($_.Exception.Message)" -Level ERROR -ScriptName 'Remediate-PatchCompliance'
        return $false
    }
}

function Invoke-CitUsoClientAction {
    param([string]$Action)

    try {
        $usoClient = Join-Path $env:windir 'System32\UsoClient.exe'
        if (Test-Path $usoClient) {
            Start-Process -FilePath $usoClient -ArgumentList $Action -Wait -WindowStyle Hidden -ErrorAction Stop
            Write-CITLog -Message "Triggered UsoClient $Action" -Level INFO -ScriptName 'Remediate-PatchCompliance'
            return $true
        }
        Write-CITLog -Message "UsoClient not found at $usoClient" -Level WARN -ScriptName 'Remediate-PatchCompliance'
        return $false
    } catch {
        Write-CITLog -Message "UsoClient $Action failed: $($_.Exception.Message)" -Level WARN -ScriptName 'Remediate-PatchCompliance'
        return $false
    }
}

function Invoke-CitQualityUpdateRemediation {
    # Full WU reset: clear cache, restart service, trigger scan/download/install
    Write-CITLog -Message 'Starting quality update remediation (WU cache reset + scan/download/install)' -Level INFO -ScriptName 'Remediate-PatchCompliance'

    $stopped = Stop-CitWuauserv
    $cache   = Remove-CitWUDownloadCache
    $started = Start-CitWuauserv

    if (-not $started) {
        Write-CITLog -Message 'wuauserv could not be restarted - cannot proceed with quality update remediation' -Level ERROR -ScriptName 'Remediate-PatchCompliance'
        return $false
    }

    Invoke-CitUsoClientAction -Action 'StartScan'
    Start-Sleep -Seconds 30
    Invoke-CitUsoClientAction -Action 'StartDownload'
    Invoke-CitUsoClientAction -Action 'StartInstall'

    Write-CITLog -Message 'Quality update remediation triggered - install may complete after reboot' -Level INFO -ScriptName 'Remediate-PatchCompliance'
    return $true
}

function Invoke-CitFeatureUpdateRemediation {
    # Trigger a feature update scan and download via the Update Orchestrator
    # This makes the feature update payload available but does NOT force
    # the upgrade. The user or Datto initiates the actual upgrade install.
    Write-CITLog -Message 'Starting feature update remediation (scan + download feature update payload)' -Level INFO -ScriptName 'Remediate-PatchCompliance'

    # Use UsoClient to trigger an interactive scan which includes feature updates
    $scanOk = Invoke-CitUsoClientAction -Action 'StartInteractiveScan'
    if ($scanOk) {
        Start-Sleep -Seconds 45
        Invoke-CitUsoClientAction -Action 'StartDownload'
        Write-CITLog -Message 'Feature update scan + download triggered - user or Datto should initiate the upgrade' -Level INFO -ScriptName 'Remediate-PatchCompliance'
        return $true
    }

    # Fallback: try the COM API to search for feature updates
    try {
        $session = New-Object -ComObject Microsoft.Update.Session -ErrorAction Stop
        $searcher = $session.CreateUpdateSearcher()
        # Search for software updates that are not installed
        $result = $searcher.Search("IsInstalled=0 and Type='Software'")
        if ($result.Updates.Count -gt 0) {
            $toDownload = New-Object -ComObject Microsoft.Update.UpdateColl
            foreach ($update in $result.Updates) {
                $toDownload.Add($update) | Out-Null
            }
            $downloader = $session.CreateUpdateDownloader()
            $downloader.Updates = $toDownload
            $downloader.Download() | Out-Null
            Write-CITLog -Message "Feature update download via COM API: $($result.Updates.Count) updates downloaded" -Level INFO -ScriptName 'Remediate-PatchCompliance'
            return $true
        } else {
            Write-CITLog -Message 'No feature updates found via COM API search' -Level WARN -ScriptName 'Remediate-PatchCompliance'
        }
    } catch {
        Write-CITLog -Message "COM API feature update fallback failed: $($_.Exception.Message)" -Level WARN -ScriptName 'Remediate-PatchCompliance'
    }

    return $false
}

# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

try {
    Write-CITLog -Message 'Starting patch compliance remediation' -Level INFO -ScriptName 'Remediate-PatchCompliance'

    $buildNumber = Get-CitOsBuildNumber
    if ($buildNumber -eq 0) {
        Write-CITLog -Message 'Could not determine OS build number - exiting with error' -Level ERROR -ScriptName 'Remediate-PatchCompliance'
        exit 2
    }

    # Skip LTSC / thin clients
    if ($buildNumber -in $SkipBuilds) {
        Write-CITLog -Message "Build $buildNumber in skip list - no action" -Level INFO -ScriptName 'Remediate-PatchCompliance'
        Write-Output "Build=$buildNumber;Status=Skip;Reason=SkipList"
        exit 0
    }

    # Parse the detect output to know what issues were found
    # Intune passes the detect script output in the preRemediationDetectionScriptOutput
    # but we cannot rely on that being available. Re-check conditions here.
    $targetBuild = $FeatureUpdateTargets[$buildNumber.ToString()]
    $needsFeatureUpdate = $false
    $needsQualityUpdate = $false
    $isWin10EOL = $false

    if ($buildNumber -eq 19045) {
        $isWin10EOL = $true
    } elseif ($targetBuild -and $buildNumber -lt $targetBuild) {
        $needsFeatureUpdate = $true
    }

    # Check quality update freshness
    $lastUpdateDate = $null
    try {
        $session = New-Object -ComObject Microsoft.Update.Session -ErrorAction Stop
        $searcher = $session.CreateUpdateSearcher()
        $history = $searcher.QueryHistory(0, 1)
        if ($history -and $history.Count -gt 0) {
            $lastUpdateDate = $history.Item(0).Date
        }
    } catch {
        # Fallback to registry
        try {
            $regPath = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\Results\Install'
            if (Test-Path $regPath) {
                $lastRun = (Get-ItemProperty -Path $regPath -Name 'LastSuccessTime' -ErrorAction SilentlyContinue).LastSuccessTime
                if ($lastRun) {
                    $lastUpdateDate = [datetime]::Parse($lastRun)
                }
            }
        } catch { }
    }

    $daysSinceUpdate = -1
    if ($lastUpdateDate) {
        $daysSinceUpdate = [int]((Get-Date) - $lastUpdateDate).TotalDays
        if ($daysSinceUpdate -gt 14) {
            $needsQualityUpdate = $true
        }
    } else {
        # Can't determine - trigger a scan anyway to be safe
        $needsQualityUpdate = $true
    }

    Write-CITLog -Message "Build=$buildNumber daysSinceUpdate=$daysSinceUpdate needsQuality=$needsQualityUpdate needsFeature=$needsFeatureUpdate win10EOL=$isWin10EOL" -Level INFO -ScriptName 'Remediate-PatchCompliance'

    $actions = @()

    # 1. Win10 EOL - no auto-remediation (needs hardware compat check for Win11)
    if ($isWin10EOL) {
        Write-CITLog -Message 'Win10 22H2 EOL - flagging for manual Win11 upgrade (no auto-remediation)' -Level WARN -ScriptName 'Remediate-PatchCompliance'
        $actions += 'Win10EOL-Flagged'
        # Still trigger quality updates so the device is at least patched on Win10
        $qOk = Invoke-CitQualityUpdateRemediation
        if ($qOk) { $actions += 'QualityUpdateTriggered' }
    }

    # 2. Quality update remediation
    if ($needsQualityUpdate -and -not $isWin10EOL) {
        $qOk = Invoke-CitQualityUpdateRemediation
        if ($qOk) { $actions += 'QualityUpdateTriggered' }
    }

    # 3. Feature update remediation
    if ($needsFeatureUpdate) {
        $fOk = Invoke-CitFeatureUpdateRemediation
        if ($fOk) { $actions += 'FeatureUpdateTriggered' }
    }

    # 4. If nothing needed remediation, exit clean
    if ($actions.Count -eq 0) {
        Write-CITLog -Message 'No remediation actions needed (idempotent check passed)' -Level INFO -ScriptName 'Remediate-PatchCompliance'
        Write-Output "Build=$buildNumber;Status=NoAction;DaysSinceUpdate=$daysSinceUpdate"
        exit 0
    }

    $actionStr = $actions -join ','
    Write-CITLog -Message "Remediation complete: $actionStr" -Level INFO -ScriptName 'Remediate-PatchCompliance'

    Write-Output "Status=REMEDIATION_TRIGGERED;Build=$buildNumber;DaysSinceUpdate=$daysSinceUpdate;Actions=$actionStr;RebootMsg=A reboot may be required for updates to complete"

    exit 0

} catch {
    Write-CITLog -Message "Remediation error: $($_.Exception.Message)" -Level ERROR -ScriptName 'Remediate-PatchCompliance'
    exit 2
}