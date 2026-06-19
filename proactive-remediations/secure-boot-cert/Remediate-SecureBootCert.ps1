# Remediate-SecureBootCert.ps1
# Triggers Windows Update to scan, download, and install the cumulative update
# that carries the Secure Boot DBX certificate refresh.
# Author:  Kyle Etter
# Created: 2026-06-19
# Tested:  Windows 10 22H2, Windows 11 23H2, Windows 11 24H2
# Intune:  Proactive Remediation - Remediation
# Notes:   Blast radius: clears the WU download cache and re-triggers scan/download/install.
#          The actual KB install may complete after a reboot - that is expected.
#          This script does NOT force a reboot. Windows Update will prompt natively.
#          Idempotent: re-checks the detect condition before acting. If the KB is
#          already installed, exits 0 without doing anything.

[CmdletBinding()]
param()

$ErrorActionPreference = 'Stop'
$WarningPreference     = 'Continue'

. "$PSScriptRoot\..\..\platform\CIT-Logging.ps1" -ScriptName 'Remediate-SecureBootCert'

# ---------------------------------------------------------------------------
# KB mapping: must match Detect-SecureBootCert.ps1
# ---------------------------------------------------------------------------
$SecureBootKbMap = @{
    '19045' = 'KB5063610'
    '22631' = 'KB5063917'
    '26100' = 'KB5063915'
    '26200' = 'KB5063915'
}

function Get-CitOsBuildNumber {
    try {
        $os = Get-WmiObject -Class Win32_OperatingSystem -ErrorAction Stop
        $version = $os.Version
        $parts = $version -split '\.'
        return $parts[2]
    } catch {
        Write-CITLog -Message "Unable to determine OS build: $($_.Exception.Message)" -Level WARN -ScriptName 'Remediate-SecureBootCert'
        return $null
    }
}

function Test-CitKbInstalled {
    param([string]$KbNumber)

    try {
        $hotfix = Get-HotFix -Id $KbNumber -ErrorAction SilentlyContinue
        if ($hotfix) {
            return $true
        }
        $wmiQuery = "SELECT * FROM Win32_QuickFixEngineering WHERE HotFixID = '$KbNumber'"
        $wmiResult = Get-WmiObject -Query $wmiQuery -ErrorAction SilentlyContinue
        if ($wmiResult) {
            return $true
        }
        return $false
    } catch {
        return $false
    }
}

function Stop-CitWuauserv {
    try {
        if ((Get-Service -Name 'wuauserv' -ErrorAction SilentlyContinue).Status -eq 'Running') {
            Stop-Service -Name 'wuauserv' -Force -ErrorAction Stop
            Write-CITLog -Message 'Stopped wuauserv' -Level INFO -ScriptName 'Remediate-SecureBootCert'
        }
        return $true
    } catch {
        Write-CITLog -Message "Failed to stop wuauserv: $($_.Exception.Message)" -Level WARN -ScriptName 'Remediate-SecureBootCert'
        return $false
    }
}

function Remove-CitWUDownloadCache {
    try {
        $downloadPath = 'C:\Windows\SoftwareDistribution\Download'
        if (Test-Path $downloadPath) {
            Get-ChildItem $downloadPath -Recurse -ErrorAction SilentlyContinue |
                Remove-Item -Recurse -Force -ErrorAction SilentlyContinue
            Write-CITLog -Message 'Cleared WU download cache' -Level INFO -ScriptName 'Remediate-SecureBootCert'
        }
        return $true
    } catch {
        Write-CITLog -Message "Failed to clear WU download cache: $($_.Exception.Message)" -Level WARN -ScriptName 'Remediate-SecureBootCert'
        return $false
    }
}

function Start-CitWuauserv {
    try {
        if ((Get-Service -Name 'wuauserv' -ErrorAction SilentlyContinue).Status -ne 'Running') {
            Start-Service -Name 'wuauserv' -ErrorAction Stop
            Write-CITLog -Message 'Started wuauserv' -Level INFO -ScriptName 'Remediate-SecureBootCert'
        }
        return $true
    } catch {
        Write-CITLog -Message "Failed to start wuauserv: $($_.Exception.Message)" -Level WARN -ScriptName 'Remediate-SecureBootCert'
        return $false
    }
}

function Invoke-CitUsoClientAction {
    param([string]$Action)

    try {
        $usoClient = Join-Path $env:windir 'System32\UsoClient.exe'
        if (Test-Path $usoClient) {
            Start-Process -FilePath $usoClient -ArgumentList $Action -Wait -WindowStyle Hidden -ErrorAction Stop
            Write-CITLog -Message "Triggered UsoClient $Action" -Level INFO -ScriptName 'Remediate-SecureBootCert'
        }
        return $true
    } catch {
        Write-CITLog -Message "UsoClient $Action failed: $($_.Exception.Message)" -Level WARN -ScriptName 'Remediate-SecureBootCert'
        return $false
    }
}

try {
    Write-CITLog -Message 'Starting Secure Boot certificate remediation' -Level INFO -ScriptName 'Remediate-SecureBootCert'

    # 1. Idempotency check: re-verify the device actually needs the update.
    $buildNumber = Get-CitOsBuildNumber
    if (-not $buildNumber) {
        Write-CITLog -Message 'Could not determine OS build number - exiting with error' -Level ERROR -ScriptName 'Remediate-SecureBootCert'
        exit 2
    }

    $expectedKb = $SecureBootKbMap[$buildNumber]
    if (-not $expectedKb) {
        Write-CITLog -Message "No KB mapping for build $buildNumber - nothing to remediate" -Level INFO -ScriptName 'Remediate-SecureBootCert'
        Write-Output "Build=$buildNumber;Status=NoAction;Reason=NoKbMapping"
        exit 0
    }

    $alreadyInstalled = Test-CitKbInstalled -KbNumber $expectedKb
    if ($alreadyInstalled) {
        Write-CITLog -Message "KB $expectedKb already installed - no action needed (idempotent)" -Level INFO -ScriptName 'Remediate-SecureBootCert'
        Write-Output "Build=$buildNumber;Kb=$expectedKb;Status=AlreadyInstalled"
        exit 0
    }

    Write-CITLog -Message "KB $expectedKb not installed on build $buildNumber - proceeding with remediation" -Level INFO -ScriptName 'Remediate-SecureBootCert'

    # 2. Reset WU download cache and trigger scan/download/install.
    $stopped = Stop-CitWuauserv
    $cache   = Remove-CitWUDownloadCache
    $started = Start-CitWuauserv

    if (-not $started) {
        Write-CITLog -Message 'wuauserv could not be restarted - cannot proceed' -Level ERROR -ScriptName 'Remediate-SecureBootCert'
        exit 2
    }

    Invoke-CitUsoClientAction -Action 'StartScan'
    Start-Sleep -Seconds 30
    Invoke-CitUsoClientAction -Action 'StartDownload'
    Invoke-CitUsoClientAction -Action 'StartInstall'

    Write-CITLog -Message "Remediation triggered for KB $expectedKb - install may complete after reboot" -Level INFO -ScriptName 'Remediate-SecureBootCert'

    [PSCustomObject]@{
        Status    = 'UPDATE_TRIGGERED'
        Kb        = $expectedKb
        Build     = $buildNumber
        RebootMsg = 'A reboot may be required for the update to complete'
    } | ConvertTo-Json -Compress | Write-Output

    Write-CITLog -Message 'Secure Boot certificate remediation complete' -Level INFO -ScriptName 'Remediate-SecureBootCert'

    exit 0
} catch {
    Write-CITLog -Message "Remediation error: $($_.Exception.Message)" -Level ERROR -ScriptName 'Remediate-SecureBootCert'
    exit 2
}