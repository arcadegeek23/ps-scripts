#Requires -Version 5.1
# CIT-PIA-WUFix-Generic.ps1
# Performs a soft reset of Windows Update for generic patch-install failures.
# Author:  Kyle Etter
# Created: 2026-06-13
# Updated: 2026-06-27
# Tested:  Windows 10 22H2, Windows 11 23H2
# Intune:  Proactive Remediation - Remediation
# Notes:   Blast radius: clears the WU download cache and re-triggers scan/download/install.
#          Safer than the full component reset; try this before Branch C.
#          Scan/download/install run through the Windows Update COM API (works under
#          SYSTEM / session 0); UsoClient is only a best-effort fallback because its
#          verbs are deprecated / no-op on Win10 22H2 and Win11 23H2-24H2.

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
            # Verify the cache actually drained; a residual lock leaves files behind.
            $remaining = @(Get-ChildItem $downloadPath -Recurse -Force -ErrorAction SilentlyContinue)
            if ($remaining.Count -gt 0) {
                Write-CITLog -Message "WU download cache only partially cleared ($($remaining.Count) item(s) remain)" -Level WARN -ScriptName 'CIT-PIA-WUFix-Generic'
                return $false
            }
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

# Primary scan/download/install path: the Windows Update Agent COM API.
# Unlike UsoClient this works non-interactively under NT AUTHORITY\SYSTEM
# (session 0). Returns a hashtable describing what actually happened so the
# caller can gate the success token on the installer ResultCode.
function Invoke-CitComUpdateCycle {
    $outcome = @{
        Searched       = $false
        Found          = 0
        Downloaded     = 0
        Installed      = 0
        InstallResult  = -1
        RebootRequired = $false
        Succeeded      = $false
    }

    try {
        $session  = New-Object -ComObject Microsoft.Update.Session -ErrorAction Stop
        $searcher = $session.CreateUpdateSearcher()
        $searchResult = $searcher.Search("IsInstalled=0 and IsHidden=0")
        $outcome.Searched = $true
        $outcome.Found    = $searchResult.Updates.Count
        Write-CITLog -Message "COM search found $($outcome.Found) applicable update(s)" -Level INFO -ScriptName 'CIT-PIA-WUFix-Generic'

        if ($outcome.Found -eq 0) {
            # A clean scan with nothing applicable is a legitimate success: the
            # device is already current and the soft reset re-primed the cache.
            $outcome.Succeeded = $true
            return $outcome
        }

        $toProcess = New-Object -ComObject Microsoft.Update.UpdateColl
        foreach ($update in $searchResult.Updates) {
            # EULA must be accepted before unattended download/install.
            if (-not $update.EulaAccepted) {
                try { $update.AcceptEula() | Out-Null } catch { }
            }
            $toProcess.Add($update) | Out-Null
        }

        $downloader = $session.CreateUpdateDownloader()
        $downloader.Updates = $toProcess
        $downloadResult = $downloader.Download()
        # OperationResultCode 2 = orcSucceeded, 3 = orcSucceededWithErrors.
        if ($downloadResult.ResultCode -ne 2 -and $downloadResult.ResultCode -ne 3) {
            Write-CITLog -Message "COM download failed (ResultCode $($downloadResult.ResultCode))" -Level WARN -ScriptName 'CIT-PIA-WUFix-Generic'
            return $outcome
        }

        $toInstall = New-Object -ComObject Microsoft.Update.UpdateColl
        foreach ($update in $searchResult.Updates) {
            if ($update.IsDownloaded) {
                $toInstall.Add($update) | Out-Null
            }
        }
        $outcome.Downloaded = $toInstall.Count
        Write-CITLog -Message "COM downloaded $($outcome.Downloaded) update(s)" -Level INFO -ScriptName 'CIT-PIA-WUFix-Generic'

        if ($outcome.Downloaded -eq 0) {
            Write-CITLog -Message 'COM download reported success but no updates are marked downloaded' -Level WARN -ScriptName 'CIT-PIA-WUFix-Generic'
            return $outcome
        }

        $installer = $session.CreateUpdateInstaller()
        $installer.Updates = $toInstall
        $installResult = $installer.Install()
        $outcome.InstallResult  = $installResult.ResultCode
        $outcome.RebootRequired = [bool]$installResult.RebootRequired

        # Gate success strictly on the installer ResultCode.
        if ($installResult.ResultCode -eq 2 -or $installResult.ResultCode -eq 3) {
            $outcome.Installed = $outcome.Downloaded
            $outcome.Succeeded = $true
            Write-CITLog -Message "COM install completed (ResultCode $($installResult.ResultCode), RebootRequired $($outcome.RebootRequired))" -Level INFO -ScriptName 'CIT-PIA-WUFix-Generic'
        } else {
            Write-CITLog -Message "COM install failed (ResultCode $($installResult.ResultCode))" -Level WARN -ScriptName 'CIT-PIA-WUFix-Generic'
        }

        return $outcome
    } catch {
        Write-CITLog -Message "COM update cycle failed: $($_.Exception.Message)" -Level WARN -ScriptName 'CIT-PIA-WUFix-Generic'
        return $outcome
    }
}

# Best-effort fallback only. UsoClient verbs are deprecated / no-op on the
# targeted builds and under session 0, so success is NEVER gated on this.
function Invoke-CitUsoClientAction {
    param([string]$Action)

    try {
        $usoClient = Join-Path $env:windir 'System32\UsoClient.exe'
        if (Test-Path $usoClient) {
            Start-Process -FilePath $usoClient -ArgumentList $Action -Wait -WindowStyle Hidden -ErrorAction Stop
            Write-CITLog -Message "Triggered UsoClient $Action (best-effort fallback)" -Level INFO -ScriptName 'CIT-PIA-WUFix-Generic'
        }
        return $true
    } catch {
        Write-CITLog -Message "UsoClient $Action failed: $($_.Exception.Message)" -Level WARN -ScriptName 'CIT-PIA-WUFix-Generic'
        return $false
    }
}

try {
    Write-CITLog -Message 'Starting generic WU reset remediation' -Level INFO -ScriptName 'CIT-PIA-WUFix-Generic'

    Stop-CitWuauserv | Out-Null
    $cache   = Remove-CitWUDownloadCache
    $started = Start-CitWuauserv

    if (-not $started) {
        Write-CITLog -Message 'wuauserv could not be restarted' -Level ERROR -ScriptName 'CIT-PIA-WUFix-Generic'
        [PSCustomObject]@{
            Status        = 'FAILED'
            CacheCleared  = $cache
            ServiceReset  = $false
            Reason        = 'wuauserv-restart-failed'
        } | ConvertTo-Json -Compress | Write-Output
        exit 2
    }

    # Primary: drive the WU COM API (works under SYSTEM / session 0).
    $com = Invoke-CitComUpdateCycle

    # Fallback: nudge the orchestrator. Result is intentionally ignored.
    Invoke-CitUsoClientAction -Action 'StartScan' | Out-Null

    # Success requires the cache clear to have actually worked AND the COM
    # update cycle to have succeeded. Do not emit COMPLETE on a no-op.
    if ($cache -and $com.Succeeded) {
        Write-CITLog -Message 'Generic WU reset remediation complete' -Level INFO -ScriptName 'CIT-PIA-WUFix-Generic'

        [PSCustomObject]@{
            Status           = 'COMPLETE'
            CacheCleared     = $cache
            ServiceReset     = $started
            UpdatesFound     = $com.Found
            UpdatesInstalled = $com.Installed
            RebootRequired   = $com.RebootRequired
        } | ConvertTo-Json -Compress | Write-Output

        exit 0
    }

    Write-CITLog -Message 'Generic WU reset remediation did not fully succeed' -Level ERROR -ScriptName 'CIT-PIA-WUFix-Generic'

    [PSCustomObject]@{
        Status           = 'FAILED'
        CacheCleared     = $cache
        ServiceReset     = $started
        UpdatesFound     = $com.Found
        UpdatesInstalled = $com.Installed
        InstallResult    = $com.InstallResult
    } | ConvertTo-Json -Compress | Write-Output

    exit 2
} catch {
    Write-CITLog -Message "Generic WU reset remediation error: $($_.Exception.Message)" -Level ERROR -ScriptName 'CIT-PIA-WUFix-Generic'
    [PSCustomObject]@{
        Status = 'FAILED'
        Reason = 'unhandled-exception'
    } | ConvertTo-Json -Compress | Write-Output
    exit 2
}