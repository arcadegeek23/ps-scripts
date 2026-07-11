<#
.SYNOPSIS
  Foresight patch-detail collector for Datto RMM.

.DESCRIPTION
  The Datto RMM API exposes patch *counts* and a coarse status string, but never
  the named updates behind those counts. This Component runs on each managed
  Windows endpoint, enumerates the missing/pending and recently-failed Windows
  Updates via the Windows Update Agent COM API, and writes a compact encoded
  line into a device UDF. Foresight's Datto RMM telemetry sync reads that UDF and
  decodes it (server/connectors/dattoRmmPatchDetail.ts) so the Patch Posture view
  can show KB names, severity, and patch age instead of bare counts.

  The encoded value is written to HKLM:\SOFTWARE\CentraStage\Custom<N>, which the
  Datto agent maps to udf<N> on its next check-in. Set $UdfSlot to match the slot
  configured in Foresight (Settings -> Datto RMM patch-detail UDF, default 25).

  Deploy as a Component that runs on a schedule (recommended: daily or aligned
  with the patch window). No parameters are required; tune the variables below.

.NOTES
  - Read-only with respect to Windows Update: it searches, it does not install.
  - Targets Windows endpoints. On non-Windows / WUA-unavailable hosts it exits
    cleanly without writing a UDF.
  - The named list is capped to fit the ~255-char UDF limit; the mc/cc/fc totals
    always carry the exact counts so Foresight scoring stays accurate.
#>

# --- Configuration ----------------------------------------------------------
# UDF slot to write (must match Foresight's configured patch-detail UDF).
$UdfSlot = 25
# Max named entries to encode (oldest-first). Keeps the value under ~255 chars.
$MaxNamedEntries = 12

$ErrorActionPreference = "Stop"
$FormatVersion = "PD1"

function Get-RebootPending {
  $paths = @(
    "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\RebootPending",
    "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\RebootRequired"
  )
  foreach ($path in $paths) {
    if (Test-Path $path) { return $true }
  }
  try {
    $sysInfo = New-Object -ComObject "Microsoft.Update.SystemInfo"
    if ($sysInfo.RebootRequired) { return $true }
  } catch { }
  return $false
}

function Test-ExcludedUpdate {
  param($Update)
  # Exclude non-security noise that drags posture scores down without
  # representing real security exposure: Defender antivirus "Definition
  # Updates" reissue daily (so a device is essentially never compliant),
  # driver updates, and optional/preview picks the OS won't auto-select.
  # These should not count toward the missing/critical patch totals.
  try {
    foreach ($cat in $Update.Categories) {
      $name = ""
      try { $name = [string]$cat.Name } catch { }
      if ($name -match "(?i)definition" -or $name -match "(?i)driver") { return $true }
    }
  } catch { }
  # BrowseOnly = optional / hand-pick updates Windows won't auto-select.
  try { if ($Update.BrowseOnly) { return $true } } catch { }
  return $false
}

function Get-Severity {
  param($Update)
  $sev = ""
  try { $sev = [string]$Update.MsrcSeverity } catch { }
  if ($sev -match "Critical") { return "C" }
  $title = ""
  try { $title = [string]$Update.Title } catch { }
  if ($title -match "(?i)security|critical") { return "C" }
  return "I"
}

function Get-ReleaseDate {
  param($Update)
  try {
    $d = $Update.LastDeploymentChangeTime
    if ($d) { return (Get-Date $d -Format "yyyy-MM-dd") }
  } catch { }
  return "-"
}

function Get-KbToken {
  param($Update)
  try {
    if ($Update.KBArticleIDs -and $Update.KBArticleIDs.Count -gt 0) {
      return [string]$Update.KBArticleIDs.Item(0)
    }
  } catch { }
  # No KB (driver / Defender definition): use a short, sanitized title token.
  $title = ""
  try { $title = [string]$Update.Title } catch { }
  $token = ($title -replace "[^A-Za-z0-9]", "")
  if ($token.Length -gt 20) { $token = $token.Substring(0, 20) }
  if (-not $token) { $token = "Update" }
  return $token
}

function Set-DattoUdf {
  param([int]$Slot, [string]$Value)
  $key = "HKLM:\SOFTWARE\CentraStage"
  if (-not (Test-Path $key)) { New-Item -Path $key -Force | Out-Null }
  New-ItemProperty -Path $key -Name "Custom$Slot" -PropertyType String -Value $Value -Force | Out-Null
}

# --- Collect ----------------------------------------------------------------
try {
  $session = New-Object -ComObject "Microsoft.Update.Session"
} catch {
  Write-Output "Windows Update Agent unavailable; skipping patch-detail collection."
  exit 0
}

$searcher = $session.CreateUpdateSearcher()
# Missing/pending = not installed and not hidden.
$missingResult = $searcher.Search("IsInstalled=0 and IsHidden=0")
$missing = @($missingResult.Updates)

# Recently failed installs from the local Windows Update history.
$failed = @()
try {
  $historyCount = $searcher.GetTotalHistoryCount()
  if ($historyCount -gt 0) {
    $history = $searcher.QueryHistory(0, [Math]::Min($historyCount, 100))
    foreach ($entry in $history) {
      # ResultCode: 4 = Failed. Operation 1 = Installation.
      if ($entry.ResultCode -eq 4 -and $entry.Operation -eq 1) {
        $failed += $entry
      }
    }
  }
} catch { }

$rebootPending = Get-RebootPending
$scanDate = Get-Date -Format "yyyy-MM-dd"

# Build named entries (oldest release date first so the cap keeps the oldest).
$missingEntries = @()
foreach ($u in $missing) {
  # Skip definition/driver/optional updates so posture reflects real patches.
  if (Test-ExcludedUpdate $u) { continue }
  $missingEntries += [PSCustomObject]@{
    Kb       = (Get-KbToken $u)
    Sev      = (Get-Severity $u)
    Released = (Get-ReleaseDate $u)
  }
}
$missingEntries = @($missingEntries | Sort-Object -Property @{
  Expression = { if ($_.Released -eq "-") { Get-Date } else { Get-Date $_.Released } }
})

$failedEntries = @()
foreach ($f in $failed) {
  $kb = "Update"
  $title = ""
  try { $title = [string]$f.Title } catch { }
  $m = [regex]::Match($title, "KB(\d+)")
  if ($m.Success) {
    $kb = $m.Groups[1].Value
  } else {
    $token = ($title -replace "[^A-Za-z0-9]", "")
    if ($token.Length -gt 20) { $token = $token.Substring(0, 20) }
    if ($token) { $kb = $token }
  }
  $failedEntries += "$kb~I~-"
}

$missingTotal = @($missingEntries).Count
$criticalTotal = @($missingEntries | Where-Object { $_.Sev -eq "C" }).Count
$failedTotal = @($failedEntries).Count

$named = @($missingEntries | Select-Object -First $MaxNamedEntries)
$truncated = if ($missingTotal -gt $named.Count) { 1 } else { 0 }
$missingPayload = (@($named | ForEach-Object { "$($_.Kb)~$($_.Sev)~$($_.Released)" })) -join ";"
$failedPayload = (@($failedEntries | Select-Object -First $MaxNamedEntries)) -join ";"

$rb = if ($rebootPending) { 1 } else { 0 }

$encoded = "$FormatVersion|s=$scanDate|rb=$rb|rs=-|mc=$missingTotal|cc=$criticalTotal|fc=$failedTotal|t=$truncated|m=$missingPayload|f=$failedPayload"

Set-DattoUdf -Slot $UdfSlot -Value $encoded

Write-Output "Patch detail written to UDF $UdfSlot."
Write-Output "  Missing: $missingTotal (critical $criticalTotal), Failed: $failedTotal, Reboot pending: $rebootPending"
Write-Output "  Encoded length: $($encoded.Length) chars"
exit 0
