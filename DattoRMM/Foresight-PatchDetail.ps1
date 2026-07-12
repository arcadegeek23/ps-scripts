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
  configured in Foresight (Settings -> Datto RMM patch-detail UDF, slot 20).

  Deploy as a Component that runs on a schedule (recommended: daily or aligned
  with the patch window). No parameters are required; tune the variables below.

.NOTES
  - Read-only with respect to Windows Update: it searches, it does not install.
  - Targets Windows endpoints. On non-Windows / WUA-unavailable hosts it exits
    cleanly without writing a UDF.
  - The named list is dynamically capped to the 255-char UDF limit. The mc/cc/fc
    totals stay exact for scoring; dc/oc/dfc preserve excluded-class counts for
    overall device-health reporting.
#>

# --- Configuration ----------------------------------------------------------
# UDF slot to write (must match Foresight's configured patch-detail UDF).
$UdfSlot = 20
# Max named entries to encode (oldest-first). Keeps the value under ~255 chars.
$MaxNamedEntries = 12
$MaxUdfLength = 255

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

function Get-UpdateClass {
  param($Update)

  # UpdateType 2 is a driver. Keep the category fallback for WUA variants that
  # expose the enum as a string or omit Type through COM interop.
  try {
    $typeValue = $Update.Type
    if ([string]$typeValue -match "(?i)driver" -or [int]$typeValue -eq 2) {
      return "Driver"
    }
  } catch { }

  $isDefinition = $false
  try {
    foreach ($cat in $Update.Categories) {
      $name = ""
      try { $name = [string]$cat.Name } catch { }
      if ($name -match "(?i)driver") { return "Driver" }
      if ($name -match "(?i)definition") { $isDefinition = $true }
    }
  } catch { }
  if ($isDefinition) { return "Definition" }

  # BrowseOnly updates are optional and not intended for automatic processing.
  try { if ($Update.BrowseOnly) { return "Optional" } } catch { }
  return "Scored"
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

  if (-not $Value.StartsWith("PD1|", [System.StringComparison]::Ordinal)) {
    throw "Refusing to write a non-PD1 patch-detail value to Datto UDF $Slot."
  }

  $key = "HKLM:\SOFTWARE\CentraStage"
  $propertyName = "Custom$Slot"
  if (-not (Test-Path $key)) { New-Item -Path $key -Force | Out-Null }
  $writeResult = New-ItemProperty -Path $key -Name $propertyName -PropertyType String -Value $Value -Force
  $writtenProperty = $writeResult.PSObject.Properties[$propertyName]
  if (-not $writtenProperty -or [string]$writtenProperty.Value -cne $Value) {
    throw "Registry write verification failed for $key\$propertyName."
  }

  try {
    $readBack = [string](Get-ItemPropertyValue -Path $key -Name $propertyName -ErrorAction Stop)
    if ($readBack -cne $Value) {
      throw "Registry read-back verification failed for $key\$propertyName."
    }
    return "verified"
  } catch [System.Management.Automation.ItemNotFoundException] {
    return "consumed by the Datto agent"
  } catch [System.Management.Automation.PSArgumentException] {
    return "consumed by the Datto agent"
  }
}

function New-PatchDetailPayload {
  param(
    [string]$Version,
    [string]$ScanDate,
    [int]$RebootFlag,
    [int]$MissingTotal,
    [int]$CriticalTotal,
    [int]$FailedTotal,
    [int]$DriverTotal,
    [int]$OptionalTotal,
    [int]$DefinitionTotal,
    [string[]]$MissingEntries,
    [string[]]$FailedEntries,
    [int]$MaxEntries,
    [int]$MaxLength
  )

  $selectedMissing = @($MissingEntries | Select-Object -First $MaxEntries)
  $selectedFailed = @($FailedEntries | Select-Object -First $MaxEntries)
  $truncated = if (
    @($MissingEntries).Count -gt $selectedMissing.Count -or
    @($FailedEntries).Count -gt $selectedFailed.Count
  ) { 1 } else { 0 }

  while ($true) {
    $missingPayload = $selectedMissing -join ";"
    $failedPayload = $selectedFailed -join ";"
    $payload = "$Version|s=$ScanDate|rb=$RebootFlag|rs=-|mc=$MissingTotal|cc=$CriticalTotal|fc=$FailedTotal|dc=$DriverTotal|oc=$OptionalTotal|dfc=$DefinitionTotal|t=$truncated|m=$missingPayload|f=$failedPayload"
    if ($payload.Length -le $MaxLength) { return $payload }

    $truncated = 1
    if ($selectedMissing.Count -ge $selectedFailed.Count -and $selectedMissing.Count -gt 0) {
      $selectedMissing = @($selectedMissing | Select-Object -First ($selectedMissing.Count - 1))
    } elseif ($selectedFailed.Count -gt 0) {
      $selectedFailed = @($selectedFailed | Select-Object -First ($selectedFailed.Count - 1))
    } else {
      throw "Patch-detail totals exceed the $MaxLength-character Datto UDF limit."
    }
  }
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
$driverTotal = 0
$optionalTotal = 0
$definitionTotal = 0
foreach ($u in $missing) {
  $updateClass = Get-UpdateClass $u
  if ($updateClass -eq "Driver") {
    $driverTotal++
    continue
  }
  if ($updateClass -eq "Optional") {
    $optionalTotal++
    continue
  }
  if ($updateClass -eq "Definition") {
    $definitionTotal++
    continue
  }
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

$missingTokens = @($missingEntries | ForEach-Object { "$($_.Kb)~$($_.Sev)~$($_.Released)" })
$failedTokens = @($failedEntries)

$rb = if ($rebootPending) { 1 } else { 0 }

$encoded = New-PatchDetailPayload `
  -Version $FormatVersion `
  -ScanDate $scanDate `
  -RebootFlag $rb `
  -MissingTotal $missingTotal `
  -CriticalTotal $criticalTotal `
  -FailedTotal $failedTotal `
  -DriverTotal $driverTotal `
  -OptionalTotal $optionalTotal `
  -DefinitionTotal $definitionTotal `
  -MissingEntries $missingTokens `
  -FailedEntries $failedTokens `
  -MaxEntries $MaxNamedEntries `
  -MaxLength $MaxUdfLength

$writeStatus = Set-DattoUdf -Slot $UdfSlot -Value $encoded

Write-Output "Patch detail written to UDF $UdfSlot ($writeStatus)."
Write-Output "  Encoded value: $encoded"
Write-Output "  Missing: $missingTotal (critical $criticalTotal), Failed: $failedTotal, Reboot pending: $rebootPending"
Write-Output "  Excluded from score: drivers $driverTotal, optional $optionalTotal, definitions $definitionTotal"
Write-Output "  Encoded length: $($encoded.Length) chars"
exit 0
