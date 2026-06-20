# patch-compliance

## Purpose

Safety-net Proactive Remediation that detects devices behind on quality updates or feature updates and triggers Windows Update to catch them up. Runs alongside Datto RMM (which owns the approval/scheduling workflow). This script catches devices Datto missed or that were offline during the patch window.

## Compliance logic

| Condition | Result | Remediation |
|---|---|---|
| LTSC 2019 (17763) | Skip (compliant by exception) | None |
| Quality update > 14 days old | Non-compliant (`QualityUpdateStale`) | WU cache clear + scan/download/install |
| Win11 below target build (25H2) | Non-compliant (`FeatureUpdateAvailable`) | Feature update scan + download |
| Win10 22H2 (19045) | Non-compliant (`Win10EOL`) | Quality update only; feature upgrade flagged for manual handling |
| Pending reboot + stale quality | Non-compliant (`PendingReboot`) | Quality update remediation (reboot is user/Datto's call) |
| All checks pass | Compliant | None |

## Configuration

Both scripts share the same configuration block at the top:

```powershell
# Days without a quality update before flagging as stale
$QualityUpdateStaleDays = 14

# Target feature update build per OS family
$FeatureUpdateTargets = @{
    '19045' = 26200   # Win10 22H2 -> target Win11 25H2 (flagged, not auto-triggered)
    '22621' = 26200   # Win11 22H2 -> target 25H2
    '22631' = 26200   # Win11 23H2 -> target 25H2
    '26100' = 26200   # Win11 24H2 -> target 25H2
    '26200' = 26200   # Win11 25H2 -> current target (compliant)
}

# Builds to skip entirely (LTSC, thin clients, KVMs)
$SkipBuilds = @(17763)
```

Update `$FeatureUpdateTargets` when CIT adopts a new feature update (e.g., when 26H1 is released and approved). Update `$QualityUpdateStaleDays` if Datto's patch cadence changes.

## What the remediation does

### Quality update remediation
1. Stops `wuauserv`, clears `C:\Windows\SoftwareDistribution\Download`, restarts `wuauserv`
2. Triggers `UsoClient StartScan` -> 30s wait -> `StartDownload` -> `StartInstall`
3. Install may complete after reboot -- that is expected
4. Does NOT force a reboot

### Feature update remediation
1. Triggers `UsoClient StartInteractiveScan` (includes feature updates)
2. 45s wait, then `StartDownload` to fetch the feature update payload
3. Fallback: uses the Microsoft.Update.Session COM API to search and download
4. Does NOT force the upgrade install -- the user or Datto initiates the actual feature upgrade
5. Does NOT force a reboot

### Win10 EOL
- Quality updates are triggered (device should be patched on Win10)
- Feature upgrade is flagged in the output but NOT auto-triggered (Win10->Win11 needs hardware compatibility check)
- Output includes `Win10EOL-Flagged` so monitoring can identify these devices for manual upgrade planning

## Blast radius

- Clears WU download cache (same as CIT-PIA-WUFix-Generic.ps1)
- Restarts wuauserv service
- Triggers WU scan/download/install
- No registry mutations, no service deletions, no forced reboots

## Detect output format

```
Build=26200;LastUpdateDays=3;PendingReboot=False;Compliant=1
Build=22631;LastUpdateDays=45;PendingReboot=True;Compliant=0;Issues=QualityUpdateStale,FeatureUpdateAvailable;Reasons=QualityUpdateStale:45 days;FeatureUpdateAvailable:current=22631 target=26200;PendingReboot:reboot required to finalize updates
```

## Exit codes

- **Detect:** 0 = compliant, 1 = non-compliant, 2+ = error
- **Remediate:** 0 = success (remediation triggered or no action needed), 2+ = error

## Scripts

| Script | Purpose |
|---|---|
| `Detect-PatchCompliance.ps1` | Checks quality update freshness + feature update status. Zero side effects. |
| `Remediate-PatchCompliance.ps1` | Triggers WU scan/download/install for quality + feature updates. Idempotent. |

## Relationship to existing patch-remediation scripts

This pair is a **fleet-wide safety net** that runs on a schedule via Intune Proactive Remediation. The existing `patch-remediation/` scripts (`CIT-PIA-WUFix-Generic.ps1`, `CIT-PIA-WUDiag.ps1`, etc.) are **per-ticket remediation** triggered by PIA.ai when a specific device generates a HaloPSA ticket. They serve different purposes:

| | patch-compliance (this) | patch-remediation (existing) |
|---|---|---|
| Trigger | Scheduled (hourly/daily via Intune) | Per-ticket (HaloPSA -> PIA.ai) |
| Scope | Entire fleet | One device at a time |
| Purpose | Catch devices Datto missed | Fix a specific WU failure on one device |
| Diagnostic depth | Light (days since last update + build check) | Deep (disk space, pending reboot, SD size, error codes, service status) |

## Deployment

1. Upload detect + remediate scripts to Intune as a Proactive Remediation
2. Assign to **CIT - Workstations (Win11 fleet)** group (`e54908d3-50cf-4e41-aba2-f432f1868e90`)
3. Schedule: every 4-6 hours (hourly is too frequent for patch checks)
4. Monitor via deviceRunStates for compliance trends

## Test history

- 2026-06-20 Created. Parse-checked on macOS with pwsh. Not yet tested on Windows.

## Deploy history

- Not yet deployed. Pilot with the Secure Boot Pilot group first.

## References

- Microsoft: UsoClient reference - https://learn.microsoft.com/en-us/windows/deployment/update/
- Microsoft: Windows Update for Business - https://learn.microsoft.com/en-us/windows/deployment/update/waas-quick-start
- CIT: Datto vs Intune patch split - see `cit-intune-policy` skill references