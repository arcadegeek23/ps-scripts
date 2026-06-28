# HP BIOS Update for Secure Boot - Proactive Remediation

## Purpose

HP EliteBooks (particularly G6/G7 generation) with outdated firmware reject
the Windows UEFI CA 2023 Secure Boot database write. The OS-side servicing
task triggers correctly (our Secure Boot cert PIA sets `AvailableUpdates=0x5944`),
but the firmware returns `0x80004005` (E_FAIL) and Event ID 1797:

> "The Secure Boot update failed as the Windows UEFI CA 2023 certificate
> is not present in Db."

This PIA detects that specific failure pattern on HP devices and flashes the
latest HP BIOS automatically. After the BIOS update + reboot, the existing
Secure Boot cert PIA completes the cert transition.

## Position in the PIA stack

```
[THIS PIA] HP BIOS Update
    -> Fixes firmware (root cause)
    -> After reboot:
       [EXISTING] Secure Boot Cert (118af8e1)
           -> Sets AvailableUpdates=0x5944
           -> Windows servicing task writes cert to Db (now succeeds)
           -> After cert update:
              [EXISTING] BitLocker Re-Seal (ba7f7923)
                  -> Suspends BL for 1 reboot
                  -> BitLocker re-seals to new PCR 7 values
```

This PIA sits **upstream** of the other two. It fixes the root cause (firmware)
so the downstream PIAs can complete their work.

## Detection logic

The detect script flags a device as non-compliant only when ALL of:
1. Manufacturer is HP (matches "HP", "Hewlett-Packard", "HP Inc.")
2. `UEFICA2023Error` = 2147500037 (0x80004005, E_FAIL)
3. Latest Secure Boot event in System log = Event ID 1797
4. No prior BIOS update sentinel (`HKLM:\SOFTWARE\CIT\HPBIOSUpdate\Applied`)

Non-HP devices exit compliant immediately. HP devices without the 1797 error
exit compliant. Devices that have already been flashed exit compliant.

## Remediation logic

1. **Idempotency check** - exit if sentinel already set
2. **Install HPCMSL** - `Install-Module HPCMSL -Force -Scope AllUsers` if not present
3. **BIOS password check** - if password is set, write sentinel + exit with `BIOS_PASSWORD_REQUIRED` (manual handling needed)
4. **Suspend BitLocker** - `Suspend-BitLocker -MountPoint C: -RebootCount 1` (auto-resumes on next reboot)
5. **Flash BIOS** - `Get-HPBIOSUpdates -Flash -BitLocker Suspend -Force -Yes`
6. **Write sentinel** - `HKLM:\SOFTWARE\CIT\HPBIOSUpdate\Applied = 1`
7. **Return** `REBOOT_REQUIRED` - flash stages silently, applies on next restart

## Sentinel values

| Applied value | Meaning |
|---------------|---------|
| 1 | Flash succeeded |
| 2 | HPCMSL install failed |
| 3 | BIOS password is set (manual intervention needed) |
| 4 | Flash failed (check Note field for error) |
| 5 | Unhandled exception |

## What this does NOT do

- Does NOT force a reboot (user reboots naturally, or Datto schedules it)
- Does NOT clear Secure Boot keys (not needed when BIOS update adds 2023 cert support)
- Does NOT touch non-HP devices (detection exits immediately)
- Does NOT re-trigger after sentinel is written (fire-once per device)

## Testing

```bash
# Parse validation (Mac with pwsh 7)
pwsh -NoProfile -Command "& { Get-Content Detect-HPBIOS.ps1 | Out-Null }"
pwsh -NoProfile -Command "& { Get-Content Remediate-HPBIOS.ps1 | Out-Null }"

# Pester tests
pwsh -NoProfile -Command "Invoke-Pester Detect-HPBIOS.Tests.ps1"
pwsh -NoProfile -Command "Invoke-Pester Remediate-HPBIOS.Tests.ps1"
```

**Manual testing required on a real HP device before production rollout**
(Kyle's standing rule: build, manually test, then automate).

Test on one of the two failing devices:
- CIT-CM-54659 (Sarah Burns, HP EliteBook 850 G6)
- CIT-CM-55174 (Chris Carignan, HP EliteBook 840 G7)

## Deployment

1. Upload both scripts to Intune portal as a new Proactive Remediation:
   - Display name: `CIT - HP BIOS Update for Secure Boot`
   - Publisher: `CIT Solutions`
   - Run as: `SYSTEM` (required for BIOS flash + BitLocker suspension)
2. Assign to pilot group first: `CIT-Secure Boot Pilot` (2f2789cd-cdda-4ebe-a076-b310a05a0e01)
3. Schedule: hourly detection
4. After pilot validation, expand to `CIT - Workstations (Win11 fleet)` (e54908d3-50cf-4e41-aba2-f432f1868e90)

## Verification after deployment

```powershell
# Check sentinel
Get-ItemProperty 'HKLM:\SOFTWARE\CIT\HPBIOSUpdate' | Select Applied, Date, Note

# After reboot, check if Secure Boot cert transition completed
Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\SecureBoot\Servicing' | Select UEFICA2023Status, UEFICA2023Error

# Should show: UEFICA2023Status = Updated, UEFICA2023Error = 0
```

## Risks and mitigations

| Risk | Mitigation |
|------|-----------|
| BIOS flash fails mid-update | HP EliteBooks have dual-BIOS redundancy (auto-rollback) |
| BitLocker recovery prompt | Suspend-BitLocker before flash + existing re-seal PIA after |
| HPCMSL not in PowerShell Gallery | Remediate script installs it first (`Install-Module`) |
| BIOS password set on device | Script checks and returns `BIOS_PASSWORD_REQUIRED` for manual handling |
| Non-HP devices affected | Detection exits compliant immediately for non-HP manufacturers |
| Repeated flash attempts | Fire-once sentinel prevents re-execution regardless of outcome |

## Files

| File | Purpose |
|------|---------|
| `Detect-HPBIOS.ps1` | Detection script - flags HP devices with 1797 firmware rejection |
| `Remediate-HPBIOS.ps1` | Remediation script - installs HPCMSL, suspends BL, flashes BIOS |
| `Detect-HPBIOS.Tests.ps1` | Pester tests for detection |
| `Remediate-HPBIOS.Tests.ps1` | Pester tests for remediation |
| `README.md` | This file |

## Source

GitHub: `arcadegeek23/ps-scripts/proactive-remediations/hp-bios-secureboot`
Local: `~/git/ps-scripts/proactive-remediations/hp-bios-secureboot/`