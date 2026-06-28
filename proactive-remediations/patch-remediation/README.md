# patch-remediation

## Purpose

PowerShell scripts that diagnose and remediate Windows Update patch-install failures. The diagnostic script (`CIT-PIA-WUDiag`) emits structured JSON that a future PIA workflow can read to pick one of four fix branches: disk cleanup, reboot, WU component reset, or generic soft reset.

This folder intentionally does **not** follow the standard Detect/Remediate pair pattern. It is a PIA.ai execution bundle: one diagnostic + four branch-specific remediations. All scripts still honor the repo's exit-code contract and source `CIT-Logging.ps1`.

## Scripts

| Script | Branch | Purpose | Exit codes |
|---|---|---|---|
| `CIT-PIA-WUDiag.ps1` | n/a | Diagnoses failure mode, outputs JSON | 0 = no fix, 1 = fix needed, 2+ = error |
| `CIT-PIA-WUFix-DiskClean.ps1` | A | Frees disk space | 0 = success, 2+ = error |
| `CIT-PIA-WUFix-Reboot.ps1` | B | Handles pending reboot | 0 = success, 2+ = error |
| `CIT-PIA-WUFix-Components.ps1` | C | Resets WU components | 0 = success, 2+ = error |
| `CIT-PIA-WUFix-Generic.ps1` | D | Soft WU reset | 0 = success, 2+ = error |

## Manual test playbook (pilot device)

Run these in order on a pilot device. Each script emits JSON or key-value pairs to stdout and writes to `C:\ProgramData\CIT\Logs\<ScriptName>.log`.

1. **Baseline diagnostic**

   ```powershell
   cd proactive-remediations\patch-remediation
   .\CIT-PIA-WUDiag.ps1
   ```

   Expected output: a single line of compressed JSON showing `RecommendedFix`. If the device is healthy, exit code is `0`. If a fix is needed, exit code is `1`.

2. **Branch A — Disk cleanup** (only if `RecommendedFix = DISKCLEAN`)

   ```powershell
   .\CIT-PIA-WUFix-DiskClean.ps1
   ```

   Expected output: JSON with `Status = COMPLETE` and `FreeSpaceAfterGB`. Takes 5-15 minutes depending on DISM.

3. **Branch B — Reboot** (only if `RecommendedFix = REBOOT`)

   ```powershell
   .\CIT-PIA-WUFix-Reboot.ps1
   ```

   - No interactive user (detected reliably via the explorer.exe owner): emits `Action = IMMEDIATE_REBOOT`, flushes stdout, then schedules `shutdown /r /t 15`.
   - Logged-in user **or uncertain detection**: outputs `Action = SCHEDULE_VIA_DATTO` and does **not** reboot (fail-closed).

   To force a reboot during testing, use:

   ```powershell
   .\CIT-PIA-WUFix-Reboot.ps1 -Force
   ```

4. **Branch C — WU component reset** (only if `RecommendedFix = WUCOMPONENTS`)

   ```powershell
   .\CIT-PIA-WUFix-Components.ps1
   ```

   Expected output: JSON with `Status = COMPLETE` and `RebootRecommended = true`. DISM + SFC can take 15-30 minutes. Reboot the device afterward, then re-run `CIT-PIA-WUDiag.ps1`.

5. **Branch D — Generic reset** (only if `RecommendedFix = GENERIC`)

   ```powershell
   .\CIT-PIA-WUFix-Generic.ps1
   ```

   Expected output: JSON with `Status = COMPLETE` only when the cache clear and the update cycle actually succeed; otherwise `Status = FAILED` and a non-zero exit. Clears `SoftwareDistribution\Download` and drives scan/download/install through the Windows Update COM API (works under SYSTEM / session 0); `UsoClient.exe` is only a best-effort fallback.

6. **Verify**

   After any remediation branch completes, re-run:

   ```powershell
   .\CIT-PIA-WUDiag.ps1
   ```

   Expected: exit code `0` (no fix recommended) unless the device legitimately still needs a reboot.

## Pester tests

Run all tests from the repo root:

```powershell
Invoke-Pester ./proactive-remediations/patch-remediation/
```

Required test cases are included for each script: syntax parse, mocked success path, mocked failure path, and log-file creation.

## Test history

- 2026-06-13 Created from `~/me/Vault/Projects/Pia/pia-windows-update-automation.md`. Pester tests pass locally.

## Deploy history

- Not yet deployed. Pilot guidance: 1-2 CIT devices, hourly detection schedule.

## References

- Microsoft: Reset Windows Update components — https://support.microsoft.com/en-us/topic/reset-windows-update-components-8b65f8f4-4f60-9a56-5cf1f0f9caa5
- Microsoft: Clean up the WinSxS folder — https://learn.microsoft.com/en-us/windows-hardware/manufacture/desktop/clean-up-the-winsxs-folder
