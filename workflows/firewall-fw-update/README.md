# firewall-fw-update

## Purpose

PowerShell package for backing up and upgrading customer firewall firmware from a PIA probe device (Windows box on the customer LAN). v1 supports SonicWall and Fortinet via SSH with Posh-SSH. WatchGuard is a phase-2 stub.

This folder intentionally does **not** follow the standard Detect/Remediate pair pattern. It is a PIA.ai execution bundle: one diagnostic plus four remediation activities. All scripts honor the repo's exit-code contract and source `CIT-Logging.ps1`.

## Vendor scope

| Vendor    | Status | Connection |
|---|---|---|
| SonicWall | v1 implemented | SSH / Posh-SSH |
| Fortinet  | v1 implemented | SSH / Posh-SSH |
| WatchGuard | Phase 2 stub | HTTPS REST API on port 8080 (not yet implemented) |

## Scripts

| Script | Activity | Purpose | Exit codes |
|---|---|---|---|
| `FW-Diag.ps1` | Diagnostic | Gather model, firmware, HA state, uptime JSON | 0 = healthy, 1 = upgrade needed, 2+ = error (incl. `NO_TARGET_BASELINE` when `-TargetFirmware` is omitted) |
| `FW-Backup.ps1` | Pre-upgrade | Save config to `\\<probe>\FWBackups\<site>\<model>_<timestamp>.cfg\|conf` | 0 = success, 2+ = error |
| `FW-StageFirmware.ps1` | Pre-upgrade | SCP firmware image to firewall; do not install | 0 = staged, 2+ = error |
| `FW-ApplyUpdate.ps1` | Upgrade | Install staged image and reboot; HA-aware | 0 = initiated or schedule-needed, 2+ = error |
| `FW-Verify.ps1` | Post-upgrade | Wait up to 15 min for reboot and confirm firmware/uptime | 0 = verified, 1 = recovery needed, 2+ = error |

## Safety rails

- **No mutation in `FW-Diag.ps1`.** It only reads state.
- **Maintenance window gate in `FW-ApplyUpdate.ps1`.** Without `-MaintenanceWindow`, the script checks local business hours (06:00-22:00 by default, configurable). Inside the window it returns `SCHEDULE_VIA_HALOPSA` and exits `0`.
- **HA-aware apply.** Active units with a present peer are failed over before upgrade. Single-unit firewalls abort with `NEEDS_CHANGE_WINDOW` unless `-AllowSingleUnitWithoutWindow` is explicitly passed.
- **No plaintext credentials.** Use per-probe SSH key, `PIA_FW_CREDENTIAL` env var, or the ITGlue stub (not implemented in v1).
- **Abort on backup failure.** `FW-Backup.ps1` does not continue if the config export cannot be written.
- **Verify deadline.** `FW-Verify.ps1` polls for 15 minutes by default; if the firewall does not come back with the expected firmware and uptime < 1 day, it returns `RECOVERY_NEEDED`.

## Manual test playbook (pilot device)

1. **Install Posh-SSH on the probe** machine-wide if not already present.

   The Intune agent runs these scripts as `NT AUTHORITY\SYSTEM`. A module
   installed `-Scope CurrentUser` lives in the operator profile and is
   invisible to SYSTEM, so it must be installed `-Scope AllUsers`. The FW-*
   scripts gate on Posh-SSH and emit `POSH_SSH_UNAVAILABLE` (exit 2) rather
   than crashing if it is missing.

   ```powershell
   Install-Module Posh-SSH -Scope AllUsers -Force
   ```

2. **Diagnostic**

   ```powershell
   cd workflows\firewall-fw-update
   .\FW-Diag.ps1 -FirewallAddress 192.168.1.1 -Vendor SonicWall -TargetFirmware 'SonicOS 7.1.2-7018-R6177'
   ```

   Expected: JSON with `UpgradeNeeded` and exit `0` or `1`.

3. **Backup**

   ```powershell
   .\FW-Backup.ps1 -FirewallAddress 192.168.1.1 -Vendor SonicWall -SiteCode ACME -BackupRoot '\\probe\FWBackups'
   ```

   Expected: JSON with `Success = true` and the path to the `.exp` or `.conf` file.

4. **Stage firmware**

   ```powershell
   .\FW-StageFirmware.ps1 -FirewallAddress 192.168.1.1 -Vendor SonicWall -ImagePath 'C:\Firmware\SonicOS-7.1.2-7018-R6177.sig'
   ```

   Expected: JSON with `Staged = true`.

5. **Apply update**

   ```powershell
   .\FW-ApplyUpdate.ps1 -FirewallAddress 192.168.1.1 -Vendor SonicWall -ImagePath 'C:\Firmware\SonicOS-7.1.2-7018-R6177.sig' -MaintenanceWindow
   ```

   Expected: JSON with `Applied = true` and `RebootInit = true`, or a schedule/HA gate action.

6. **Verify**

   ```powershell
   .\FW-Verify.ps1 -FirewallAddress 192.168.1.1 -Vendor SonicWall -ExpectedFirmware 'SonicOS 7.1.2-7018-R6177'
   ```

   Expected: JSON with `Action = VERIFY_OK` and exit `0`, or `RECOVERY_NEEDED` after the deadline.

## Credential resolution order

Configured in `private/credential-resolution.ps1`:

1. Per-probe SSH key. Default path is `C:\ProgramData\CIT\fw-ssh.key`
   (SYSTEM-stable; a `$env:USERPROFILE`-based path resolves to the
   `systemprofile` directory under the Intune agent and is invisible). Override
   the path with `-KeyPath` or the `CIT_FW_SSH_KEY` env var, and supply the SSH
   username via `CIT_FW_SSH_USER` (defaults to `admin`) so key-file auth has a
   user to log in as.
2. `PIA_FW_CREDENTIAL` env var (base64 `username:password`).
3. ITGlue API via `ITGLUE_API_TOKEN` + `ITGLUE_SUBDOMAIN` (stub in v1).
4. Abort with `NO_CREDENTIAL_SOURCE` JSON.

SSH sessions are opened with `-AcceptKey` so first-contact host-key acceptance
does not hang under the non-interactive SYSTEM context.

## Pester tests

Run all tests from the repo root:

```powershell
Invoke-Pester ./workflows/firewall-fw-update/
```

Required test cases are included for each script: syntax parse, AST function-name presence checks, and log-file creation (skipped on non-Windows).

## Test history

- 2026-06-13 Created from coordinator task (Zeus). Pester tests pass locally on Mac; Windows log-file checks skipped.

## Deploy history

- Not yet deployed. Pilot guidance: 1-2 CIT devices with lab SonicWall/Fortinet hardware, hourly detection schedule for `FW-Diag.ps1`.

## References

- Posh-SSH module — https://github.com/darkoperator/Posh-SSH
- SonicWall CLI reference — https://www.sonicwall.com/support/knowledge-base/
- FortiOS CLI reference — https://docs.fortinet.com/document/fortigate/7.4.0/cli-reference/
