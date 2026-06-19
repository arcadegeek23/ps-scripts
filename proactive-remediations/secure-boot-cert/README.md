# secure-boot-cert

## Purpose

Detects whether a device has the Secure Boot DBX certificate refresh applied (the June 2026 Microsoft cumulative update that refreshes expired UEFI Secure Boot signing certificates). If the KB is missing, the remediation triggers Windows Update to scan, download, and install the update.

## Background

Microsoft announced a Secure Boot certificate expiration fix starting June 2026. The expired certificates are the 2011 cross-signed UEFI Secure Boot certificates. The fix ships in the monthly cumulative update as a DBX revocation list refresh. Devices that are not updated will continue to boot but may miss important future security protections.

CIT is currently handling this through manual client outreach (7+ tickets/week, each requiring approval cycles and deployment scheduling). This PIA pair automates the detect-and-trigger workflow so the fleet self-heals without per-client ticket work.

## What "compliant" means

The device has the required KB installed for its OS build:

| OS Build | KB |
|---|---|
| Win10 22H2 (19045) | KB5063610 |
| Win11 23H2 (22631) | KB5063917 |
| Win11 24H2 (26100) | KB5063915 |
| Win11 25H2 (26200) | KB5063915 |

**Exception:** If Secure Boot is disabled (`Confirm-SecureBootUEFI` returns `$false`), the device is automatically compliant -- the certificate expiration does not apply.

**Exception:** If the OS build is not in the KB map (unknown/newer build), the device is treated as compliant -- no action is defined for that build yet. Update the `$SecureBootKbMap` hash table in both scripts when new builds are released.

## What the remediation does

1. Re-checks whether the KB is already installed (idempotency). If yes, exits 0 without action.
2. Stops `wuauserv`, clears `C:\Windows\SoftwareDistribution\Download`, restarts `wuauserv`.
3. Triggers `UsoClient StartScan` -> 30s wait -> `StartDownload` -> `StartInstall`.
4. The actual KB install may complete after a reboot -- that is expected. The script does NOT force a reboot. Windows Update will prompt the user natively.

**Blast radius:** Clears the WU download cache and triggers an update scan/download/install. Same pattern as the existing `CIT-PIA-WUFix-Generic.ps1`. No registry mutations, no service deletions, no forced reboots.

## Exit codes

- **Detect:** 0 = compliant, 1 = non-compliant (KB missing), 2+ = error
- **Remediate:** 0 = success (update triggered or already installed), 2+ = error

## Scripts

| Script | Purpose |
|---|---|
| `Detect-SecureBootCert.ps1` | Checks Secure Boot status + KB installation. Zero side effects. |
| `Remediate-SecureBootCert.ps1` | Triggers WU to download/install the missing KB. Idempotent. |

## Updating the KB map

The `$SecureBootKbMap` hash table at the top of both scripts maps OS build numbers to KB IDs. When Microsoft releases the confirmed June 2026 KBs (or future updates), update both files:

```powershell
$SecureBootKbMap = @{
    '19045' = 'KB5063610'   # Win10 22H2
    '22631' = 'KB5063917'   # Win11 23H2
    '26100' = 'KB5063915'   # Win11 24H2
    '26200' = 'KB5063915'   # Win11 25H2
}
```

**Important:** The KB numbers above are the June 2026 cumulative updates based on the standard Microsoft patch cadence. Verify the exact KBs on the Microsoft Update Catalog or the Windows release health dashboard before deploying. The hash table is the only place to change them.

## Pester tests

Run all tests from the repo root:

```powershell
Invoke-Pester ./proactive-remediations/secure-boot-cert/
```

Test coverage:
- Syntax parse (both scripts)
- Expected helper functions present
- KB map hash table has required build entries
- CIT-Logging.ps1 sourced with correct path
- Detect has zero side effects (no Stop-Service, Remove-Item, Set-ItemProperty, Start-Process)
- Remediate has idempotency check
- Remediate does not force reboot
- Remediate triggers UsoClient scan/download/install
- Log file created on Windows

## Test history

- 2026-06-19 Created. Pester tests not yet run on this machine (no PowerShell on macOS). Run on a Windows box with Pester 5+ before deploying.

## Deploy history

- Not yet deployed. Pilot guidance: 1-2 CIT devices with Secure Boot enabled, hourly detection schedule. Verify the KB map against the actual June 2026 KBs before assigning broadly.

## References

- Microsoft: Secure Boot certificate expiration - https://learn.microsoft.com/en-us/windows/security/hardware-security/secure-boot
- Microsoft: KB5063610 (Win10 22H2 June 2026) - https://support.microsoft.com/help/5063610
- Microsoft: KB5063917 (Win11 23H2 June 2026) - https://support.microsoft.com/help/5063917
- Microsoft: KB5063915 (Win11 24H2 June 2026) - https://support.microsoft.com/help/5063915