# secure-boot-cert

## Purpose

Detects whether a device has completed the Secure Boot 2011-to-2023 certificate transition and, if not, sets the `AvailableUpdates` registry bitmask to trigger the Windows servicing task that applies the new certificates.

## Background

Microsoft's 2011 UEFI Secure Boot certificates expire mid-2026. The 2023 replacement certificates are applied via a Windows scheduled task that runs approximately every 12 hours. The task checks the `AvailableUpdates` registry bitmask and, if set to `0x5944`, performs the full update sequence:

1. Add 2023 DB entries (Windows UEFI CA 2023 + Option ROM UEFI CA 2023)
2. Update the KEK
3. Update the boot manager to the 2023-signed version

**The monthly cumulative KB alone does NOT apply the certificates.** The KB delivers the payload, but the registry bitmask is what triggers the OS-side servicing flow. This is the gap that caused BitLocker recovery prompts on CIT desktops -- the KB was present but the certificate servicing task was never activated.

## What "compliant" means

The device has `UEFICA2023Status = "Updated"` in the registry:

```
HKLM\SYSTEM\CurrentControlSet\Control\SecureBoot\Servicing
```

| Value Name | Type | Values |
|---|---|---|
| `UEFICA2023Status` | string | `NotStarted` / `InProgress` / `Updated` |
| `AvailableUpdates` | DWORD | `0x5944` = full sequence; `0` = not set |
| `UEFICA2023Error` | DWORD | `0` = OK; non-zero = failure code |
| `HighConfidenceOptOut` | DWORD | `1` = block auto monthly deploy; `0` = allow |
| `MicrosoftUpdateManagedOptIn` | DWORD | CFR opt-in for Microsoft-managed rollout |

**Compliant:** `UEFICA2023Status = "Updated"` (exit 0)

**Non-compliant:** `NotStarted`, `InProgress`, error state, or registry not set (exit 1)

**Exception:** If Secure Boot is disabled (`Confirm-SecureBootUEFI` returns `$false`), the device is automatically compliant -- the certificate expiration does not apply.

## What the remediation does

1. **Idempotency:** If `UEFICA2023Status = "Updated"`, exits 0 without action.
2. **Check for prior error:** If `UEFICA2023Error` is non-zero, logs a warning but continues (retry may succeed if the error was transient).
3. **Set the bitmask:** Sets `AvailableUpdates = 0x5944` (DWORD) under `HKLM:\SYSTEM\CurrentControlSet\Control\SecureBoot\Servicing`. This tells the Windows scheduled task to perform the full cert update sequence on its next run.
4. **Trigger the task immediately:** Attempts to start the SecureBoot servicing scheduled task (`\Microsoft\Windows\SecureBoot\CertificateUpdate`) rather than waiting up to 12 hours for the next scheduled run. Non-fatal if the task path is not found.
5. **No forced reboot.** The servicing task handles reboots natively. Some steps in the sequence require a restart to complete.

**Blast radius:** Sets one registry DWORD under HKLM. Does not clear WU cache, stop services, delete files, or force reboots. The Windows scheduled task performs the actual firmware writes.

## Event log IDs to monitor (System log)

| Event ID | Meaning |
|---|---|
| 1808 | Success -- certs applied and boot manager updated |
| 1801 | Failure during cert apply -- check `UEFICA2023Error` |
| 1795 | Firmware rejected variable write -- OEM firmware update needed |

## Exit codes

- **Detect:** 0 = compliant, 1 = non-compliant, 2+ = error
- **Remediate:** 0 = success (bitmask set or already compliant), 2+ = error

## Scripts

| Script | Purpose |
|---|---|
| `Detect-SecureBootCert.ps1` | Reads `UEFICA2023Status` registry value. Zero side effects. |
| `Remediate-SecureBootCert.ps1` | Sets `AvailableUpdates=0x5944` + triggers servicing task. Idempotent. |

## Deployment options

### Option A: Intune Proactive Remediation (recommended)

Deploy as a deviceHealthScript (Proactive Remediation) pair assigned to the workstation fleet. Detection runs hourly; remediation fires only when non-compliant.

1. Upload detect + remediate scripts to Intune (portal or Graph).
2. Assign to the **CIT - Workstations (Win11 fleet)** group (`e54908d3-50cf-4e41-aba2-f432f1868e90`).
3. Schedule: hourly detection.
4. Monitor via `deviceRunStates` -- look for `UEFICA2023Status` transitions.

### Option B: Intune Settings Catalog policy

Microsoft also exposes three Settings Catalog policies that map to the registry keys:

| Setting | Registry key | Value |
|---|---|---|
| Enable Secureboot Certificate Updates | `AvailableUpdates` | Enabled = sets `0x5944` |
| Configure Microsoft Update Managed Opt In | `MicrosoftUpdateManagedOptIn` | Enabled = opt into CFR |
| Configure High Confidence Opt-Out | `HighConfidenceOptOut` | Disabled (default) = allow auto deploy |

Create a Settings Catalog profile (Windows 10 and later) in the Intune portal, search for "Secure Boot", add the three settings, and assign to the workstation group.

**Note:** The Proactive Remediation (Option A) gives better telemetry -- you can see per-device status and error states. The Settings Catalog policy (Option B) is simpler to deploy but has less per-device visibility. You can use both: Settings Catalog for the opt-in keys + Proactive Remediation for monitoring and remediation.

## Prerequisites

- **Diagnostic data:** For Microsoft-managed CFR assistance, devices must send Required diagnostic data (level 1). Check via `HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection\AllowTelemetry`.
- **BitLocker recovery keys:** Ensure BitLocker recovery keys are escrowed in Azure AD/Entra ID before deploying. The cert update can trigger a BitLocker recovery prompt because the measured boot state changes.
- **Firmware:** Some older devices may reject the firmware variable writes (Event ID 1795). These need an OEM firmware update before the OS-side flow can succeed.

## Verification

Run elevated on a target device after remediation:

```powershell
# Check status
Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\SecureBoot\Servicing' | Select-Object UEFICA2023Status, UEFICA2023Error, AvailableUpdates

# Confirm the 2023 cert is in the DB
[Text.Encoding]::ASCII.GetString((Get-SecureBootUEFI db).bytes) -match 'Windows UEFI CA 2023'

# Check event log for success
Get-WinEvent -LogName System -MaxEvents 50 | Where-Object { $_.Id -in 1795, 1801, 1808 }
```

## Test history

- 2026-06-19 Created. KB-based detection only.
- 2026-06-20 Rewritten to use registry-status detection (UEFICA2023Status) + bitmask remediation (AvailableUpdates=0x5944) per Microsoft's official Secure Boot playbook.

## Deploy history

- Not yet deployed. Pilot guidance: 2-3 CIT devices with Secure Boot enabled + BitLocker, hourly detection. Verify BitLocker recovery keys are escrowed before deploying broadly.

## References

- Microsoft: Secure Boot playbook for certificates expiring in 2026 -- https://techcommunity.microsoft.com/blog/windows-itpro-blog/secure-boot-playbook-for-certificates-expiring-in-2026/4469235
- Microsoft: Registry key updates for Secure Boot -- https://support.microsoft.com/en-us/topic/registry-key-updates-for-secure-boot-windows-devices-with-it-managed-updates-a7be69c9-4634-42e1-9ca1-df06f43f360d
- Microsoft: Intune method for Secure Boot -- https://support.microsoft.com/en-us/topic/microsoft-intune-method-of-secure-boot-for-windows-devices-with-it-managed-updates-1c4cf9a3-8983-40c8-924f-44d9c959889d
- Microsoft: Update Secure Boot Certificates for Windows Devices -- https://learn.microsoft.com/en-us/troubleshoot/windows-client/windows-security/update-secure-boot-certificates
- Microsoft: Applying Secure Boot settings using model-based targeting in Intune -- https://support.microsoft.com/en-us/topic/applying-secure-boot-certificate-update-settings-using-model-based-targeting-in-microsoft-intune-7f2dd4da-5e24-4514-9a2c-bb8a3d0e94e1