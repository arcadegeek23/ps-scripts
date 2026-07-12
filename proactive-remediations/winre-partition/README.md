# WinRE Partition Resize — Proactive Remediation

Detects and resizes an undersized Windows Recovery Environment (WinRE) partition,
which is the root cause of "Not enough free space" errors during Windows feature
updates (Windows 11 24H2+). Based on Microsoft KB5028997.

## What it does

**Detection:** Reads `reagentc /info` to find the recovery partition, then checks
its size via `Get-Partition`. Non-compliant if WinRE is disabled or partition < 600 MB.

**Remediation:** Resizes recovery partition to 1024 MB (1 GB) by:
1. Disabling WinRE (`reagentc /disable`)
2. Shrinking C: by the needed amount via `diskpart`
3. Deleting the old recovery partition
4. Creating a new partition with correct GPT type GUID + attributes
5. Re-enabling WinRE (`reagentc /enable`)
6. Verifying WinRE is enabled at the new location

## Exit Code Contract

| Exit | Script       | Meaning                                                    |
|------|--------------|------------------------------------------------------------|
| `0`  | Detection    | Compliant — recovery partition >= 600 MB                   |
| `1`  | Detection    | Non-compliant — resize needed                              |
| `2`  | Detection    | Error — reagentc or Get-Partition failed                   |
| `0`  | Remediation  | Success or already compliant                               |
| `0`  | Remediation  | Safe-bail — unsupported layout (MBR, dynamic, not last part) |
| `2`  | Remediation  | Error — diskpart or reagentc failure, check logs           |

## Safe-Bail Conditions (exits 0, detection stays non-compliant for tracking)

- MBR disk (only GPT supported)
- Dynamic disk
- Recovery partition is not the last partition on the disk
- C: has < (shrink_needed + 4096) MB free

## Blast Radius

- **Shrinks C: drive** by up to ~550 MB (typical: 500 MB recovery → 1024 MB target)
- Only runs on modern GPT layouts — bails cleanly on anything unusual
- WinRE is disabled for < 60 seconds during diskpart ops
- Idempotent: no-ops if recovery partition already >= 1024 MB
- Logs to `C:\ProgramData\CIT\Logs\Remediate-WinRePartition.log`

## Deployment

- **Schedule:** Daily (once the partition is resized, detection exits 0 and remediation is skipped)
- **Run as:** System (required for diskpart + reagentc)
- **Assignment:** `CIT Autopatch Group - Test` initially; broaden after validation
- **Intune Script ID:** see `script_id.txt` after deployment

## Tested On

- Windows 10 22H2 (19045) — GPT, single disk
- Windows 11 22H2 (22621) — GPT, single disk
- Windows 11 23H2 (22631) — GPT, single disk
- Windows 11 24H2 (26100) — GPT, single disk

## Not Supported

- MBR disks (pre-2012 hardware) — safe-bails
- Dynamic disks — safe-bails
- Devices with recovery partition not at end of disk (some OEM layouts) — safe-bails
- Devices with < 4 GB free on C: — safe-bails

## References

- [Microsoft KB5028997](https://support.microsoft.com/en-us/topic/kb5028997-instructions-to-manually-resize-your-partition-to-install-the-winre-update-400faa27-9343-461c-ada9-24c8229763bf)
- Recovery partition GPT type GUID: `de94bba4-06d1-4d40-a16a-bfd50179d6ac`
