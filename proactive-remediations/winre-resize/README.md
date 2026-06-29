# WinRE Recovery Partition Resize - Intune Proactive Remediation

## Before / After (plain language)

Many HP EliteBook fleet devices were shipped with a Windows Recovery Environment
(WinRE) / recovery partition that is too small. **Before:** when Windows tries to
install a Windows 11 feature update, it needs to update the recovery image but
the tiny recovery partition has no room, so the update fails with errors such as
`0x80070643` or `0x80070070` (the KB5028997 class of failure). **After:** these
two scripts detect the undersized recovery partition and (on safe, AC-powered,
properly key-escrowed devices) automatically shrink the OS partition slightly,
rebuild a larger recovery partition (~1 GB), and re-register WinRE - so feature
updates install cleanly. BitLocker is suspended around the partition work and
resumed afterward so encrypted devices stay secure and bootable.

## How it works

### Detection (`Detect-WinRESize.ps1`) - read-only, makes no changes

1. **PRIMARY signal (language-independent):** finds the Recovery-**typed**
   partition on the system disk with `Get-Partition` and measures its on-disk
   size. Partition `Type` is not localized, so this works on any OS language.
2. **SECONDARY signal (advisory only):** `reagentc /info` is parsed for the
   WinRE status, but because its output strings (e.g. `Windows RE status:
   Enabled`) are **localized**, the decision is **not** gated purely on that
   string. The reagentc result is logged for diagnostics (`reagentEnabled=...`).
   It optionally also reports free space inside the recovery volume.
3. Decision (Intune PIA exit-code convention):
   - Exactly one Recovery-typed partition AND its size **>= threshold** ->
     prints `COMPLIANT...` and `exit 0` (no remediation).
   - Recovery partition smaller than threshold, OR no Recovery-typed partition
     (WinRE on OS volume / missing), OR more than one Recovery-typed partition
     (ambiguous) -> prints `NONCOMPLIANT...` and `exit 1` (triggers remediation).
   - If detection itself errors out, it prints the error and **exits 0**
     (fail-safe / no-op). An inconclusive detection must never trigger a
     destructive remediation on an encrypted device.
4. The threshold is a variable at the top of the script (`$ThresholdBytes`,
   default **750 MB**). Microsoft guidance is ~1 GB total / ~250 MB free; we flag
   any recovery partition under 750 MB.

> **English-only detection caveat.** The primary size check is
> language-independent (partition Type), but the secondary `reagentc /info`
> parsing relies on English status strings. **Confirm the fleet is English-only,
> or validate detection against the actual OS language** before relying on the
> reagentc signal. The size-based primary check is safe across languages.

### Remediation (`Remediate-WinRESize.ps1`) - the risky one, heavily defended

- **Logging:** everything is timestamped to
  `C:\ProgramData\CIT\Logs\WinRE-Resize.log`.
- **Idempotency:** a marker file `C:\ProgramData\CIT\Logs\WinRE-Resize.done` is
  checked first; if present the script exits 0 and does nothing. The marker is
  written **only on verified success** (WinRE Enabled AND new recovery partition
  >= threshold AND BitLocker protection re-verified On).
- **Blocking marker (mid-failure safety):** a distinct marker
  `C:\ProgramData\CIT\Logs\WinRE-Resize.BLOCKED` is checked at startup. If a
  prior run failed **after** the destructive delete step (disk possibly
  partially modified), the script writes this BLOCKED marker. While it exists,
  every future run **exits 0 without acting**, so Intune does **not** blindly
  retry destructive surgery on a half-modified disk. A technician must inspect
  the device, repair the layout, and delete the marker to re-enable remediation.
- **Layout-verification preconditions (BEFORE anything destructive; abort exit 0
  if not met):** the Microsoft KB5028997 procedure only works when the recovery
  partition is the **last** partition on the disk and **immediately follows C:**,
  so that shrinking C: and deleting recovery yields one contiguous free region.
  The script reads the layout via `Get-Disk`/`Get-Partition` and verifies ALL of:
  - **exactly one** Recovery-typed partition (zero / multiple -> abort exit 0);
  - recovery partition offset is **greater** than the OS partition offset;
  - recovery **immediately follows C:** (no partition between C: end and recovery);
  - recovery is the **last** partition on the disk (highest offset);
  - **no free/unallocated gap exists earlier on the disk** (partitions are
    contiguous from the disk start through recovery, within a ~1 MB alignment
    tolerance). This guarantees the post-shrink+delete free region is a single
    contiguous trailing extent so the sizeless `create` is unambiguous.
  It then computes the achievable target size = (old recovery size + 250 MB
  shrink) and **aborts exit 0 BEFORE deleting anything** if that is below the
  threshold (default ~1024 MB) - surgery that would not fix the problem is not
  performed. Recovery-partition identity (disk/partition/offset/size) is captured
  from `Get-Partition`, **not** from `reagentc /info` (which is cleared after
  `/disable`), and re-confirmed by offset/type/size before the delete.
- **Pre-flight checks (abort cleanly with exit 0 if any fail):**
  - On AC power. Treated as AC if there is **no battery** (desktop), OR
    `Win32_Battery.BatteryStatus` is in {2,6,7,8} (AC / charging variants), OR
    Win32 `GetSystemPowerStatus` `ACLineStatus == 1` (P/Invoke). A genuinely
    plugged-in laptop is **not** aborted merely because it is charging.
  - C: has at least 300 MB free to shrink.
  - Layout verification + achievable-size check (above).
  - BitLocker state on C: is confirmed and a RecoveryPassword protector exists;
    its key protector ID is logged. If BitLocker is On it is suspended before
    partition operations.
- **Procedure (each step in try/catch, exit codes checked):**
  1. `reagentc /disable` (moves `winre.wim` onto C:).
  2. If BitLocker On: `Suspend-BitLocker -MountPoint C: -RebootCount 1` (the
     RebootCount is only a backstop; the script resumes explicitly).
  3. Re-confirm the captured layout by offset/type/size (refuse if changed).
  4. `diskpart /s <script>`: shrink the OS partition by 250 MB, `select` the old
     recovery partition (by its still-valid number) then delete it (override),
     and create a new recovery partition with a **sizeless `create partition
     primary`** (no `size=`) following Microsoft's KB5028997 procedure. Because
     the layout checks guarantee recovery is the last partition, immediately
     follows C:, and has no free gap earlier on the disk, the freed region after
     shrink+delete is a single contiguous trailing extent, so a sizeless create
     fills exactly that extent (growing recovery by the 250 MB shrink). This is
     the MS-documented form and avoids the alignment over-commit failure an
     explicit `size=` causes. GPT branch (in order): `create partition primary`,
     `format quick fs=ntfs label=Recovery`, `set id=de94bba4-06d1-4d40-a16a-bfd50179d6ac`,
     `gpt attributes=0x8000000000000001` (the `id=<GUID>` form on `create` is
     **invalid** on GPT - it is the legacy MBR byte-type usage - so the GUID is
     applied with `set id=` after create). MBR branch: `create partition primary
     id=27` (`id=27` on `create` IS valid as an MBR byte-type), then `format
     quick fs=ntfs label=Recovery`. The sizeless `create` operates on free space
     and does **not** re-select a partition number.
  5. `reagentc /enable`.
  6. **Verify success:** WinRE **Enabled** (reagentc) AND the new recovery
     partition actual size **>= threshold** (Get-Partition, language-independent).
     An undersized result is **not** treated as success.
  7. `Resume-BitLocker -MountPoint C:` if it was suspended, then **re-query**
     `Get-BitLockerVolume` and confirm `ProtectionStatus -eq 'On'`. If not, an
     explicit **ALERT** line is logged and success is withheld.
- **Failure handling:** if any partition step throws, a `finally`/recovery block
  re-reads and logs the post-failure layout, re-runs `reagentc /enable`
  (WinRE-on-C: is an acceptable interim - the device stays bootable), and - if
  the failure happened after the destructive delete - writes the **BLOCKED**
  marker and logs the FAILED state loudly. The script exits 1 on failure (Intune
  shows failed) and exits 0 only on fully verified success.

## SAFETY / PRE-DEPLOY CHECKLIST

**Read and complete this before assigning the remediation:**

- **Deploy to the PILOT ring ONLY first.** Do not assign broadly. Validate on a
  small pilot group before widening.
- **Confirm BitLocker recovery keys are escrowed in Entra ID / Intune for the
  pilot devices BEFORE assigning.** If a partition operation goes wrong, the
  recovery key is your safety net - it must already be backed up.
- **Run on AC power.** The script aborts on battery, but ensure pilot devices are
  plugged in so they actually remediate.
- **The script suspends BitLocker around the operation** and resumes it
  afterward (and it auto-resumes after one reboot via `-RebootCount 1`).
- **Verify on the 2 pilot PCs before widening:** reboot each device, confirm it
  boots normally, and run `reagentc /info` to confirm WinRE status is **Enabled**
  and located on the new (larger) recovery partition. Check the log at
  `C:\ProgramData\CIT\Logs\WinRE-Resize.log` and the `.done` marker.
- **Check for `WinRE-Resize.BLOCKED`** in `C:\ProgramData\CIT\Logs\` on any
  device that reports a failure. Its presence means a run failed mid-surgery and
  the device needs manual inspection; the remediation will keep no-opping (exit
  0) until a technician repairs the layout and deletes the marker.
- **Confirm the fleet is English-only**, or validate the detection script
  against the actual OS language. The remediation and the detection *size* check
  are language-independent (partition Type / `Get-Partition`), but the
  `reagentc /info` status string parsing assumes English.

## Deployment notes

- This is the **detect + remediate pair** to be added as a **new Intune
  Proactive Remediation (script package)**, assigned to a **WinRE pilot group**.
- **Save / upload the `.ps1` files as UTF-8 (no BOM) with ASCII-only content** to
  avoid the known Intune encoding-corruption bug (prior UTF-16-LE corruption).
  The script bodies contain no smart quotes, em-dashes, or other Unicode.
- In the Proactive Remediation settings:
  - Run the scripts in **64-bit PowerShell**.
  - Run in **system context** (SYSTEM) - not as the logged-on user.
  - **Disable signature check** ("Enforce script signature check = No") if the
    scripts are not signed.
- Detection script: `Detect-WinRESize.ps1`. Remediation script:
  `Remediate-WinRESize.ps1`.
