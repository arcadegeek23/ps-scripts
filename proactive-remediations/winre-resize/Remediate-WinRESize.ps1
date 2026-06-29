# Remediate-WinRESize.ps1
# Intune Proactive Remediation - REMEDIATION script (DESTRUCTIVE partition ops).
# Purpose: resize / recreate the WinRE recovery partition on HP EliteBook-class
# fleet devices so Windows 11 feature updates (KB5028997 class: 0x80070643 /
# 0x80070070) can install. Automates Microsoft's documented manual procedure.
#
# These devices are BitLocker-encrypted. SAFETY IS PARAMOUNT. The script:
#   - is idempotent (.done marker), never repeats on an already-resized device
#   - refuses to run on a device flagged BLOCKED by a prior mid-failure
#   - performs strict LAYOUT VERIFICATION before any destructive action and
#     aborts cleanly (exit 0) if the disk layout is not the supported shape
#     (recovery partition must immediately follow C: AND be the LAST partition)
#   - suspends BitLocker around the partition operations and resumes it, then
#     re-verifies that protection was actually restored
#   - on any failure, attempts recovery (reagentc /enable + Resume-BitLocker)
#     and writes a BLOCKING marker so Intune does NOT retry surgery on a
#     partially-modified disk
#   - writes the .done success marker ONLY when WinRE is Enabled AND the new
#     recovery partition is >= threshold AND BitLocker protection is restored
#
# Exit codes:
#   exit 0 = nothing to do / safe abort / verified success
#   exit 1 = remediation attempted but FAILED (Intune shows failure)
#
# ASCII ONLY - no smart quotes, no em-dashes, no Unicode. Run 64-bit, SYSTEM.

# ---- Configuration ----
$LogDir         = 'C:\ProgramData\CIT\Logs'
$LogFile        = Join-Path $LogDir 'WinRE-Resize.log'
$DoneMarker     = Join-Path $LogDir 'WinRE-Resize.done'
$BlockedMarker  = Join-Path $LogDir 'WinRE-Resize.BLOCKED'
$ShrinkMB       = 250        # how much to shrink the OS partition by (MB)
$MinFreeOsMB    = 300        # require at least this much free on C: before shrink
$TargetMinMB    = 1024       # required final recovery partition size (MB).
                             # If (old recovery size + shrink) is below this, we
                             # abort BEFORE deleting anything (surgery would not
                             # fix the KB5028997 problem). ~1 GB per MS guidance.

# Recovery partition type identifiers (kept identical to MS documented values).
$GptRecoveryTypeGuid = 'de94bba4-06d1-4d40-a16a-bfd50179d6ac'
$GptRecoveryAttrs    = '0x8000000000000001'   # GPT_BASIC_DATA + REQUIRED + NO_DRIVE_LETTER
$MbrRecoveryTypeId   = '27'                    # MBR hidden recovery type 0x27

# ---- Logging helper (timestamped) ----
function Write-Log {
    param([string]$Message)
    $ts = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'
    $line = "$ts  $Message"
    try { Add-Content -Path $LogFile -Value $line -ErrorAction Stop } catch {}
    Write-Output $line
}

# Ensure log directory exists.
try {
    if (-not (Test-Path $LogDir)) { New-Item -Path $LogDir -ItemType Directory -Force | Out-Null }
}
catch {
    Write-Output "FATAL: cannot create log directory $LogDir : $($_.Exception.Message)"
    exit 1
}

Write-Log "==== WinRE-Resize remediation started ===="

# ---- BLOCKING marker: refuse to retry destructive surgery on a half-modified disk ----
# Written by a prior run that failed AFTER the destructive delete step. We must
# NOT blindly re-run diskpart on a partially-modified disk. A human must inspect.
if (Test-Path $BlockedMarker) {
    Write-Log "BLOCKED marker present ($BlockedMarker). A prior run failed mid-surgery."
    Write-Log "Refusing to run. A technician must inspect this device, repair the layout,"
    Write-Log "and delete the BLOCKED marker before remediation can run again. Exiting 0."
    exit 0
}

# ---- Idempotency: bail out if already done ----
if (Test-Path $DoneMarker) {
    Write-Log "Marker file present ($DoneMarker). Device already remediated. Exiting 0."
    exit 0
}

# State tracking for failure recovery.
$BitLockerWasOn      = $false
$BitLockerSuspended  = $false
$PassedDeleteStep    = $false   # set true once the destructive delete has been issued

# =====================================================================
# AC POWER detection helper (MINOR 8).
# On AC if: no battery present (desktop), OR Win32_Battery.BatteryStatus is in
# {2,6,7,8} (AC / charging variants), OR Win32 GetSystemPowerStatus
# ACLineStatus == 1. We do NOT abort a genuinely plugged-in laptop just because
# it happens to be charging.
# =====================================================================
function Test-OnAcPower {
    # Signal 1: Win32 GetSystemPowerStatus P/Invoke (most authoritative).
    try {
        if (-not ([System.Management.Automation.PSTypeName]'CITPower.PowerStatus').Type) {
            Add-Type -Namespace 'CITPower' -Name 'PowerStatus' -MemberDefinition @'
[System.Runtime.InteropServices.StructLayout(System.Runtime.InteropServices.LayoutKind.Sequential)]
public struct SYSTEM_POWER_STATUS {
    public byte ACLineStatus;
    public byte BatteryFlag;
    public byte BatteryLifePercent;
    public byte SystemStatusFlag;
    public int  BatteryLifeTime;
    public int  BatteryFullLifeTime;
}
[System.Runtime.InteropServices.DllImport("kernel32.dll", SetLastError=true)]
public static extern bool GetSystemPowerStatus(out SYSTEM_POWER_STATUS lpSystemPowerStatus);
public static int AcLineStatus() {
    SYSTEM_POWER_STATUS s;
    if (GetSystemPowerStatus(out s)) { return (int)s.ACLineStatus; }
    return -1;
}
'@ -ErrorAction Stop
        }
        $acl = [CITPower.PowerStatus]::AcLineStatus()
        # 1 = AC online, 0 = offline (on battery), 255 = unknown.
        if ($acl -eq 1) { Write-Log "AC detection: GetSystemPowerStatus ACLineStatus = 1 (AC online)."; return $true }
        if ($acl -eq 0) { Write-Log "AC detection: GetSystemPowerStatus ACLineStatus = 0 (on battery)."; return $false }
        Write-Log "AC detection: GetSystemPowerStatus ACLineStatus = $acl (unknown); falling back to Win32_Battery."
    }
    catch {
        Write-Log "AC detection: GetSystemPowerStatus P/Invoke unavailable: $($_.Exception.Message); falling back to Win32_Battery."
    }

    # Signal 2: Win32_Battery. No battery => desktop => AC.
    $batteries = Get-CimInstance -ClassName Win32_Battery -ErrorAction SilentlyContinue
    if (-not $batteries) {
        Write-Log "AC detection: no Win32_Battery present (desktop); treating as AC."
        return $true
    }
    # BatteryStatus codes that indicate AC is connected: 2 (AC), 6/7/8 (charging variants).
    $acStatuses = @(2, 6, 7, 8)
    foreach ($b in $batteries) {
        if ($acStatuses -contains [int]$b.BatteryStatus) {
            Write-Log "AC detection: Win32_Battery BatteryStatus = $($b.BatteryStatus) (AC/charging); treating as AC."
            return $true
        }
    }
    Write-Log "AC detection: Win32_Battery present and not in AC/charging states; treating as on battery."
    return $false
}

# =====================================================================
# LAYOUT VERIFICATION helper (BLOCKER 1 + BLOCKER 2 + BLOCKER 3).
# Returns a hashtable describing the verified-safe layout, or $null if the
# layout is NOT the supported shape (caller must then abort exit 0).
# This reads identity from Get-Partition / Get-Disk (NOT reagentc, which is
# cleared after /disable) so the identity is stable across the procedure.
# =====================================================================
function Get-VerifiedRecoveryLayout {
    # OS partition (C:) and its disk.
    $osPartition = Get-Partition -DriveLetter C -ErrorAction Stop
    $diskNumber  = $osPartition.DiskNumber
    $disk        = Get-Disk -Number $diskNumber -ErrorAction Stop
    $partStyle   = $disk.PartitionStyle   # 'GPT' or 'MBR'

    # All partitions on the system disk, ordered by on-disk offset.
    $allParts = Get-Partition -DiskNumber $diskNumber -ErrorAction Stop |
        Sort-Object -Property Offset

    # Need offsets and sizes for all partitions for the contiguity check (CHECK E).
    # CHECK A: exactly one Recovery-typed partition (BLOCKER 3 - no ambiguity).
    $recParts = @($allParts | Where-Object { $_.Type -eq 'Recovery' })
    if ($recParts.Count -eq 0) {
        Write-Log "LAYOUT FAIL: no Recovery-typed partition found on disk $diskNumber."
        return $null
    }
    if ($recParts.Count -gt 1) {
        Write-Log "LAYOUT FAIL: $($recParts.Count) Recovery-typed partitions found on disk $diskNumber (ambiguous). Refusing."
        return $null
    }
    $recPart = $recParts[0]

    # CHECK B: recovery offset is greater than the OS offset (recovery after C:).
    if ([int64]$recPart.Offset -le [int64]$osPartition.Offset) {
        Write-Log "LAYOUT FAIL: recovery offset ($($recPart.Offset)) is not greater than OS offset ($($osPartition.Offset))."
        return $null
    }

    # CHECK C: recovery immediately follows C: - no partition sits between the
    # end of C: and the start of recovery.
    $osEnd = [int64]$osPartition.Offset + [int64]$osPartition.Size
    $between = @($allParts | Where-Object {
        [int64]$_.Offset -ge $osEnd -and [int64]$_.Offset -lt [int64]$recPart.Offset
    })
    if ($between.Count -gt 0) {
        Write-Log "LAYOUT FAIL: $($between.Count) partition(s) sit between C: end and the recovery partition. Recovery does not immediately follow C:."
        return $null
    }

    # CHECK D: recovery is the LAST partition on the disk (highest offset).
    $maxOffset = ($allParts | Measure-Object -Property Offset -Maximum).Maximum
    if ([int64]$recPart.Offset -ne [int64]$maxOffset) {
        Write-Log "LAYOUT FAIL: recovery partition is not the last partition on the disk (its offset $($recPart.Offset) != max offset $maxOffset)."
        return $null
    }

    # CHECK E: NO unallocated/free gap on the disk BEFORE the recovery partition.
    # Walk the offset-sorted partitions and confirm each partition's start offset
    # equals the previous partition's end (offset + size), within a small
    # alignment tolerance, from the first partition through recovery. If any gap
    # exists earlier on the disk, the post-shrink+delete free region would not be
    # a single contiguous trailing extent and a sizeless create would be
    # ambiguous, so we abort (return $null).
    $gapToleranceBytes = 1MB
    $prevEnd = $null
    foreach ($p in $allParts) {
        if ($null -ne $prevEnd) {
            $gap = [int64]$p.Offset - [int64]$prevEnd
            if ($gap -gt [int64]$gapToleranceBytes) {
                Write-Log "LAYOUT FAIL: free gap of $gap bytes before partition $($p.PartitionNumber) (offset $($p.Offset), previous partition ended at $prevEnd). Disk is not contiguous through recovery; sizeless create would be ambiguous."
                return $null
            }
        }
        $prevEnd = [int64]$p.Offset + [int64]$p.Size
        # Stop once we have validated contiguity up to and including recovery.
        if ([int64]$p.Offset -eq [int64]$recPart.Offset) { break }
    }

    $recSizeMB = [math]::Round([int64]$recPart.Size / 1MB, 0)
    Write-Log "LAYOUT OK: disk $diskNumber ($partStyle); C: = partition $($osPartition.PartitionNumber) offset $($osPartition.Offset); recovery = partition $($recPart.PartitionNumber) offset $($recPart.Offset) size ${recSizeMB} MB; recovery immediately follows C: and is the last partition."

    return @{
        DiskNumber       = $diskNumber
        PartitionStyle   = $partStyle
        OsPartitionNumber= $osPartition.PartitionNumber
        OsOffset         = [int64]$osPartition.Offset
        OsSize           = [int64]$osPartition.Size
        RecPartitionNumber = $recPart.PartitionNumber
        RecOffset        = [int64]$recPart.Offset
        RecSize          = [int64]$recPart.Size
        RecSizeMB        = $recSizeMB
    }
}

# =====================================================================
# PRE-FLIGHT CHECKS - abort (exit 0, log reason) if any fail.
# =====================================================================

# --- 1. AC power (MINOR 8) ---
try {
    if (-not (Test-OnAcPower)) {
        Write-Log "PRE-FLIGHT ABORT: device is on battery power, not AC. Exiting 0."
        exit 0
    }
    Write-Log "Pre-flight: AC power OK."
}
catch {
    Write-Log "PRE-FLIGHT ABORT: could not determine power state: $($_.Exception.Message). Exiting 0."
    exit 0
}

# --- 2. OS volume (C:) free space ---
try {
    $cDrive = Get-PSDrive -Name C -ErrorAction Stop
    $freeMB = [math]::Round($cDrive.Free / 1MB, 0)
    if ($freeMB -lt $MinFreeOsMB) {
        Write-Log "PRE-FLIGHT ABORT: C: free space ${freeMB} MB < required ${MinFreeOsMB} MB. Exiting 0."
        exit 0
    }
    Write-Log "Pre-flight: C: free space ${freeMB} MB OK (need ${MinFreeOsMB} MB)."
}
catch {
    Write-Log "PRE-FLIGHT ABORT: could not read C: free space: $($_.Exception.Message). Exiting 0."
    exit 0
}

# --- 3. LAYOUT VERIFICATION (BLOCKER 1 + 2 + 3) - capture stable identity ---
# Done BEFORE reagentc /disable so identity comes from Get-Partition, not the
# (soon to be cleared) reagentc /info output.
try {
    $layout = Get-VerifiedRecoveryLayout
    if ($null -eq $layout) {
        Write-Log "PRE-FLIGHT ABORT: disk layout is not the supported shape for this procedure. Exiting 0 (safe no-op)."
        exit 0
    }
}
catch {
    Write-Log "PRE-FLIGHT ABORT: could not read disk layout: $($_.Exception.Message). Exiting 0."
    exit 0
}

# --- 4. ACHIEVABLE TARGET SIZE check (BLOCKER 2 / MAJOR 4) ---
# The new recovery partition will occupy roughly (old recovery size + shrink).
# If that is still below the threshold, surgery would NOT fix the problem, so we
# refuse BEFORE deleting anything.
$targetSizeMB = [int]$layout.RecSizeMB + [int]$ShrinkMB
if ($targetSizeMB -lt $TargetMinMB) {
    Write-Log "PRE-FLIGHT ABORT: achievable recovery size ~${targetSizeMB} MB (old $($layout.RecSizeMB) MB + shrink $ShrinkMB MB) is below threshold ${TargetMinMB} MB. Surgery would not fix the problem. Exiting 0."
    exit 0
}
Write-Log "Pre-flight: achievable recovery size ~${targetSizeMB} MB >= threshold ${TargetMinMB} MB. OK to proceed."

# --- 5. BitLocker state + recovery password protector on C: ---
try {
    $blv = Get-BitLockerVolume -MountPoint 'C:' -ErrorAction Stop
    Write-Log "Pre-flight: BitLocker ProtectionStatus on C: = $($blv.ProtectionStatus); VolumeStatus = $($blv.VolumeStatus)."

    if ($blv.ProtectionStatus -eq 'On') {
        $BitLockerWasOn = $true

        # Confirm a recovery password protector exists and log its key ID.
        $recProtector = $blv.KeyProtector | Where-Object { $_.KeyProtectorType -eq 'RecoveryPassword' }
        if (-not $recProtector) {
            Write-Log "PRE-FLIGHT ABORT: BitLocker is On but NO RecoveryPassword protector found on C:. Refusing to proceed. Exiting 0."
            exit 0
        }
        foreach ($rp in $recProtector) {
            Write-Log "Pre-flight: RecoveryPassword protector present. KeyProtectorId = $($rp.KeyProtectorId)."
        }
    }
    else {
        Write-Log "Pre-flight: BitLocker is not On (status $($blv.ProtectionStatus)); no suspend needed."
    }
}
catch {
    Write-Log "PRE-FLIGHT ABORT: could not query BitLocker on C:: $($_.Exception.Message). Exiting 0."
    exit 0
}

# =====================================================================
# PROCEDURE - each step wrapped; failure jumps to recovery in finally.
# All partition identity comes from $layout (captured above), NOT reagentc.
# =====================================================================
$success = $false
try {

    # --- Step 1: reagentc /disable (moves winre.wim onto C:) ---
    Write-Log "Step 1: reagentc /disable"
    $out = (reagentc /disable) 2>&1 | Out-String
    Write-Log "reagentc /disable output: $($out.Trim())"
    if ($LASTEXITCODE -ne 0) {
        throw "reagentc /disable failed with exit code $LASTEXITCODE"
    }

    # --- Step 2: Suspend BitLocker (auto-resume after 1 reboot as a backstop) ---
    if ($BitLockerWasOn) {
        Write-Log "Step 2: Suspend-BitLocker -MountPoint C: -RebootCount 1"
        Suspend-BitLocker -MountPoint 'C:' -RebootCount 1 -ErrorAction Stop | Out-Null
        $BitLockerSuspended = $true
        Write-Log "BitLocker suspended on C: (RebootCount 1 is a backstop; we resume explicitly below)."
    }
    else {
        Write-Log "Step 2: skipped (BitLocker not On)."
    }

    # --- Step 3: Re-confirm the captured layout is still intact (BLOCKER 3) ---
    # reagentc /disable should not change partition geometry; confirm the
    # captured recovery partition still matches by offset/type/size before we
    # destroy anything. Identity here is by OFFSET (stable), not reagentc.
    $recNow = Get-Partition -DiskNumber $layout.DiskNumber -ErrorAction Stop |
        Where-Object { $_.Type -eq 'Recovery' }
    $recNow = @($recNow)
    if ($recNow.Count -ne 1) {
        throw "Layout re-confirm failed: expected exactly 1 Recovery partition, found $($recNow.Count)."
    }
    if ([int64]$recNow[0].Offset -ne $layout.RecOffset) {
        throw "Layout re-confirm failed: recovery offset changed from $($layout.RecOffset) to $($recNow[0].Offset)."
    }
    if ([int64]$recNow[0].Size -ne $layout.RecSize) {
        throw "Layout re-confirm failed: recovery size changed from $($layout.RecSize) to $($recNow[0].Size)."
    }
    $recoveryPartNumber = $recNow[0].PartitionNumber
    Write-Log "Step 3: layout re-confirmed by offset/type/size. Recovery = partition $recoveryPartNumber (offset $($layout.RecOffset))."

    # --- Step 4: diskpart - shrink OS, delete old recovery, create new ---
    # We build a diskpart script and run it with diskpart /s. This follows the
    # Microsoft KB5028997 documented procedure, branched by partition style.
    #
    # The recovery partition is created with a SIZELESS "create partition primary"
    # (no size=). The layout checks (A-E) guarantee the recovery partition is the
    # LAST partition, immediately follows C:, and has no free gap earlier on the
    # disk. So after "shrink desired=250" + "delete partition override" the freed
    # region is a SINGLE contiguous trailing extent, and a sizeless create fills
    # exactly that extent (growing recovery by the 250 MB shrink). This is the
    # MS-documented form and avoids the alignment over-commit failure that an
    # explicit size= can cause.
    #
    # On GPT, "create partition primary id=<GUID>" is INVALID (the id= form on
    # create is the legacy MBR byte-type usage and rejects a 36-char GUID). The
    # GPT type is set AFTER create via "set id=" plus "gpt attributes=". On MBR,
    # "create partition primary id=27" IS valid (MBR byte-type) so it stays inline.
    #
    # Ordering note: "select partition <recovery#>" is issued BEFORE "delete
    # partition override" while the number is still valid. The subsequent sizeless
    # "create" operates on free space and must NOT re-select a partition number.
    $diskpartScript = Join-Path $env:TEMP 'winre-resize-diskpart.txt'

    $lines = @()
    $lines += "select disk $($layout.DiskNumber)"
    $lines += "select partition $($layout.OsPartitionNumber)"
    $lines += "shrink desired=$ShrinkMB minimum=$ShrinkMB"
    $lines += "select partition $recoveryPartNumber"
    $lines += "delete partition override"
    if ($layout.PartitionStyle -eq 'GPT') {
        # GPT recovery partition (MS KB5028997 procedure): sizeless create, then
        # format, then set the recovery type GUID and the required GPT attributes.
        $lines += "create partition primary"
        $lines += "format quick fs=ntfs label=Recovery"
        $lines += "set id=$GptRecoveryTypeGuid"
        $lines += "gpt attributes=$GptRecoveryAttrs"
    }
    else {
        # MBR recovery partition: id=27 on create IS valid (MBR byte-type 0x27),
        # then format. Sizeless create fills the contiguous trailing free extent.
        $lines += "create partition primary id=$MbrRecoveryTypeId"
        $lines += "format quick fs=ntfs label=Recovery"
    }
    $lines += "exit"

    # Write diskpart script as ASCII.
    Set-Content -Path $diskpartScript -Value $lines -Encoding ASCII -ErrorAction Stop
    Write-Log "Step 4: diskpart script written to $diskpartScript :"
    foreach ($l in $lines) { Write-Log "    diskpart> $l" }

    # Mark that we are about to perform the destructive delete. From this point
    # on, a failure means the disk may be partially modified.
    $PassedDeleteStep = $true

    $dpOut = (diskpart /s $diskpartScript) 2>&1 | Out-String
    Write-Log "diskpart output: $($dpOut.Trim())"
    if ($LASTEXITCODE -ne 0) {
        throw "diskpart failed with exit code $LASTEXITCODE"
    }
    # Clean up the temp script.
    Remove-Item -Path $diskpartScript -Force -ErrorAction SilentlyContinue

    # --- Step 5: reagentc /enable ---
    Write-Log "Step 5: reagentc /enable"
    $out = (reagentc /enable) 2>&1 | Out-String
    Write-Log "reagentc /enable output: $($out.Trim())"
    if ($LASTEXITCODE -ne 0) {
        throw "reagentc /enable failed with exit code $LASTEXITCODE"
    }

    # --- Step 6: VERIFY success (MAJOR 4 + MAJOR 6 + MAJOR 7) ---
    # Success requires ALL of:
    #   (a) WinRE Enabled (reagentc /info),
    #   (b) the new recovery partition actual size >= threshold (Get-Partition),
    #   (c) BitLocker protection restored (handled after Resume in finally; we
    #       record the size/enable result here and gate $success on the BL check
    #       at the very end).
    Write-Log "Step 6: verification (WinRE Enabled + recovery size >= threshold)"

    $verify = (reagentc /info) 2>&1 | Out-String
    Write-Log "reagentc /info output: $($verify.Trim())"
    $isEnabled = $verify -match 'Windows RE status:\s*Enabled'

    # Language-independent size check: find the (single) Recovery partition now.
    $newRec = @(Get-Partition -DiskNumber $layout.DiskNumber -ErrorAction Stop |
        Where-Object { $_.Type -eq 'Recovery' })
    $newRecSizeMB = 0
    if ($newRec.Count -eq 1) {
        $newRecSizeMB = [math]::Round([int64]$newRec[0].Size / 1MB, 0)
    }
    Write-Log "Verification: WinRE Enabled = $isEnabled; new recovery partition count = $($newRec.Count); size = ${newRecSizeMB} MB (threshold ${TargetMinMB} MB)."

    if (-not $isEnabled) {
        throw "Verification failed: WinRE is not Enabled after reagentc /enable."
    }
    if ($newRec.Count -ne 1) {
        throw "Verification failed: expected exactly 1 Recovery partition, found $($newRec.Count)."
    }
    if ($newRecSizeMB -lt $TargetMinMB) {
        throw "Verification failed: new recovery partition ${newRecSizeMB} MB is below threshold ${TargetMinMB} MB (undersized result is NOT success)."
    }

    Write-Log "Verification OK: WinRE Enabled and recovery partition ${newRecSizeMB} MB >= ${TargetMinMB} MB. (BitLocker restore verified after resume.)"
    $success = $true
}
catch {
    # The procedure threw. Record and let finally attempt recovery.
    Write-Log "ERROR during procedure: $($_.Exception.Message)"
    $success = $false
}
finally {
    # =================================================================
    # FAILURE HANDLING / cleanup. Always try to leave WinRE enabled and
    # BitLocker resumed so the device is never left unbootable.
    # =================================================================
    if (-not $success) {
        Write-Log "FAILURE RECOVERY: attempting to restore WinRE on C: (interim) and BitLocker."

        # MAJOR 5: re-confirm layout state for the log so a human sees what is on disk.
        try {
            $postParts = @(Get-Partition -DiskNumber $layout.DiskNumber -ErrorAction Stop | Sort-Object Offset)
            $postRec   = @($postParts | Where-Object { $_.Type -eq 'Recovery' })
            Write-Log "FAILURE RECOVERY: post-failure layout on disk $($layout.DiskNumber): $($postParts.Count) partitions, $($postRec.Count) Recovery-typed."
            foreach ($p in $postParts) {
                $pMB = [math]::Round([int64]$p.Size / 1MB, 0)
                Write-Log "FAILURE RECOVERY:   partition $($p.PartitionNumber) type=$($p.Type) offset=$($p.Offset) size=${pMB} MB"
            }
        }
        catch {
            Write-Log "FAILURE RECOVERY: could not re-read layout: $($_.Exception.Message)"
        }

        # Attempt reagentc /enable. WinRE-on-C: is an acceptable interim state;
        # the device stays bootable.
        try {
            $out = (reagentc /enable) 2>&1 | Out-String
            Write-Log "FAILURE RECOVERY: reagentc /enable output: $($out.Trim()) (exit $LASTEXITCODE)"
        }
        catch {
            Write-Log "FAILURE RECOVERY: reagentc /enable threw: $($_.Exception.Message)"
        }

        # MAJOR 5: if we had already passed the destructive delete, the disk may
        # be partially modified. Write a BLOCKING marker so Intune does NOT retry
        # surgery, and log the FAILED state loudly.
        if ($PassedDeleteStep) {
            Write-Log "!!!! ALERT: failure occurred AFTER the destructive delete step. The disk may be PARTIALLY MODIFIED. !!!!"
            try {
                $blockMsg = @(
                    "WinRE-Resize FAILED after the destructive delete step at $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')."
                    "The recovery partition may have been deleted and not correctly recreated."
                    "Disk $($layout.DiskNumber). DO NOT re-run the remediation: it will refuse while this file exists."
                    "A technician must inspect the disk layout, repair WinRE, and delete this file to re-enable remediation."
                ) -join "`r`n"
                Set-Content -Path $BlockedMarker -Value $blockMsg -Encoding ASCII -ErrorAction Stop
                Write-Log "!!!! ALERT: wrote BLOCKING marker $BlockedMarker. Future runs will exit 0 without acting until it is removed. !!!!"
            }
            catch {
                Write-Log "!!!! ALERT: FAILED to write BLOCKING marker ${BlockedMarker}: $($_.Exception.Message). Manual intervention required. !!!!"
            }
        }
        else {
            Write-Log "FAILURE RECOVERY: failure occurred BEFORE the destructive delete step; disk layout untouched. No blocking marker needed."
        }
    }

    # Resume BitLocker explicitly if we suspended it (success or failure).
    if ($BitLockerSuspended) {
        try {
            Resume-BitLocker -MountPoint 'C:' -ErrorAction Stop | Out-Null
            Write-Log "Resume-BitLocker -MountPoint C: completed."
        }
        catch {
            Write-Log "WARNING: Resume-BitLocker failed: $($_.Exception.Message). RebootCount 1 backstop will resume on next reboot."
        }

        # MAJOR 7: re-query and VERIFY protection was actually restored.
        try {
            $blAfter = Get-BitLockerVolume -MountPoint 'C:' -ErrorAction Stop
            Write-Log "Post-resume BitLocker ProtectionStatus on C: = $($blAfter.ProtectionStatus); VolumeStatus = $($blAfter.VolumeStatus)."
            if ($blAfter.ProtectionStatus -eq 'On') {
                Write-Log "BitLocker protection verified restored (ProtectionStatus = On)."
            }
            else {
                # Loud ALERT, not a soft warning. Gate success on this below.
                Write-Log "!!!! ALERT: BitLocker protection NOT restored on C: (ProtectionStatus = $($blAfter.ProtectionStatus)). RebootCount 1 backstop should resume on next reboot, but this must be checked. !!!!"
                $success = $false
            }
        }
        catch {
            Write-Log "!!!! ALERT: could not re-query BitLocker after resume: $($_.Exception.Message). Treating protection as NOT verified. !!!!"
            $success = $false
        }
    }
}

# =====================================================================
# Final exit handling.
# The .done marker is written ONLY when WinRE Enabled + recovery size >=
# threshold (verified in Step 6) AND BitLocker restore verified (above).
# =====================================================================
if ($success) {
    try {
        Set-Content -Path $DoneMarker -Value (Get-Date -Format 'yyyy-MM-dd HH:mm:ss') -Encoding ASCII -ErrorAction Stop
        Write-Log "SUCCESS: WinRE resized, verified (size + Enabled), BitLocker restored. Marker written to $DoneMarker. Exiting 0."
    }
    catch {
        Write-Log "SUCCESS but could not write marker ${DoneMarker}: $($_.Exception.Message). Exiting 0."
    }
    exit 0
}
else {
    Write-Log "FAILED: remediation did not complete successfully. No .done marker written. Exiting 1."
    exit 1
}
