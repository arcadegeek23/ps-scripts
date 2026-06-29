# Detect-WinRESize.ps1
# Intune Proactive Remediation - DETECTION script (read-only, no changes).
# Purpose: detect HP EliteBook-class fleet devices whose Windows Recovery
# Environment (WinRE) / recovery partition is too small to install Windows 11
# feature updates (KB5028997 class failures: 0x80070643 / 0x80070070).
#
# Exit code convention (Intune PIA):
#   exit 0 = compliant (no remediation needed)
#   exit 1 = non-compliant (trigger the remediation script)
#
# IMPORTANT: this script makes NO changes. It only reads state.
#
# Detection strategy (MINOR 9/10 - localization-robust):
#   PRIMARY signal is the on-disk size of the Recovery-TYPED partition via
#   Get-Partition (language-independent: partition Type is not localized).
#   reagentc /info is used only as a SECONDARY signal, because its output
#   strings (e.g. "Windows RE status: Enabled") are LOCALIZED and unreliable on
#   non-English OS images. See the README "English-only detection caveat".
#
# ASCII ONLY - no smart quotes, no em-dashes, no Unicode. Run 64-bit, SYSTEM.

# ---- Configurable threshold ----
# Microsoft guidance: grow recovery partition to ~1 GB; feature update needs
# roughly 250 MB free. We flag any recovery partition smaller than this total.
$ThresholdBytes = 750MB

try {
    # =================================================================
    # PRIMARY signal: the Recovery-TYPED partition on the system disk.
    # Type is language-independent, so this works regardless of OS language.
    # =================================================================
    $osPartition = Get-Partition -DriveLetter C -ErrorAction Stop
    $diskNumber  = $osPartition.DiskNumber

    $recParts = @(Get-Partition -DiskNumber $diskNumber -ErrorAction Stop |
        Where-Object { $_.Type -eq 'Recovery' })

    $threshMB = [math]::Round($ThresholdBytes / 1MB, 0)

    if ($recParts.Count -eq 0) {
        # No dedicated recovery partition: WinRE is on the OS volume or missing.
        Write-Output "NONCOMPLIANT: no Recovery-typed partition found on system disk ${diskNumber} (WinRE on OS volume or missing)."
        exit 1
    }
    if ($recParts.Count -gt 1) {
        # Ambiguous layout: let remediation's strict checks decide; flag for review.
        Write-Output "NONCOMPLIANT: $($recParts.Count) Recovery-typed partitions found on disk ${diskNumber} (ambiguous layout)."
        exit 1
    }

    $recPart  = $recParts[0]
    $sizeBytes = [int64]$recPart.Size
    $sizeMB    = [math]::Round($sizeBytes / 1MB, 0)

    # =================================================================
    # SECONDARY signal: reagentc /info (LOCALIZED - advisory only).
    # We log it for diagnostics but do NOT gate the decision purely on the
    # localized "Enabled" string.
    # =================================================================
    $statusEnabled = $false
    try {
        $reagent = (reagentc /info) 2>&1 | Out-String
        $statusEnabled = $reagent -match 'Windows RE status:\s*Enabled'
    }
    catch {
        # reagentc unavailable or errored; rely on the primary size signal.
        $statusEnabled = $null
    }

    # =================================================================
    # Optional: report free space inside the recovery volume (best-effort).
    # =================================================================
    $freeNote = ""
    try {
        $recVol = Get-Volume -Partition $recPart -ErrorAction SilentlyContinue
        if ($recVol -and $null -ne $recVol.SizeRemaining) {
            $freeRecMB = [math]::Round([int64]$recVol.SizeRemaining / 1MB, 0)
            $freeNote = " recovery-volume-free=${freeRecMB} MB;"
        }
    }
    catch { }

    $reagentNote = " reagentEnabled=$statusEnabled;"

    # =================================================================
    # Decision (PRIMARY = on-disk recovery partition size).
    # =================================================================
    if ($sizeBytes -ge $ThresholdBytes) {
        Write-Output "COMPLIANT: recovery partition ${sizeMB} MB (>= ${threshMB} MB).${freeNote}${reagentNote}"
        exit 0
    }
    else {
        Write-Output "NONCOMPLIANT: recovery partition ${sizeMB} MB (< ${threshMB} MB); needs resize.${freeNote}${reagentNote}"
        exit 1
    }
}
catch {
    # FAIL SAFE: if detection itself errors, we cannot be sure of state.
    # We deliberately exit 0 (compliant / no-op) so that an inconclusive
    # detection NEVER triggers the destructive remediation on a possibly
    # healthy, BitLocker-encrypted device. Better to skip than to risk it.
    Write-Output "DETECT-ERROR (treating as compliant/no-op): $($_.Exception.Message)"
    exit 0
}
