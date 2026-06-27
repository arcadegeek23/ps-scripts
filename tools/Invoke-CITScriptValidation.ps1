<#
.SYNOPSIS
    Validate a single CIT Intune PowerShell script before committing.

.DESCRIPTION
    Runs the layered local QA checks from docs/QA-PROCESS.md against ONE script:
      1. Parse          -- syntax check via the PowerShell parser.
      2. Analyzer       -- Invoke-ScriptAnalyzer with the repo settings (WARN if module absent).
      3. Encoding       -- BOM-less file containing non-ASCII bytes fails (em-dash / signing class).
      4. LoggingContract-- dot-source of CIT-Logging.ps1 must match the helper's param contract,
                           and the log path convention (C:\ProgramData\CIT\Logs) is enforced.
      5. LoadContract   -- actually dot-sources CIT-Logging.ps1 the way the script does and
                           asserts it does not throw (catches the FW-ApplyUpdate / WUDiag crash).
      6. ExitCodeContract-- static sanity check of exit codes for Detect / Remediate scripts.
      7. Pester         -- runs the matching <script>.Tests.ps1 if present.

    Prints a PASS / FAIL / WARN table and a single verdict line, and exits non-zero on any FAIL.

    PowerShell 5.1 compatible (no ternary, null-coalescing, or PS7-only cmdlets).

.PARAMETER Path
    The .ps1 file to validate.

.PARAMETER Role
    Detect | Remediate | Diag | Activity | Module. Inferred from the filename when omitted.

.PARAMETER SkipPester
    Skip the matching Pester test run (analyzer + lint only).

.PARAMETER Json
    Emit a machine-readable JSON object instead of the human table (for pre-commit hooks).

.EXAMPLE
    .\tools\Invoke-CITScriptValidation.ps1 -Path .\platform\CIT-Logging.ps1

.EXAMPLE
    .\tools\Invoke-CITScriptValidation.ps1 -Path .\proactive-remediations\patch-compliance\Detect-PatchCompliance-v1.ps1 -Json
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string] $Path,

    [ValidateSet('Detect', 'Remediate', 'Diag', 'Activity', 'Module')]
    [string] $Role,

    [switch] $SkipPester,

    [switch] $Json
)

$ErrorActionPreference = 'Stop'

# --- result accumulator -----------------------------------------------------
$results = New-Object System.Collections.Generic.List[object]
function Add-Result {
    param([string]$Name, [string]$Result, [string]$Detail, [string]$Remedy = '')
    $results.Add([pscustomobject]@{
        Name   = $Name
        Result = $Result
        Detail = $Detail
        Remedy = $Remedy
    })
}

# --- resolve paths ----------------------------------------------------------
if (-not (Test-Path -LiteralPath $Path)) {
    Write-Error "Path not found: $Path"
    exit 2
}
$target   = (Resolve-Path -LiteralPath $Path).Path
$leaf     = Split-Path $target -Leaf

# Repo root = nearest ancestor that contains PSScriptAnalyzerSettings.psd1.
$repoRoot = Split-Path $target -Parent
while ($repoRoot -and -not (Test-Path (Join-Path $repoRoot 'PSScriptAnalyzerSettings.psd1'))) {
    $parent = Split-Path $repoRoot -Parent
    if ($parent -eq $repoRoot) { $repoRoot = $null; break }
    $repoRoot = $parent
}
if (-not $repoRoot) {
    # Fall back to the script's own location (tools/ -> repo root).
    $repoRoot = Split-Path (Split-Path $PSCommandPath -Parent) -Parent
}
$settings = Join-Path $repoRoot 'PSScriptAnalyzerSettings.psd1'

# --- infer role -------------------------------------------------------------
if (-not $Role) {
    switch -Regex ($leaf) {
        '^Detect-'        { $Role = 'Detect';    break }
        '^Remediate-'     { $Role = 'Remediate'; break }
        'WUDiag|FW-Diag'  { $Role = 'Diag';      break }
        'CIT-Logging'     { $Role = 'Module';    break }
        default           { $Role = 'Activity' }
    }
}

$src = Get-Content -LiteralPath $target -Raw

# --- 1. Parse ---------------------------------------------------------------
$parseErrors = $null
[System.Management.Automation.Language.Parser]::ParseFile($target, [ref]$null, [ref]$parseErrors) | Out-Null
if ($parseErrors -and $parseErrors.Count -gt 0) {
    Add-Result 'Parse' 'FAIL' "$($parseErrors.Count) syntax error(s): $($parseErrors[0].Message)" 'Fix syntax before committing.'
}
else {
    Add-Result 'Parse' 'PASS' 'Clean parse'
}

# --- 2. Analyzer ------------------------------------------------------------
if (Get-Module -ListAvailable -Name PSScriptAnalyzer) {
    Import-Module PSScriptAnalyzer -ErrorAction SilentlyContinue
    if (Test-Path $settings) {
        $an = Invoke-ScriptAnalyzer -Path $target -Settings $settings
    }
    else {
        $an = Invoke-ScriptAnalyzer -Path $target
    }
    $anErr  = @($an | Where-Object { $_.Severity -eq 'Error' })
    $anWarn = @($an | Where-Object { $_.Severity -ne 'Error' })
    if ($anErr.Count -gt 0) {
        Add-Result 'Analyzer' 'FAIL' "$($anErr.Count) error / $($anWarn.Count) warning" 'Resolve Error-severity rules (null-RHS, unapproved verbs, PS7 syntax).'
    }
    elseif ($anWarn.Count -gt 0) {
        Add-Result 'Analyzer' 'WARN' "0 error / $($anWarn.Count) warning" 'Review analyzer warnings (aliases, Write-Host, positional params).'
    }
    else {
        Add-Result 'Analyzer' 'PASS' 'No analyzer findings'
    }
}
else {
    Add-Result 'Analyzer' 'WARN' 'PSScriptAnalyzer not installed' 'Install-Module PSScriptAnalyzer -Scope CurrentUser (CI enforces this on Windows).'
}

# --- 3. Encoding / signing --------------------------------------------------
$bytes  = [System.IO.File]::ReadAllBytes($target)
$hasBom = $bytes.Length -ge 3 -and $bytes[0] -eq 0xEF -and $bytes[1] -eq 0xBB -and $bytes[2] -eq 0xBF
$nonAscii = $false
foreach ($b in $bytes) { if ($b -gt 0x7F) { $nonAscii = $true; break } }
if ($nonAscii -and -not $hasBom) {
    Add-Result 'Encoding' 'FAIL' 'BOM-less file contains non-ASCII byte (em-dash / signing class)' 'Replace non-ASCII chars with ASCII, or save as UTF-8 with BOM before signing.'
}
else {
    Add-Result 'Encoding' 'PASS' 'ASCII-only or UTF-8-with-BOM'
}

# --- 4. Logging convention / dot-source contract ----------------------------
$dotSourcesLogging = $src -match 'CIT-Logging\.ps1'
$inlinesLog        = $src -match 'function\s+Write-CITLog'
if ($dotSourcesLogging) {
    # Find the helper relative to the dot-sourcing script and read its param contract.
    $helper = $null
    foreach ($candidate in @(
            (Join-Path $repoRoot 'platform\CIT-Logging.ps1'),
            (Join-Path (Split-Path $target -Parent) '..\..\platform\CIT-Logging.ps1'),
            (Join-Path (Split-Path $target -Parent) '..\platform\CIT-Logging.ps1'))) {
        if (Test-Path $candidate) { $helper = (Resolve-Path $candidate).Path; break }
    }
    $passesScriptName = $src -match 'CIT-Logging\.ps1["'']?\s+-ScriptName'
    if (-not $helper) {
        Add-Result 'LoggingContract' 'FAIL' 'Dot-sources CIT-Logging.ps1 but the helper does not resolve at the expected relative path' 'Fix the relative path to platform\CIT-Logging.ps1.'
    }
    elseif ($passesScriptName) {
        $helperSrc = Get-Content -LiteralPath $helper -Raw
        $helperAcceptsScriptName = $helperSrc -match '(?im)^\s*param\s*\(([^)]*)\)' -and $Matches[1] -match '\$ScriptName'
        if ($helperAcceptsScriptName) {
            Add-Result 'LoggingContract' 'PASS' 'Dot-source passes -ScriptName and the helper declares a matching param() block'
        }
        else {
            Add-Result 'LoggingContract' 'FAIL' 'Dot-sources CIT-Logging.ps1 with -ScriptName, but the helper has no param([string]$ScriptName) -> binding crash' 'Add param([string]$ScriptName) to CIT-Logging.ps1, or drop -ScriptName from the dot-source.'
        }
    }
    else {
        Add-Result 'LoggingContract' 'PASS' 'Dot-sources CIT-Logging.ps1 with no unsupported argument'
    }
}
elseif ($inlinesLog) {
    if ($src -match 'C:\\ProgramData\\CIT\\Logs') {
        Add-Result 'LoggingContract' 'PASS' 'Inlines Write-CITLog with the C:\ProgramData\CIT\Logs convention'
    }
    else {
        Add-Result 'LoggingContract' 'WARN' 'Inlines Write-CITLog but the C:\ProgramData\CIT\Logs path was not found' 'Log to C:\ProgramData\CIT\Logs\<ScriptName>.log per the repo convention.'
    }
}
else {
    Add-Result 'LoggingContract' 'WARN' 'No CIT logging detected' 'Most scripts should log via CIT-Logging.ps1 or an inline Write-CITLog.'
}

# --- 5. Load contract (dot-source as production does) -----------------------
if ($dotSourcesLogging -and $helper -and (Test-Path $helper)) {
    $loadOk = $true
    $loadErr = ''
    try {
        if ($src -match 'CIT-Logging\.ps1["'']?\s+-ScriptName') {
            . $helper -ScriptName 'ValidationProbe' *> $null
        }
        else {
            . $helper *> $null
        }
        if (-not (Get-Command Write-CITLog -ErrorAction SilentlyContinue)) {
            $loadOk = $false
            $loadErr = 'Write-CITLog not defined after load'
        }
    }
    catch {
        $loadOk = $false
        $loadErr = $_.Exception.Message
    }
    if ($loadOk) {
        Add-Result 'LoadContract' 'PASS' 'CIT-Logging.ps1 dot-sourced as production does without throwing'
    }
    else {
        Add-Result 'LoadContract' 'FAIL' "Dot-sourcing CIT-Logging.ps1 as production does FAILED: $loadErr" 'Reconcile the dot-source argument with the helper param() contract.'
    }
}

# --- 6. Exit-code contract (static) for Detect / Remediate ------------------
if ($Role -eq 'Detect' -or $Role -eq 'Remediate') {
    $exitMatches = [System.Text.RegularExpressions.Regex]::Matches($src, '\bexit\s+(\d+)')
    $codes = New-Object System.Collections.Generic.List[int]
    foreach ($m in $exitMatches) { [void]$codes.Add([int]$m.Groups[1].Value) }
    $distinct = @($codes | Sort-Object -Unique)
    if ($distinct.Count -eq 0) {
        Add-Result 'ExitCodeContract' 'WARN' 'No literal exit codes found' 'Detect/Remediate should explicitly exit 0/1/2 per the contract.'
    }
    else {
        $bad = @($distinct | Where-Object { $_ -gt 2 })
        if ($Role -eq 'Detect') {
            # Detect: 0 = compliant, 1 = non-compliant, 2 = error.
            if ($bad.Count -gt 0) {
                Add-Result 'ExitCodeContract' 'FAIL' "Detect uses exit code(s) outside {0,1,2}: $($bad -join ',')" 'Detect must exit 0 (compliant), 1 (non-compliant), or 2 (error).'
            }
            else {
                Add-Result 'ExitCodeContract' 'PASS' "Detect exit codes within contract: $($distinct -join ',')"
            }
        }
        else {
            # Remediate: 0 = success, 2+ = error. Exit 1 from a remediation is read as
            # "still non-compliant" and is almost always a crash leaking through.
            if ($distinct -contains 1) {
                Add-Result 'ExitCodeContract' 'WARN' 'Remediate emits exit 1 (read as "still non-compliant" by PIA)' 'Remediate should exit 0 (success) or 2 (error); avoid bare exit 1.'
            }
            elseif ($bad.Count -gt 0 -and ($bad | Where-Object { $_ -ne 2 }).Count -gt 0) {
                Add-Result 'ExitCodeContract' 'WARN' "Remediate uses non-standard exit code(s): $($distinct -join ',')" 'Prefer exit 0 (success) / 2 (error).'
            }
            else {
                Add-Result 'ExitCodeContract' 'PASS' "Remediate exit codes within contract: $($distinct -join ',')"
            }
        }
    }
}

# --- 7. Matching Pester -----------------------------------------------------
$testFile = $target -replace '\.ps1$', '.Tests.ps1'
if (-not $SkipPester -and (Test-Path $testFile)) {
    if (Get-Module -ListAvailable -Name Pester | Where-Object { $_.Version -ge [version]'5.0.0' }) {
        Import-Module Pester -MinimumVersion 5.0.0 -ErrorAction SilentlyContinue
        $cfg = New-PesterConfiguration
        $cfg.Run.Path        = $testFile
        $cfg.Run.PassThru    = $true
        $cfg.Output.Verbosity = 'None'
        $p = Invoke-Pester -Configuration $cfg
        if ($p.FailedCount -gt 0) {
            Add-Result 'Pester' 'FAIL' "$($p.PassedCount) passed / $($p.FailedCount) failed" 'Fix the failing assertions in the matching .Tests.ps1.'
        }
        else {
            Add-Result 'Pester' 'PASS' "$($p.PassedCount) passed / 0 failed"
        }
    }
    else {
        Add-Result 'Pester' 'WARN' 'Pester 5+ not installed; matching test not run' 'Install-Module Pester -MinimumVersion 5.5.0 -Scope CurrentUser.'
    }
}
elseif (-not $SkipPester -and -not (Test-Path $testFile)) {
    Add-Result 'Pester' 'WARN' 'No matching .Tests.ps1 found' 'Add behavioral tests (see docs/QA-PROCESS.md backfill plan).'
}

# --- verdict ----------------------------------------------------------------
$fail = @($results | Where-Object { $_.Result -eq 'FAIL' }).Count
$warn = @($results | Where-Object { $_.Result -eq 'WARN' }).Count
if ($fail -gt 0) { $verdict = 'FAIL' }
elseif ($warn -gt 0) { $verdict = 'PASS (with warnings)' }
else { $verdict = 'PASS' }

if ($Json) {
    [pscustomobject]@{
        path     = $target
        role     = $Role
        verdict  = $verdict
        checks   = $results
        errors   = $fail
        warnings = $warn
    } | ConvertTo-Json -Depth 5
}
else {
    Write-Output ''
    Write-Output ("Validating: {0}  (role: {1})" -f $leaf, $Role)
    $table = $results | Format-Table Name, Result, Detail -AutoSize | Out-String -Width 200
    Write-Output $table.TrimEnd()
    Write-Output ''
    $summary = "VALIDATION: $verdict ($fail errors, $warn warnings)"
    if ($fail -gt 0)      { Write-Host $summary -ForegroundColor Red }
    elseif ($warn -gt 0)  { Write-Host $summary -ForegroundColor Yellow }
    else                  { Write-Host $summary -ForegroundColor Green }
}

if ($fail -gt 0) { exit 1 }
exit 0
