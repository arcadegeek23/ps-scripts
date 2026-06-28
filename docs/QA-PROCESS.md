# QA Process & Validation Skill for `citmn/ps-scripts`

This design is built directly against the verified failure classes in the review data. Every gate maps to at least one confirmed finding so nothing is theoretical. The recurring deploy-killers are:

| Failure class | Confirmed in | A gate must catch it |
|---|---|---|
| Dot-source `-ScriptName` against a paramless `CIT-Logging.ps1` | FW-ApplyUpdate (critical), CIT-PIA-WUDiag (critical) | **load-contract test** |
| Logging can throw to caller under `$ErrorActionPreference='Stop'` | CIT-Logging | **fault-injection unit test** |
| Wrong exit-code semantics (crash → exit 1 read as "non-compliant") | WUDiag, WUFix-Generic | **exit-code contract harness** |
| False success: `Status=COMPLETE`/`exit 0` after a failed action | WUFix-Components/DiskClean/Generic, FW-Backup, vendor partials | **outcome-aggregation assertions** |
| BOM-less UTF-8 + non-ASCII em-dash (signing/encoding) | every FW-* + vendor file | **encoding/BOM lint** |
| Missing 64-bit re-launch guard for module-bound cmdlets | Remediate-BitLockerReseal | **SysNative-guard static check** |
| `$null` on RHS, unapproved verbs, aliases | secure-boot-cert, vendor partials | **PSScriptAnalyzer** |
| Tests AST-parse only; never dot-source or assert behavior | all 12 existing tests | **coverage/behavior gate** |
| Pester asserts a string absent from the script (red gate ignored) | Remediate-SecureBootCert | **CI fails the build on red** |

---

## 1. Layered QA gate: local pre-commit → CI → pre-deploy

Three layers, fastest-and-cheapest first. The same `PSScriptAnalyzerSettings.psd1` and the same harness scripts are reused in all three so a clean pre-commit predicts a clean CI.

### Layer 1 — Local pre-commit (fast, no Windows required)

Runs in the author's shell (pwsh 7 on Mac/Linux works for everything except the live SYSTEM checks). Wire via `.git/hooks/pre-commit` or `pre-commit` framework calling the validation skill (§3).

| Tool / check | What it enforces | Catches |
|---|---|---|
| `Invoke-ScriptAnalyzer -Settings ./PSScriptAnalyzerSettings.psd1` | Static rules, see §1.5 | aliases, `$null` RHS, unapproved verbs, `Write-Host`, PS5.1 incompat |
| **Encoding lint** (`Test-CITEncoding`) | ASCII-only OR UTF-8-with-BOM; reject BOM-less files containing bytes > 0x7F; reject CRLF/LF drift via `.gitattributes` | em-dash signing risk across FW-* |
| **Logging-convention lint** (regex/AST) | every script either inlines `Write-CITLog` or dot-sources `CIT-Logging.ps1` **without** an unsupported `-ScriptName` arg; log path is `C:\ProgramData\CIT\Logs` | the dot-source crashes |
| **Parse** (`[Parser]::ParseFile`) | syntax (keep the existing Makefile behavior) | regressions |
| **Pester (matching test only)** | `Invoke-Pester <script>.Tests.ps1` for the file being committed | local fast feedback |

Hook is non-blocking-optional for WIP via `git commit --no-verify`, but CI re-runs everything so nothing slips.

### Layer 2 — CI on PR (authoritative, Windows)

GitHub Actions, `windows-latest`. Runs the **full** analyzer + **all** Pester + the **exit-code contract harness** + the load-contract test, on a matrix of **Windows PowerShell 5.1 (desktop)** and **pwsh 7**. 5.1 is the production runtime and is the only place `PSUseCompatibleSyntax`/`PSUseCompatibleCommands` and the real `Microsoft.PowerShell.Security` signature check are meaningful. YAML in §2. **The job fails the PR on any analyzer error-severity finding, any failing Pester test, any contract-harness mismatch, or any coverage gap below threshold** — this is what would have stopped the permanently-red `CertificateUpdate` test from shipping.

### Layer 3 — Pre-deploy gate (before PIA/Intune assignment)

Run by the deployer (manual or a `deploy` workflow_dispatch), against the signed artifact:

| Check | Tool | Catches |
|---|---|---|
| **Authenticode signature valid** | `Get-AuthenticodeSignature` → `Status -eq 'Valid'` for every `*.ps1` shipped | unsigned / encoding-broke-signature |
| **Signed bytes == committed bytes** | hash compare before/after signing | re-encode invalidation |
| **SYSTEM-context smoke** | `PsExec -s pwsh -File Detect.ps1` on a CIT-ring device; assert exit code ∈ {0,1,2} and a parseable stdout token | USERPROFILE/SysNative/UsoClient-under-SYSTEM no-ops |
| **Idempotency** | run Remediate twice; assert second run is a no-op (no second reboot, no second suspend) | BitLocker re-suspend loop, reboot loop |
| **Contract re-confirm** | the §3 harness against the live exit codes | drift between local and device |

### 1.5 `PSScriptAnalyzerSettings.psd1` (tuned for Intune / SYSTEM / PS 5.1)

```powershell
# PSScriptAnalyzerSettings.psd1 — repo root. Used identically by pre-commit, CI, and the skill.
@{
    Severity = @('Error','Warning')

    # Rules that map to confirmed deploy failures in this repo.
    IncludeRules = @(
        'PSAvoidUsingCmdletAliases',          # ? / % / gci hide intent in SYSTEM logs
        'PSAvoidUsingPositionalParameters',
        'PSUseApprovedVerbs',                 # Stage-/Apply-/Failover-CitSonicWall* warn-noise on stderr
        'PSPossibleIncorrectComparisonWithNull', # $item.$Name -ne $null  (secure-boot-cert)
        'PSUseDeclaredVarsMoreThanAssignments',  # $renamed/$dism/$sfc captured then ignored
        'PSAvoidUsingWriteHost',              # PIA/Datto parse stdout; Write-Host bypasses the stream
        'PSAvoidUsingInvokeExpression',
        'PSAvoidUsingPlainTextForPassword',
        'PSAvoidUsingConvertToSecureStringWithPlainText',
        'PSUseCompatibleSyntax',              # see rule config below — flags PS7-only syntax for 5.1
        'PSUseCompatibleCommands',            # flags cmdlets/params missing on 5.1 (e.g. -SkipCertificateCheck)
        'PSUseBOMForUnicodeEncodedFile',      # backs the encoding lint
        'PSUseShouldProcessForStateChangingFunctions',
        'PSAvoidGlobalVars',
        'PSReviewUnusedParameter'
    )

    Rules = @{
        PSUseCompatibleSyntax = @{
            Enable         = $true
            TargetVersions = @('5.1')         # Windows PowerShell 5.1 is the prod runtime
        }
        PSUseCompatibleCommands = @{
            Enable         = $true
            # Desktop 5.1 on Win10/11. Generate profiles with New-PSScriptAnalyzerProfile if richer coverage needed.
            TargetProfiles = @('win-8_x64_10.0.19041.0_5.1.19041.1_x64_4.0.30319.42000_framework')
        }
    }
}
```

Note: `PSUseCompatibleSyntax`/`PSUseCompatibleCommands` only flag *executable* PS7-only constructs — they will not catch a BOM-less em-dash in a comment, which is why the standalone encoding lint (Layer 1) is a separate, mandatory gate.

---

## 2. GitHub Actions workflow — `.github/workflows/qa.yml`

```yaml
name: QA

on:
  pull_request:
    paths: ['**/*.ps1', 'PSScriptAnalyzerSettings.psd1', '.github/workflows/qa.yml']
  push:
    branches: [main]

jobs:
  analyze-and-test:
    name: Analyze + Pester (${{ matrix.shell }})
    runs-on: windows-latest
    strategy:
      fail-fast: false
      matrix:
        include:
          - shell: powershell     # Windows PowerShell 5.1 — the production runtime
          - shell: pwsh           # PowerShell 7 — parity check
    steps:
      - uses: actions/checkout@v4

      - name: Install tooling
        shell: ${{ matrix.shell }}
        run: |
          Set-PSRepository PSGallery -InstallationPolicy Trusted
          Install-Module PSScriptAnalyzer -MinimumVersion 1.22.0 -Scope CurrentUser -Force
          Install-Module Pester           -MinimumVersion 5.5.0  -Scope CurrentUser -Force

      - name: PSScriptAnalyzer (repo settings)
        shell: ${{ matrix.shell }}
        run: |
          $files = Get-ChildItem -Recurse -Filter *.ps1 |
                   Where-Object FullName -notmatch '\\archived\\|\.Tests\.ps1$'
          $r = Invoke-ScriptAnalyzer -Path $files.FullName `
                 -Settings ./PSScriptAnalyzerSettings.psd1
          $r | Format-Table -AutoSize | Out-String | Write-Host
          $errors = @($r | Where-Object Severity -eq 'Error')
          if ($errors.Count) { throw "PSScriptAnalyzer: $($errors.Count) error(s)." }

      - name: Encoding / BOM lint
        shell: ${{ matrix.shell }}
        run: ./build/Test-CITEncoding.ps1 -Path . -FailOnViolation

      - name: Logging-convention + dot-source contract lint
        shell: ${{ matrix.shell }}
        run: ./build/Test-CITLoggingContract.ps1 -Path . -FailOnViolation

      - name: Pester (all tests, with coverage gate)
        shell: ${{ matrix.shell }}
        run: |
          $cfg = New-PesterConfiguration
          $cfg.Run.Path                     = './'
          $cfg.Run.Throw                    = $true            # fail the step on any failing test
          $cfg.TestResult.Enabled           = $true
          $cfg.TestResult.OutputPath        = 'testResults.xml'
          $cfg.CodeCoverage.Enabled         = $true
          $cfg.CodeCoverage.Path            = (Get-ChildItem -Recurse -Filter *.ps1 |
                                               Where-Object FullName -notmatch '\\archived\\|\.Tests\.ps1$').FullName
          $cfg.CodeCoverage.CoveragePercentTarget = 40         # ratchet up as backfill lands
          Invoke-Pester -Configuration $cfg

      - name: Exit-code contract harness
        shell: ${{ matrix.shell }}
        run: ./build/Invoke-CITContractHarness.ps1 -Path . -FailOnViolation

      - uses: actions/upload-artifact@v4
        if: always()
        with:
          name: pester-results-${{ matrix.shell }}
          path: testResults.xml

  signing-check:
    name: Signature validation (release branches)
    runs-on: windows-latest
    if: github.event_name == 'push' && github.ref == 'refs/heads/main'
    needs: analyze-and-test
    steps:
      - uses: actions/checkout@v4
      - name: Verify Authenticode on shipped scripts
        shell: powershell
        run: |
          $unsigned = Get-ChildItem -Recurse -Filter *.ps1 |
            Where-Object FullName -notmatch '\\archived\\|\.Tests\.ps1$' |
            Where-Object { (Get-AuthenticodeSignature $_.FullName).Status -ne 'Valid' }
          if ($unsigned) {
            $unsigned.FullName | Write-Host
            throw "$($unsigned.Count) script(s) not validly signed."
          }
```

(`signing-check` is gated to `main` because the dev tree is intentionally unsigned; the live signing cert is not in CI. On a self-hosted runner that holds the cert, this becomes the real Layer-3 gate.)

---

## 3. The validation skill — `/validate-script`

A repo skill an author runs on **one** script before committing. Implemented as `build/Invoke-CITScriptValidation.ps1` plus a thin `.claude/skills/validate-script/SKILL.md` wrapper so it is invokable as `/validate-script <path>`.

### Inputs
- `-Path <file.ps1>` (required) — the script to validate.
- `-Role <Detect|Remediate|Diag|Activity|Module>` (optional; inferred from filename: `Detect-*`→Detect, `Remediate-*`→Remediate, `*WUDiag*`/`FW-Diag`→Diag, `CIT-Logging`→Module, else Activity).
- `-SkipPester` (optional) — analyzer + lint only.
- `-Json` (optional) — machine-readable output for the pre-commit hook.

### Checks (each emits PASS / FAIL / WARN + a one-line remedy)
1. **Parse** — `[Parser]::ParseFile`; FAIL on syntax errors.
2. **Analyzer** — `Invoke-ScriptAnalyzer -Settings ./PSScriptAnalyzerSettings.psd1`; FAIL on Error severity, WARN on Warning.
3. **Encoding/signing** — BOM-less + any byte > 0x7F → FAIL (em-dash class); CRLF policy → WARN.
4. **Logging contract** — if the script dot-sources `CIT-Logging.ps1`, assert no `-ScriptName` arg is passed (the binding crash) **and** that the file actually resolves at the relative path; if it inlines `Write-CITLog`, assert the log dir is `C:\ProgramData\CIT\Logs`. FAIL on the `-ScriptName`-against-paramless pattern specifically.
5. **Load-contract (dot-source as production does)** — actually dot-sources the helper the way the script does and asserts it does not throw. This is the check that the AST-only tests never had.
6. **SysNative guard** — if the script references `Get-BitLockerVolume|Suspend-BitLocker|Get-WindowsFeature` (32-bit-redirected modules) and has **no** `PROCESSOR_ARCHITEW6432`/`SysNative`/`Is64BitProcess` re-launch → FAIL.
7. **Exit-code simulation** — runs the matching `.Tests.ps1` contract block (mocks injected) and asserts: Detect emits only {0,1,2}; Remediate/Activity emit only {0,2} (never 1); a forced failure of the primary action yields a non-zero exit and a `Status` token that is **not** `COMPLETE`. Directly targets the false-success class.
8. **Matching Pester** — runs `<script>.Tests.ps1` if present; WARN (loudly) if absent and the script has zero behavioral tests.

### Output format

Human (default): a table + a single verdict line `VALIDATION: FAIL (3 errors, 2 warnings)`; non-zero exit so the hook blocks. `-Json`: `{ path, role, verdict, checks:[{name,result,detail,remedy}], errors, warnings }`.

### Skeleton — `build/Invoke-CITScriptValidation.ps1`

```powershell
[CmdletBinding()]
param(
    [Parameter(Mandatory)][string]$Path,
    [ValidateSet('Detect','Remediate','Diag','Activity','Module')][string]$Role,
    [switch]$SkipPester,
    [switch]$Json
)
$ErrorActionPreference = 'Stop'
$results = [System.Collections.Generic.List[object]]::new()
function Add-Result($Name,$Result,$Detail,$Remedy='') {
    $results.Add([pscustomobject]@{ Name=$Name; Result=$Result; Detail=$Detail; Remedy=$Remedy })
}
$repoRoot = (git -C (Split-Path $Path) rev-parse --show-toplevel)
$settings = Join-Path $repoRoot 'PSScriptAnalyzerSettings.psd1'
$leaf     = Split-Path $Path -Leaf
if (-not $Role) {
    $Role = switch -Regex ($leaf) {
        '^Detect-'      {'Detect';    break}
        '^Remediate-'   {'Remediate'; break}
        'WUDiag|FW-Diag'{'Diag';      break}
        'CIT-Logging'   {'Module';    break}
        default         {'Activity'}
    }
}

# 1. Parse
$pe = $null
[System.Management.Automation.Language.Parser]::ParseFile($Path,[ref]$null,[ref]$pe) | Out-Null
if ($pe) { Add-Result 'Parse' 'FAIL' "$($pe.Count) syntax error(s)" 'Fix syntax before committing.' }
else     { Add-Result 'Parse' 'PASS' 'Clean parse' }

# 2. Analyzer
$an = Invoke-ScriptAnalyzer -Path $Path -Settings $settings
$anErr = @($an | Where-Object Severity -eq 'Error')
Add-Result 'Analyzer' ($(if($anErr){'FAIL'}elseif($an){'WARN'}else{'PASS'})) `
    "$($anErr.Count) error / $(@($an).Count - $anErr.Count) warning" `
    'Resolve Error-severity rules (null-RHS, unapproved verbs, PS7 syntax).'

# 3. Encoding / signing
$bytes = [IO.File]::ReadAllBytes($Path)
$hasBom = $bytes.Length -ge 3 -and $bytes[0] -eq 0xEF -and $bytes[1] -eq 0xBB -and $bytes[2] -eq 0xBF
$nonAscii = $bytes | Where-Object { $_ -gt 0x7F } | Select-Object -First 1
if ($nonAscii -and -not $hasBom) {
    Add-Result 'Encoding' 'FAIL' 'BOM-less file with non-ASCII byte (em-dash class)' `
        'Replace non-ASCII with ASCII, or save UTF-8 with BOM before signing.'
} else { Add-Result 'Encoding' 'PASS' 'ASCII-only or UTF-8-with-BOM' }

# 4 + 5. Logging / dot-source contract  (the FW-ApplyUpdate / WUDiag critical)
$src = Get-Content $Path -Raw
if ($src -match 'CIT-Logging\.ps1["'']?\s+-ScriptName') {
    Add-Result 'LoggingContract' 'FAIL' 'Dot-sources CIT-Logging.ps1 with -ScriptName (paramless script -> binding crash)' `
        'Drop -ScriptName from the dot-source, or add param([string]$ScriptName) to CIT-Logging.ps1.'
} else { Add-Result 'LoggingContract' 'PASS' 'No unsupported dot-source argument' }

# 6. SysNative guard for 32-bit-redirected modules
if ($src -match 'Get-BitLockerVolume|Suspend-BitLocker|Get-WindowsFeature' `
        -and $src -notmatch 'PROCESSOR_ARCHITEW6432|SysNative|Is64BitProcess') {
    Add-Result 'SysNativeGuard' 'FAIL' 'Uses a 64-bit-only module with no SysNative re-launch' `
        'Add the PROCESSOR_ARCHITEW6432 re-launch guard at the top of the script.'
} else { Add-Result 'SysNativeGuard' 'PASS' 'No unguarded 64-bit module dependency' }

# 7 + 8. Behavioral / exit-code contract via the matching Pester file
$testFile = $Path -replace '\.ps1$','.Tests.ps1'
if (-not $SkipPester -and (Test-Path $testFile)) {
    $cfg = New-PesterConfiguration
    $cfg.Run.Path = $testFile; $cfg.Run.PassThru = $true; $cfg.Output.Verbosity = 'None'
    $p = Invoke-Pester -Configuration $cfg
    Add-Result 'Pester' ($(if($p.FailedCount){'FAIL'}else{'PASS'})) `
        "$($p.PassedCount) passed / $($p.FailedCount) failed" 'Fix failing assertions.'
} elseif (-not (Test-Path $testFile)) {
    Add-Result 'Pester' 'WARN' 'No matching .Tests.ps1' 'Add behavioral tests (see backfill plan).'
}

# Verdict
$fail = @($results | Where-Object Result -eq 'FAIL').Count
$warn = @($results | Where-Object Result -eq 'WARN').Count
$verdict = if ($fail) {'FAIL'} elseif ($warn) {'PASS (with warnings)'} else {'PASS'}
if ($Json) {
    [pscustomobject]@{ path=$Path; role=$Role; verdict=$verdict; checks=$results;
        errors=$fail; warnings=$warn } | ConvertTo-Json -Depth 5
} else {
    $results | Format-Table Name,Result,Detail -AutoSize | Out-String | Write-Host
    Write-Host "VALIDATION: $verdict ($fail errors, $warn warnings)" `
        -Foreground $(if($fail){'Red'}elseif($warn){'Yellow'}else{'Green'})
}
if ($fail) { exit 1 }
```

`.claude/skills/validate-script/SKILL.md` is a thin wrapper: *"Run `build/Invoke-CITScriptValidation.ps1 -Path <arg>`; if it exits non-zero, summarize the FAIL rows and propose the listed remedies."*

---

## 4. Test-coverage backfill plan

Priority by `deploymentRiskScore` × "no test today". The three with **zero** tests come first: `CIT-Logging`, `bitlocker-reseal` pair, `patch-compliance` pair. Then fix the misleading existing tests (AST-only / asserting absent strings).

**Shared test infra to build first:** a `CITTestHelpers.psm1` that mocks `Get-WinEvent`, `Get-BitLockerVolume`, `Suspend-BitLocker`, registry, COM (`Microsoft.Update.Session`), and a runner that executes a script in a child PowerShell and captures `(exitcode, stdout)` so exit-code contracts are assertable.

| Script(s) | Test must assert |
|---|---|
| **`platform/CIT-Logging.ps1`** (none) | • `Write-CITLog` **never throws** when `Add-Content` fails — mock `Add-Content` to throw an `IOException` under caller `$ErrorActionPreference='Stop'`; assert the call returns silently (the high-sev best-effort-logging fix). • Log path = `C:\ProgramData\CIT\Logs\<ScriptName>.log`. • `Invoke-CITSafely` returns `$true` on success, `$false` on caught failure, and logs. • **doc/signature parity:** dot-source it *exactly as production does* — with and without `-ScriptName` — and assert the agreed contract (this is the test that catches the FW-ApplyUpdate/WUDiag critical at the source). |
| **`bitlocker-reseal/Detect-*`** (none) | • Mock `Get-WinEvent` to return a recovery event on the **operational channel** → exit 1. • No recovery event → exit 0. • Sentinel set → exit 0 regardless. • **Regression guard:** assert the query targets `Microsoft-Windows-BitLocker/BitLocker Management`, not `System`/767 (the false-compliant finding). |
| **`bitlocker-reseal/Remediate-*`** (none) | • **SysNative guard present** (string/AST). • Mock `Get-BitLockerVolume` not-`On` → no sentinel written, re-evaluable next cycle. • No TPM protector → no false success. • **Idempotency:** run twice with a *failing* sentinel write → `Suspend-BitLocker` is **not** called twice (the re-suspend loop). • Sentinel written **before** suspend. |
| **`patch-compliance/Detect-*`** (none) | • Mock WU `QueryHistory` returning a Defender definition update as newest → script must **not** report compliant off it (filter to Cumulative/Security). • `PendingFileRenameOperations` set as a **value** → reboot detected (not key-path Test-Path). • Stale cumulative (>14d) → exit 1. • UTC/local delta normalized near threshold. |
| **`patch-compliance/Remediate-*`** & **patch-remediation `WUFix-*`** (AST-only today) | • A UsoClient launch with no verifiable progress → **not** `Status=COMPLETE`, exit ≠ 0 (false-success class). • COM path success → `COMPLETE`. • Component/DiskClean: forced rename/DISM failure → `Status=PARTIAL/FAILED` + non-zero. • DiskClean: emit `FreeSpaceFreedGB` delta. • Reboot: `Win32_ComputerSystem.UserName` null must **fail safe** (treat as user-present), and JSON is flushed **before** reboot. |
| **`secure-boot-cert/*`** (tests exist but wrong) | • Replace the `'CertificateUpdate'` assertion with `'Secure-Boot-Update'` (red gate). • Mock `Confirm-SecureBootUEFI` **throw** (legacy BIOS) → `Compliant=1`/exit 0, **not** exit 1; Remediate writes **no** bitmask. • `UEFICA2023Error` non-zero → distinct token + exit 2, not silent `AlreadySet`. |
| **`firewall-fw-update/FW-*`** (AST-only today) | • **Load-contract:** dot-source `CIT-Logging.ps1` as production does → assert no crash (catches FW-ApplyUpdate critical). • Mock Posh-SSH absent → `MISSING_DEPENDENCY` JSON + exit 2 (not raw throw). • Credential resolver under SYSTEM `USERPROFILE` → does not silently miss a machine-path key. • FW-Diag: empty `-TargetFirmware` → distinct `NO_TARGET_BASELINE`, not false healthy. • Vendor partials: HA parse via `-join` then `-match` (not array `$matches`); `Backup-*`/`Stage-*` set `Success` from real output, not unconditionally. |

---

## 5. Rollout order (biggest deploy-failure reduction first)

1. **Fix `CIT-Logging.ps1` + the dot-source contract, and add its unit test.** One change neutralizes two *critical* findings (FW-ApplyUpdate, WUDiag are dead on every endpoint) plus the high-sev "logging throws and turns success into exit 2." Either add `param([string]$ScriptName)` or strip `-ScriptName` repo-wide — pick one, make the test enforce it. **Highest ROI single action.**
2. **Land `PSScriptAnalyzerSettings.psd1` + the encoding lint + the logging-contract lint, and the validation skill.** Now every new commit is screened locally for the em-dash/signing, null-RHS, alias, and unapproved-verb classes, and authors get the load-contract crash *before* commit.
3. **Add the CI workflow (`qa.yml`) with `fail-fast` on analyzer errors, failing Pester, and the contract harness.** This makes the gate authoritative and stops the permanently-red-test-ignored pattern (`CertificateUpdate`). Start coverage target low (40%) and ratchet.
4. **Build `CITTestHelpers.psm1` + the exit-code contract harness, then backfill the false-success scripts** (`WUFix-*`, `patch-compliance`, `FW-Backup`/vendor partials). This kills the most insidious class: green dashboards over unpatched/unbacked-up devices.
5. **Backfill `bitlocker-reseal` (SysNative guard + idempotency) and fix the `secure-boot-cert` tests**, then add the Layer-3 pre-deploy gate (signature validity + SYSTEM-context smoke + double-run idempotency) to the deployer's workflow.

Rationale: steps 1–3 are cheap, mostly static, and convert the two *guaranteed-dead* scripts plus the whole encoding/analyzer class from "ships broken" to "blocked at PR." Steps 4–5 require the mock harness investment but retire the false-success and idempotency-loop families that produce silent, dashboard-green failures — exactly the owner's "passes review, fails on deploy" symptom.

---

Files this proposal introduces (all paths absolute): `/workspace/ps-scripts/PSScriptAnalyzerSettings.psd1`, `/workspace/ps-scripts/.github/workflows/qa.yml`, `/workspace/ps-scripts/build/Invoke-CITScriptValidation.ps1`, `/workspace/ps-scripts/build/Test-CITEncoding.ps1`, `/workspace/ps-scripts/build/Test-CITLoggingContract.ps1`, `/workspace/ps-scripts/build/Invoke-CITContractHarness.ps1`, `/workspace/ps-scripts/tests/CITTestHelpers.psm1`, `/workspace/ps-scripts/.claude/skills/validate-script/SKILL.md`, plus a `.gitattributes` (`*.ps1 text eol=crlf`). The fix that unblocks the most endpoints is editing the existing `/workspace/ps-scripts/platform/CIT-Logging.ps1` to reconcile the `-ScriptName` contract.