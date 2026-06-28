# tools/

Developer QA tooling for `ps-scripts`. See `docs/QA-PROCESS.md` for the full design.

## `Invoke-CITScriptValidation.ps1` -- the `/validate-script` skill

Validate a single script against the repo's QA standards before committing. This is
the Layer 1 (local pre-commit) gate; CI (`.github/workflows/qa.yml`) re-runs the
same analyzer settings and Pester on Windows.

```powershell
# From the repo root:
.\tools\Invoke-CITScriptValidation.ps1 -Path .\platform\CIT-Logging.ps1
```

It runs, in order:

1. **Parse** -- syntax check.
2. **Analyzer** -- `Invoke-ScriptAnalyzer` with `PSScriptAnalyzerSettings.psd1` (warns if the module is absent).
3. **Encoding** -- BOM-less file with non-ASCII bytes fails (em-dash / signing class).
4. **LoggingContract** -- dot-source of `CIT-Logging.ps1` must match the helper's `param()` contract.
5. **LoadContract** -- actually dot-sources `CIT-Logging.ps1` the way the script does and asserts no throw.
6. **ExitCodeContract** -- Detect must use `{0,1,2}`; Remediate `exit 1` is flagged.
7. **Pester** -- runs the matching `<script>.Tests.ps1` if present.

It prints a PASS/FAIL/WARN table and a verdict line, and exits non-zero on any FAIL,
so it can back a `.git/hooks/pre-commit`.

### Parameters

| Parameter | Notes |
|---|---|
| `-Path <file.ps1>` | Required. The script to validate. |
| `-Role <Detect\|Remediate\|Diag\|Activity\|Module>` | Inferred from the filename when omitted. |
| `-SkipPester` | Analyzer + lint only. |
| `-Json` | Machine-readable output for hooks. |

The skill metadata for `/validate-script` lives in `.claude/skills/validate-script/SKILL.md`.

PowerShell 5.1 compatible; runs under `pwsh` 7 as well.
