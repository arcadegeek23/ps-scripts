---
name: validate-script
description: Validate a single CIT Intune PowerShell script before committing. Runs parse, PSScriptAnalyzer (repo settings), encoding/signing lint, the CIT-Logging dot-source load-contract, an exit-code-contract check for Detect/Remediate scripts, and the matching Pester test. Use when an author wants to check ONE .ps1 file against the repo's QA standards before commit.
---

# /validate-script

Run the layered local QA checks against one script. This is the Layer 1 (pre-commit)
gate from `docs/QA-PROCESS.md`. CI re-runs everything on Windows, so a clean local
run predicts a clean PR.

## How to invoke

```powershell
# From the repo root:
.\tools\Invoke-CITScriptValidation.ps1 -Path <path-to-script.ps1>
```

When invoked as the `/validate-script <path>` skill: run
`tools/Invoke-CITScriptValidation.ps1 -Path <path>`. If it exits non-zero,
summarize the `FAIL` rows for the author and propose the listed remedy for each.

## Examples

```powershell
# Validate the shared logging helper:
.\tools\Invoke-CITScriptValidation.ps1 -Path .\platform\CIT-Logging.ps1

# Validate a Detect script and get machine-readable output for a pre-commit hook:
.\tools\Invoke-CITScriptValidation.ps1 -Path .\proactive-remediations\patch-compliance\Detect-PatchCompliance-v1.ps1 -Json

# Analyzer + lint only (skip the Pester run):
.\tools\Invoke-CITScriptValidation.ps1 -Path .\proactive-remediations\firewall-fw-update\FW-Diag.ps1 -SkipPester
```

## What it checks

| Check | Fails when |
|---|---|
| Parse | Syntax errors. |
| Analyzer | PSScriptAnalyzer Error-severity finding (warns if the module is not installed). |
| Encoding | BOM-less file containing a non-ASCII byte (em-dash / signing class). |
| LoggingContract | Dot-sources `CIT-Logging.ps1` with `-ScriptName` but the helper has no matching `param()`. |
| LoadContract | Dot-sourcing `CIT-Logging.ps1` as production does actually throws. |
| ExitCodeContract | Detect uses a code outside `{0,1,2}` (warns on Remediate `exit 1`). |
| Pester | The matching `<script>.Tests.ps1` has a failing test. |

## Parameters

- `-Path <file.ps1>` (required) -- the script to validate.
- `-Role <Detect|Remediate|Diag|Activity|Module>` -- inferred from the filename when omitted.
- `-SkipPester` -- analyzer + lint only.
- `-Json` -- machine-readable output for hooks.

Exit code is non-zero when any check FAILs, so it can gate a `.git/hooks/pre-commit`.
PowerShell 5.1 compatible.
