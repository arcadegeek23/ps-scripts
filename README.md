# ps-scripts

PowerShell scripts for Microsoft Intune endpoint management — owned by **CIT Solutions** (Kyle Etter).

## What lives here

| Folder | Purpose |
|---|---|
| `proactive-remediations/` | Detection + remediation script pairs run by Intune PIA (Proactive Remediations) |
| `compliance/` | Custom compliance JSON + PowerShell discovery scripts |
| `win32-apps/` | IntuneWin packaging helpers, install/uninstall scripts, detection rules |
| `endpoint-security/` | Defender, firewall, ASR rule, BitLocker scripts |
| `platform/` | Cross-tenant utilities (device query, Graph helpers, logging) |
| `archived/` | Deprecated scripts kept for rollback reference (do not deploy) |

## Conventions

- **PowerShell 5.1 compatible** (Intune runs Windows PowerShell on most devices, not pwsh 7).
- **All scripts signed** with CIT's code-signing cert before production use.
- **Logging:** write to `C:\ProgramData\CIT\Logs\<ScriptName>.log` (create the dir if missing).
- **Exit codes:** `0` = success / no remediation needed, `1` = remediation needed / non-compliant, `2+` = error.
- **Idempotent:** safe to re-run. No side effects on second invocation.
- **No secrets in code.** Use Azure Key Vault or env vars; never hardcode tenant IDs, client secrets, or cert passwords.

## PIA Script Pairing

Every Proactive Remediation is two files:

```
proactive-remediations/
  └── <issue-name>/
      ├── Detect-<IssueName>.ps1   # runs first, exits 1 if remediation needed
      └── Remediate-<IssueName>.ps1 # runs only if Detect exits non-zero
```

Intune uploads these as **Detection script** and **Remediation script** respectively.

## Testing

- `Invoke-Pester ./tests/` from the repo root (Pester 5+)
- Manual: run Detect then Remediate, verify exit codes and log output
- Pre-deploy: validate against one test device in the **CIT** ring before assigning broadly

## QA

The repo standards above (PS 5.1 compatibility, the 0/1/2 exit-code contract, no
secrets, signing) are now enforced by a layered QA gate. See **[docs/QA-PROCESS.md](docs/QA-PROCESS.md)**
for the full design and **[docs/QA-ASSESSMENT.md](docs/QA-ASSESSMENT.md)** for the findings.

- **Before you commit**, validate one script with the `/validate-script` skill:

  ```powershell
  .\tools\Invoke-CITScriptValidation.ps1 -Path .\platform\CIT-Logging.ps1
  ```

  It runs parse, PSScriptAnalyzer (`PSScriptAnalyzerSettings.psd1`), an encoding/signing
  lint, the CIT-Logging dot-source load-contract, an exit-code-contract check, and the
  matching Pester test. See `tools/README.md`.

- **On every PR**, `.github/workflows/qa.yml` re-runs PSScriptAnalyzer and Pester on
  `windows-latest` (the production runtime) and fails the build on any analyzer error or
  failing test.

## Deploying to Intune

Use the Intune admin center or the Microsoft Graph PowerShell SDK:

```powershell
Connect-MgGraph -Scopes DeviceManagementConfiguration.ReadWrite.All
# See platform/Deploy-ProactiveRemediation.ps1 helper
```

## Safety Rules

- **Never** push scripts that touch BitLocker, Secure Boot, or TPM without a second reviewer.
- **Always** set a `Run as:` account of `System` for PIA scripts unless a user context is required.
- **Always** set a schedule (hourly/daily) — don't leave detection-only scripts at the default of "no schedule".

## License

Internal use only. © CIT Solutions.
