# Proactive Remediations (PIA)

Intune Proactive Remediations = a pair of PowerShell scripts (Detect + Remediate) deployed per device group on a schedule. Use them for drift detection, cleanup, and lightweight config fixes.

## Layout

```
<issue-name>/
├── Detect-<IssueName>.ps1
├── Remediate-<IssueName>.ps1
└── README.md   # what it does, exit codes, tested-on
```

## Exit Code Contract

| Exit | Meaning | Intune Behavior |
|---|---|---|
| `0` | Compliant / no action | Marked compliant, remediation skipped |
| `1` | Non-compliant / needs fix | Remediate runs, then Detect re-runs |
| `2+` | Error | Script reported as failed in Intune — investigate |

## Authoring Checklist

- [ ] Detection script reads state only — no side effects
- [ ] Remediation is idempotent (running twice == running once)
- [ ] Logs go to `C:\ProgramData\CIT\Logs\<ScriptName>.log` via `Write-CITLog`
- [ ] Tested on Win10 22H2 and Win11 23H2 minimum
- [ ] No hardcoded tenant IDs, certs, or secrets
- [ ] `Run as: System` (unless user context required)
- [ ] Schedule set (hourly or daily — never leave at default)
