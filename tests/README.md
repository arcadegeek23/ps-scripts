# Tests

Pester 5+ tests. Run from repo root:

```powershell
Invoke-Pester ./tests
```

Tests should validate:
- Script syntax (`Test-ScriptFileInfo` for modules, parse-only for scripts)
- Idempotency (run twice, exit code 0 both times)
- Logging actually creates the expected file
- Exit code contract (0/1/2) for Detect/Remediate pairs
