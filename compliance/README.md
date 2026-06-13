# Custom Compliance Scripts

PowerShell discovery scripts paired with JSON compliance rules for Intune custom compliance policies.

## Format

Each script returns either:
- A hashtable of `$true` / `$false` per rule name, or
- A single boolean for simple one-rule checks

Intune uploads the script + a JSON rule file separately.

See: https://learn.microsoft.com/mem/intune/protect/compliance-custom-script
