# Win32 App Helpers

Helpers for packaging, detecting, installing, and uninstalling Win32 apps for Intune.

## Workflow

1. Wrap installer + `Install.ps1` + `Uninstall.ps1` + `Detect.ps1` in a folder
2. Run `IntuneWinAppUtil.exe` to produce the `.intunewin`
3. Upload to Intune, point install/uninstall/detect at the embedded scripts

## Detection Patterns

- File exists at versioned path
- Registry key with version stamp
- AppX package + version match
- MSI product code + version match (most reliable)
