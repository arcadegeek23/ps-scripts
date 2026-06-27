# vendor-watchguard.ps1
# WatchGuard placeholder vendor partial for firewall PIA scripts.
# Author:  Kyle Etter
# Created: 2026-06-13
# Updated: 2026-06-13
# Tested:  Windows 10 22H2, Windows 11 23H2
# Intune:  Proactive Remediation - Shared helper
# Notes:   Phase 2. WatchGuard does not expose a convenient SSH firmware upgrade
#          path; the intended implementation uses HTTPS REST against
#          https://<fw>:8080 with an API key. Do not dot-source this file in
#          production workflows until phase 2 is implemented.

[CmdletBinding()]
param()

$ErrorActionPreference = 'Stop'
$WarningPreference     = 'Continue'

# TODO(phase-2):
# - Use Invoke-RestMethod against https://<fw>:8080 with -SkipCertificateCheck if available.
# - Headers: Authorization: Bearer <api-key>, Content-Type: application/json.
# - Endpoints: GET /system/status, POST /system/backup, POST /firmware/upgrade.
# - Because Windows PowerShell 5.1 lacks -SkipCertificateCheck, either install the
#   firewall cert in the probe's trusted store or gate the flag behind a PS7 check.

throw 'Watchguard support is phase 2; HTTPS+API-key flow not yet implemented.'
