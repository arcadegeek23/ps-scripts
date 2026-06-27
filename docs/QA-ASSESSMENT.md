# QA Assessment — citmn/ps-scripts (PowerShell PIA/Intune Bundle)

Prepared for: Kyle Etter, CIT Solutions · Date: 2026-06-27 · Scope: 18 reviewed scripts (firewall-fw-update, patch-compliance, patch-remediation, secure-boot-cert, bitlocker-reseal, shared platform)

---

## 1. Verdict

The repo is well-structured and disciplined on the surface — clean ASCII source, consistent logging convention, no hardcoded secrets, sensible exit-code intentions — but it is **not deploy-ready**, and the symptom Kyle reports ("works locally, fails when deployed") is real and root-caused. The single biggest reason scripts fail on deploy is that **they have never run in their actual target runtime (NT AUTHORITY\SYSTEM, non-interactive, 32-bit Intune host, with dependencies installed CurrentUser)**, so an entire class of context bugs ships untested: the shared logging helper crashes its own callers via an argument it doesn't accept, SSH/BitLocker dependencies are invisible to SYSTEM, and `$env:USERPROFILE`-based paths point at the system profile. The second systemic theme is **false success** — multiple remediations swallow every sub-step failure and emit `Status=COMPLETE` / exit 0, so genuinely broken devices auto-resolve their own tickets.

---

## 2. Top failure patterns (recurring root causes)

| # | Pattern | Scripts affected | One-line example |
|---|---------|------------------|------------------|
| 1 | **`-ScriptName` passed to a param-less helper → hard crash before try/catch** | 4 (CIT-Logging callers) | `FW-ApplyUpdate.ps1:27` dot-sources `CIT-Logging.ps1` with `-ScriptName`, but the helper has no `param()` → terminating `ParameterBindingException`, exit 1, no JSON. Also `CIT-PIA-WUDiag.ps1:17`. Root defect in `platform/CIT-Logging.ps1` (header documents a param it never implements). |
| 2 | **SYSTEM-context dependency invisibility (Posh-SSH / BitLocker module installed CurrentUser or 32-bit-redirected)** | 8 (all FW-*, both vendor partials, BitLocker remediate) | `FW-Backup.ps1:54` calls `New-SSHSession` with no `Import-Module`/availability gate; README installs Posh-SSH `-Scope CurrentUser` (invisible to SYSTEM). `Remediate-BitLockerReseal-v2.ps1:86` needs the BitLocker module unavailable to the 32-bit IME host with no SysNative re-launch. |
| 3 | **`$env:USERPROFILE` resolves to `systemprofile` under SYSTEM → primary credential path silently dead** | 5 (all FW-* via shared resolver) | `private/credential-resolution.ps1:25` builds `Join-Path $env:USERPROFILE '.cit\fw-ssh.key'`; operator's key is never found, falls through to `NO_CREDENTIAL_SOURCE`. |
| 4 | **False success / error swallowing — partial or total failure still emits success token + exit 0** | 7 | `CIT-PIA-WUFix-Generic.ps1:95-99` emits `{"Status":"COMPLETE"}` even when cache-clear and every UsoClient call fail. `vendor-fortinet.ps1:96` sets `Success=$true` unconditionally; `Remediate-PatchCompliance-v1.ps1:155` returns `$true` for a bare `Start-Process` launch. |
| 5 | **UsoClient verbs are deprecated/no-op on the targeted Win10 22H2 / Win11 23H2-24H2 builds, and don't work in session 0** | 3 (patch-remediation) | `CIT-PIA-WUFix-Generic.ps1:60-74` shells `UsoClient StartScan/StartDownload/StartInstall` — no-op on supported OSes; core remediation does nothing while reporting COMPLETE. |
| 6 | **`-match` against the Posh-SSH `.Output` string array doesn't populate `$matches` → stale/garbage parsed values** | 2 (both vendor partials) | `vendor-sonicwall.ps1:61` reads `$matches[1]` after array `-match`, feeding garbage `HARole` into `FW-ApplyUpdate.ps1:88` failover decision (outage risk). |
| 7 | **WU "freshness" keys off `QueryHistory(0,1)` → newest row is a daily Defender definition update, not a cumulative update** | 2 (patch-compliance Detect + Remediate) | `Detect-PatchCompliance-v1.ps1:99-108`: 14-day staleness gate effectively never fires → months-behind devices reported compliant. |
| 8 | **No `-AcceptKey` / known-hosts handling → first-contact SSH hangs or fails under non-interactive SYSTEM** | 4 (FW-Backup/Diag/Stage/Verify) | `FW-Verify.ps1:49-53` builds `sessionParams` with no `-AcceptKey`. |
| 9 | **Hardcoded stub telemetry baked into the parsed return contract (not just the test layer)** | 3 | `vendor-fortinet.ps1:49` hardcodes `UptimeDays=42` → `FW-Verify.ps1:71` `($diag.UptimeDays -lt 1)` can never be true → every real upgrade returns RECOVERY_NEEDED. SonicWall stub firmware string == README's example `TargetFirmware`. |
| 10 | **PendingFileRenameOperations checked with `Test-Path` (value treated as key) → always `$false`** | 2 | `Detect-PatchCompliance-v1.ps1:140` and `CIT-PIA-WUDiag.ps1:29-37` miss the most common pending-reboot signal. |
| 11 | **Non-ASCII em-dash in BOM-less UTF-8 source → signing/5.1 re-encode fragility** | 7 (all FW-* + vendor partials) | `FW-Diag.ps1:7` `— Diagnostic` (U+2014). Cosmetic today; breaks signature if re-encoded post-sign. |

---

## 3. Critical/high issues by script

| Script | Risk | Deploy-breaking issue(s) | Fix |
|--------|------|--------------------------|-----|
| `platform/CIT-Logging.ps1` | high | Unguarded `Add-Content` (line 23) throws under callers' `$ErrorActionPreference='Stop'` on a transient log lock → turns success into exit 2, or escapes the catch block entirely | Wrap the write in retry/try-catch that returns silently; never throw to caller |
| `FW-ApplyUpdate.ps1` | **critical** | `-ScriptName` on line 27 dot-source crashes every run before the try block (exit 1, no JSON) | Add `param([string]$ScriptName)` to CIT-Logging or drop the arg; test by dot-sourcing as prod does |
| `FW-Backup.ps1` | high | Posh-SSH never imported/verified (`:54`); `$env:USERPROFILE` key path dead under SYSTEM (`cred-res:25`); no `-AcceptKey` hang (`:43-54`) | Gate `Get-Module -ListAvailable Posh-SSH` + install AllUsers; use `C:\ProgramData\CIT\fw-ssh.key`; add `AcceptKey=$true` |
| `FW-Diag.ps1` | high | Same Posh-SSH/USERPROFILE/AcceptKey trio; **empty `-TargetFirmware` (default) → every firewall reports healthy/exit 0** (`:16,71`) | Emit `NO_TARGET_BASELINE`/exit 2 when target omitted; never let "no target" mean healthy |
| `FW-StageFirmware.ps1` | high | Posh-SSH gate, AcceptKey, USERPROFILE; stub `Stage-*` returns `Staged=$true` unconditionally → false-staged firmware applied later | Same SYSTEM fixes; gate `Staged` on real `$result.ExitStatus`/output |
| `FW-Verify.ps1` | high | Posh-SSH gate; **`UptimeDays=42` stub makes VERIFY_OK unreachable → every upgrade escalates to Tier 2** (`vendor:49`,`:71`); `-KeyFile` with no `-Credential`/username | Implement real version/uptime parse; supply username + `-AcceptKey` |
| `vendor-sonicwall.ps1` / `vendor-fortinet.ps1` | high | `$matches` stale after array `-match` → garbage HARole drives failover (`:60-63`); stub defaults returned as real telemetry → false compliant (`:47-49`); `Success=$true` unconditional on backup/stage/apply | Join output to single string before regex; init to `$null` + `ParseOk` flag; gate Success on `ExitStatus` |
| `Detect-PatchCompliance-v1.ps1` | high | **`QueryHistory(0,1)` = Defender update, not cumulative → stale machines pass as compliant** (`:99-108`); `Test-Path` on PendingFileRenameOps always false (`:140`) | Filter history to Cumulative/Security, exclude Defender; read the reg value, don't `Test-Path` it |
| `Remediate-PatchCompliance-v1.ps1` | high | UsoClient launch treated as success, no verification/COM fallback (`:118-155`); same `QueryHistory(0,1)` false-compliant | Drive `Microsoft.Update.Session` COM, gate success on installer ResultCode |
| `CIT-PIA-WUDiag.ps1` | high | **`-ScriptName` on line 17 crashes before try/catch → exit 1 = "remediation needed", empty stdout** | Drop the arg or add param block to CIT-Logging |
| `CIT-PIA-WUFix-Components.ps1` | high | Failed folder rename/DISM/SFC ignored — emits COMPLETE/exit 0 after partial remediation (`:120-139`) | Aggregate `$renamed`/`$dism`/`$sfc`; exit 2 + per-step booleans on any failure |
| `CIT-PIA-WUFix-DiskClean.ps1` | high | `cleanmgr -Wait` no timeout → hangs to agent kill (`:26`); partial failure still `Status=COMPLETE`/exit 0 (`:71-84`) | `Start-Process -PassThru` + `WaitForExit(ms)`/`Kill()`; per-branch booleans + before/after free-space delta |
| `CIT-PIA-WUFix-Generic.ps1` | high | UsoClient verbs no-op on targeted OSes / session-0 (`:60-74`); emits COMPLETE/exit 0 even when cache-clear + all steps fail (`:79-99`) | COM-based Search/Download/Install; gate token on real results |
| `CIT-PIA-WUFix-Reboot.ps1` | high | **`Win32_ComputerSystem.UserName` null under SYSTEM/RDP → fail-open forces reboot on in-use machine** (`:22-25`); reboot races stdout/exit before token is read (`:41-45`) | Enumerate real sessions (quser/explorer.exe owner); fail safe to user-present; emit+flush JSON then `shutdown /r /t 15` |
| `Remediate-BitLockerReseal-v2.ps1` | medium | BitLocker module unloadable in 32-bit IME host, no SysNative guard (`:86,125`) → perpetual non-compliant loop; sentinel-write failure re-suspends every cycle, holding volume unprotected (`:124-144`) | Add 64-bit re-launch guard; write sentinel before suspend / exit 2 on sentinel-write failure |
| `Detect-BitLockerReseal-v2.ps1` | medium | **Event ID 767 in `System` log is wrong source for BitLocker recovery → false compliant** (`:83-111`); remediation half broken (above) | Validate real channel `Microsoft-Windows-BitLocker/BitLocker Management` on an affected device |
| `Remediate-SecureBootCert-v2.ps1` | medium | Pester asserts `'CertificateUpdate'` (absent from script) → **pre-deploy gate is permanently red** (`Tests:100`, `README:44`); script's actual task path is correct | Fix test + README to `'Secure-Boot-Update'`; reconcile to one source of truth |
| `Detect-SecureBootCert-v2.ps1` | medium | Legacy-BIOS/non-UEFI devices fall through to exit 1 forever (`:97-152`) — bounded by Win11-only target group | Detect the `Confirm-SecureBootUEFI` throw / missing Servicing key → exit 0 `NotApplicable` |
| `vendor-watchguard.ps1` | low | None — intentional, well-documented fail-closed Phase-2 stub | No action; exclude WatchGuard from PIA assignment until Phase 2 |

---

## 4. What's already good (real strengths, keep these)

- **Logging convention is sound and consistent**: every script logs to `C:\ProgramData\CIT\Logs\<ScriptName>.log`, creates the dir if missing, uses timestamped levels with `ValidateSet`. The fix-swallowing in `Write-CITLog` is the one defect; the pattern itself is right.
- **The IME-cache lesson was learned**: the PIA detection/remediation scripts (BitLocker, secure-boot, patch-compliance, WUFix bundle) **inline** `Write-CITLog` rather than dot-sourcing — correctly avoiding the dot-source-from-cache failure. (The dot-sourcing scripts that still crash are the FW-* and WUDiag set.)
- **No secrets anywhere** — credentials are resolved via SSH key / base64 env var / ITGlue stub; nothing hardcoded. Honors the repo's no-secrets rule across all 18 scripts.
- **Genuine PS 5.1 discipline** — no ternary, `?.`, `&&`/`||`, null-coalescing, or PS7-only cmdlets in any reviewed script; `$ProgressPreference='SilentlyContinue'` set for non-interactive hosts.
- **Structured-output / exit-code intent is correct** where it executes: the FW-* JSON action tokens, the Detect 0/1/2 contract, and top-level try/catch → exit 2 mapping are the right shape for PIA/HaloPSA/Datto.
- **Honest, fail-closed stubbing**: WatchGuard throws and is excluded from `ValidateSet`; documented as Phase-2. This is exactly the forethought the rest of the bundle needs.
- **Detection scripts are genuinely side-effect-free and idempotent** (secure-boot, patch-compliance, bitlocker detect) — verified no writes/restarts.

---

## 5. Coverage gaps (testing & enforcement)

- **No script has a test that exercises the production failure modes.** Where Pester exists (FW-*, WUDiag, WUFix bundle, secure-boot, bitlocker) it **AST-parses the file only** and never dot-sources `CIT-Logging.ps1` the way production does — which is precisely why the `-ScriptName` crash (the most deploy-fatal bug in the repo) passes CI. `FW-ApplyUpdate.Tests.ps1:14-31`, `FW-Diag.Tests.ps1:27-30`.
- **Tests that do run, run against the wrong OS.** `FW-Diag.Tests.ps1` and others pass on macOS pwsh with the meaningful check skipped; `Detect-PatchCompliance-v1` was **parse-checked on macOS only, never run on Windows** (`README:106-111`) — so all the false-compliant WU logic bugs have never been observed.
- **The pre-deploy gate is broken on a Secure Boot change.** `Remediate-SecureBootCert.Tests.ps1:100` asserts a string absent from the script, so the suite is permanently red — meaning the Invoke-Pester gate (mandated by `README:39-42`, second-reviewer rule at `:55`) is either bypassed or ignored for a BitLocker/Secure-Boot-impacting script.
- **No tests at all** in the `bitlocker-reseal/` folder — only Detect, Remediate, `script_id.txt`; no `.deploy-notes.md`, so the unverified Event-ID-767 assumption and the single-fire design have nothing to validate them.
- **Integration-contract spec is wrong bundle-wide.** `.deploy-notes.md:74` says Datto parses `Status=COMPLETE` key=value, but every WUFix script emits `ConvertTo-Json -Compress` JSON — no script matches the documented parser. Reconcile before building the PIA/Datto workflow.
- **Config drift risk**: patch-compliance build-target table (e.g. 25H2=26200, unvalidated/forward-dated) is duplicated as literals across Detect and Remediate rather than shared — a one-file edit produces inconsistent fleet behavior.

**Recommended gate before any production assignment:** (1) fix the `CIT-Logging` `-ScriptName` contract and add a test that dot-sources it as prod does; (2) install Posh-SSH / verify BitLocker module `-Scope AllUsers` and add availability gates; (3) run every script under `PsExec -s` on real Win10 22H2 / Win11 23H2 / 24H2 before broad deploy; (4) replace all unconditional success tokens with aggregated per-step results.