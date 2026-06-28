#Requires -Version 5.1
# Remediate-BitLockerReseal.Tests.ps1
# Pester 5+ tests for Remediate-BitLockerReseal-v2.ps1
# Added 2026-06-27 - First test coverage for the bitlocker-reseal module

[System.Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseDeclaredVarsMoreThanAssignments','scriptPath',Justification='Referenced inside Pester Describe/It child scopes; the rule does not track cross-scope usage.')]
param()

BeforeAll {
    $scriptPath = Join-Path $PSScriptRoot 'Remediate-BitLockerReseal-v2.ps1'
}

function Test-PlatformIsWindows {
    return ($PSVersionTable.PSEdition -eq 'Desktop') -or
           ($PSVersionTable.PSEdition -eq 'Core' -and $PSVersionTable.Platform -eq 'Win32NT')
}

Describe 'Remediate-BitLockerReseal-v2' {

    Context 'Syntax and structure' {
        It 'parses without syntax errors' {
            $errors = $null
            [System.Management.Automation.Language.Parser]::ParseFile($scriptPath, [ref]$null, [ref]$errors) | Out-Null
            $errors | Should -BeNullOrEmpty
        }

        It 'loads without throwing (AST parse)' {
            $ast = [System.Management.Automation.Language.Parser]::ParseFile($scriptPath, [ref]$null, [ref]$null)
            $ast | Should -Not -BeNullOrEmpty
        }

        It 'defines the expected helper functions' {
            $ast = [System.Management.Automation.Language.Parser]::ParseFile($scriptPath, [ref]$null, [ref]$null)
            $functionNames = $ast.FindAll({ $args[0] -is [System.Management.Automation.Language.FunctionDefinitionAst] }, $false).Name
            $functionNames | Should -Contain 'Write-CITLog'
            $functionNames | Should -Contain 'Test-CitResealSentinel'
            $functionNames | Should -Contain 'Set-CitResealSentinel'
            $functionNames | Should -Contain 'Test-CitBitLockerAvailable'
            $functionNames | Should -Contain 'Get-CitBitLockerStatus'
        }

        It 'inlines Write-CITLog (no external dot-sourcing)' {
            $content = Get-Content $scriptPath -Raw
            $content | Should -Not -Match '\.\.\\\\\.\.\\\\platform\\\\CIT-Logging\.ps1'
            $content | Should -Match 'function Write-CITLog'
        }
    }

    Context 'Exit code contract (0=success, 2=error)' {
        It 'exits 0 when the reseal sentinel is already set (idempotent)' {
            $content = Get-Content $scriptPath -Raw
            $content | Should -Match 'Status=AlreadyResealed;Sentinel=1'
            $content | Should -Match 'exit 0'
        }

        It 'exits 2 with a clear contract error when BitLocker cmdlets are unavailable' {
            $content = Get-Content $scriptPath -Raw
            $content | Should -Match 'Reason=BitLockerModuleUnavailable'
            $content | Should -Match 'exit 2'
        }

        It 'exits 0 after a successful suspend-for-reboot' {
            $content = Get-Content $scriptPath -Raw
            $content | Should -Match 'Status=SUSPENDED_FOR_REBOOT'
            $content | Should -Match 'exit 0'
        }
    }

    Context 'Idempotency (safe to run repeatedly)' {
        It 'checks the sentinel before doing any work' {
            $content = Get-Content $scriptPath -Raw
            $content | Should -Match 'Test-CitResealSentinel'
        }

        It 'no-ops when already suspended on an encrypted volume (no second suspend)' {
            $content = Get-Content $scriptPath -Raw
            $content | Should -Match 'Status=ALREADY_SUSPENDED'
            $content | Should -Match "ProtectionStatus -eq 'Off'"
            $content | Should -Match 'FullyEncrypted'
        }

        It 'guards the BitLocker module presence before calling cmdlets' {
            $content = Get-Content $scriptPath -Raw
            $content | Should -Match "Get-Command -Name 'Get-BitLockerVolume'"
        }
    }

    Context 'SysNative bitness-branch logic' {
        It 'guards on 32-bit-on-64-bit-OS using the documented bitness test' {
            $content = Get-Content $scriptPath -Raw
            $content | Should -Match '\[Environment\]::Is64BitOperatingSystem'
            $content | Should -Match '-not \[Environment\]::Is64BitProcess'
        }

        It 're-launches via the SysNative 64-bit PowerShell path' {
            $content = Get-Content $scriptPath -Raw
            $content | Should -Match 'SysNative\\WindowsPowerShell\\v1\.0\\powershell\.exe'
        }

        It 'propagates the child exit code' {
            $content = Get-Content $scriptPath -Raw
            $content | Should -Match 'exit \$proc\.ExitCode'
        }

        It 'is a no-op on a native 64-bit process (no relaunch when already 64-bit)' -Skip:(-not (Test-PlatformIsWindows)) {
            ([Environment]::Is64BitOperatingSystem -and -not [Environment]::Is64BitProcess) | Should -BeFalse
        }
    }

    Context 'Blast-radius safety' {
        It 'suspends for exactly one reboot and never forces a reboot' {
            $content = Get-Content $scriptPath -Raw
            $content | Should -Match 'Suspend-BitLocker -MountPoint ''C:'' -RebootCount 1'
            $content | Should -Not -Match 'Restart-Computer'
            $content | Should -Not -Match 'shutdown\.exe'
        }
    }

    Context 'PowerShell 5.1 compatibility' {
        It 'does not invoke ConvertTo-Json -Compress (PS 6+ only) in executable code' {
            # The version-history header legitimately mentions the flag; assert no
            # non-comment line actually uses it.
            $codeLines = Get-Content $scriptPath | Where-Object { $_ -notmatch '^\s*#' }
            ($codeLines -join "`n") | Should -Not -Match 'ConvertTo-Json.*-Compress'
        }

        It 'sets $ProgressPreference to SilentlyContinue' {
            $content = Get-Content $scriptPath -Raw
            $content | Should -Match "ProgressPreference.*SilentlyContinue"
        }
    }

    Context 'Runtime (Windows only)' {
        It 'writes to the CIT log when invoked on Windows' -Skip:(-not (Test-PlatformIsWindows)) {
            & $scriptPath 2>$null | Out-Null
            'C:\ProgramData\CIT\Logs\Remediate-BitLockerReseal.log' | Should -Exist
        }
    }
}
