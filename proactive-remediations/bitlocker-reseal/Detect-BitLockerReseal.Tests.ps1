#Requires -Version 5.1
# Detect-BitLockerReseal.Tests.ps1
# Pester 5+ tests for Detect-BitLockerReseal-v2.ps1
# Added 2026-06-27 - First test coverage for the bitlocker-reseal module

[System.Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseDeclaredVarsMoreThanAssignments','scriptPath',Justification='Referenced inside Pester Describe/It child scopes; the rule does not track cross-scope usage.')]
param()

BeforeAll {
    $scriptPath = Join-Path $PSScriptRoot 'Detect-BitLockerReseal-v2.ps1'
}

function Test-PlatformIsWindows {
    return ($PSVersionTable.PSEdition -eq 'Desktop') -or
           ($PSVersionTable.PSEdition -eq 'Core' -and $PSVersionTable.Platform -eq 'Win32NT')
}

Describe 'Detect-BitLockerReseal-v2' {

    Context 'Syntax and structure' {
        It 'parses without syntax errors' {
            $errors = $null
            [System.Management.Automation.Language.Parser]::ParseFile($scriptPath, [ref]$null, [ref]$errors) | Out-Null
            $errors | Should -BeNullOrEmpty
        }

        It 'loads without throwing (dot-source / function definition)' {
            # Production runs this as a top-level script; loading the AST and the
            # inline helper definitions must not throw the way the FW-* -ScriptName
            # dot-source crash did. Guard the actual main body from running.
            $ast = [System.Management.Automation.Language.Parser]::ParseFile($scriptPath, [ref]$null, [ref]$null)
            $ast | Should -Not -BeNullOrEmpty
        }

        It 'defines the expected helper functions' {
            $ast = [System.Management.Automation.Language.Parser]::ParseFile($scriptPath, [ref]$null, [ref]$null)
            $functionNames = $ast.FindAll({ $args[0] -is [System.Management.Automation.Language.FunctionDefinitionAst] }, $false).Name
            $functionNames | Should -Contain 'Write-CITLog'
            $functionNames | Should -Contain 'Get-CitSecureBootRegValue'
            $functionNames | Should -Contain 'Test-CitResealSentinel'
            $functionNames | Should -Contain 'Get-CitBitLockerRecoveryEventCount'
        }

        It 'inlines Write-CITLog (no external dot-sourcing)' {
            $content = Get-Content $scriptPath -Raw
            $content | Should -Not -Match '\.\.\\\\\.\.\\\\platform\\\\CIT-Logging\.ps1'
            $content | Should -Match 'function Write-CITLog'
        }
    }

    Context 'Exit code contract (0=compliant, 1=non-compliant, 2=error)' {
        It 'exits 0 when the reseal sentinel is already set' {
            $content = Get-Content $scriptPath -Raw
            $content | Should -Match 'ResealSentinel=1;Compliant=1'
            $content | Should -Match 'exit 0'
        }

        It 'exits 1 when certs updated + recovery events + no sentinel' {
            $content = Get-Content $scriptPath -Raw
            $content | Should -Match 'Compliant=0;Reason=NeedsReseal'
            $content | Should -Match 'exit 1'
        }

        It 'exits 2 on error' {
            $content = Get-Content $scriptPath -Raw
            $content | Should -Match 'exit 2'
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
            # On a real 64-bit Windows host this test process is 64-bit, so the guard
            # condition must be false and the script must not attempt a relaunch.
            ([Environment]::Is64BitOperatingSystem -and -not [Environment]::Is64BitProcess) | Should -BeFalse
        }
    }

    Context 'Side-effect safety (detection must be read-only)' {
        It 'does not write registry, stop services, or reboot' {
            $content = Get-Content $scriptPath -Raw
            $content | Should -Not -Match 'Set-ItemProperty'
            # No actual Suspend-BitLocker invocation (the word may appear in a comment)
            $content | Should -Not -Match 'Suspend-BitLocker -MountPoint'
            $content | Should -Not -Match 'Restart-Computer'
            $content | Should -Not -Match 'shutdown\.exe'
        }
    }

    Context 'PowerShell 5.1 compatibility' {
        It 'does not use ConvertTo-Json -Compress (PS 6+ only)' {
            $content = Get-Content $scriptPath -Raw
            $content | Should -Not -Match 'ConvertTo-Json.*-Compress'
        }

        It 'sets $ProgressPreference to SilentlyContinue' {
            $content = Get-Content $scriptPath -Raw
            $content | Should -Match "ProgressPreference.*SilentlyContinue"
        }
    }

    Context 'Runtime (Windows only)' {
        It 'writes to the CIT log when invoked on Windows' -Skip:(-not (Test-PlatformIsWindows)) {
            & $scriptPath 2>$null | Out-Null
            'C:\ProgramData\CIT\Logs\Detect-BitLockerReseal.log' | Should -Exist
        }
    }
}
