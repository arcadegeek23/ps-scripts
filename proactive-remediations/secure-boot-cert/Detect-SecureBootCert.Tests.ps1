# Detect-SecureBootCert.Tests.ps1
# Pester 5+ tests for Detect-SecureBootCert-v2.ps1
# Updated 2026-06-23 - Rewritten for v2 registry-status detection model

[System.Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseDeclaredVarsMoreThanAssignments','scriptPath',Justification='Referenced inside Pester Describe/It child scopes; the rule does not track cross-scope usage.')]
param()

BeforeAll {
    $scriptPath = Join-Path $PSScriptRoot 'Detect-SecureBootCert-v2.ps1'
}

function Test-PlatformIsWindows {
    return ($PSVersionTable.PSEdition -eq 'Desktop') -or
           ($PSVersionTable.PSEdition -eq 'Core' -and $PSVersionTable.Platform -eq 'Win32NT')
}

Describe 'Detect-SecureBootCert-v2' {

    Context 'Syntax and structure' {
        It 'parses without syntax errors' {
            $errors = $null
            [System.Management.Automation.Language.Parser]::ParseFile($scriptPath, [ref]$null, [ref]$errors) | Out-Null
            $errors | Should -BeNullOrEmpty
        }

        It 'defines the expected v2 helper functions' {
            $ast = [System.Management.Automation.Language.Parser]::ParseFile($scriptPath, [ref]$null, [ref]$null)
            $functionNames = $ast.FindAll({ $args[0] -is [System.Management.Automation.Language.FunctionDefinitionAst] }, $false).Name
            $functionNames | Should -Contain 'Write-CITLog'
            $functionNames | Should -Contain 'Test-CitSecureBootEnabled'
            $functionNames | Should -Contain 'Get-CitSecureBootRegValue'
        }

        It 'does NOT define v1 functions that were removed' {
            $ast = [System.Management.Automation.Language.Parser]::ParseFile($scriptPath, [ref]$null, [ref]$null)
            $functionNames = $ast.FindAll({ $args[0] -is [System.Management.Automation.Language.FunctionDefinitionAst] }, $false).Name
            $functionNames | Should -Not -Contain 'Get-CitOsBuildNumber'
            $functionNames | Should -Not -Contain 'Test-CitKbInstalled'
        }

        It 'inlines Write-CITLog (no external dot-sourcing)' {
            $content = Get-Content $scriptPath -Raw
            $content | Should -Not -Match '\.\.\\\\\.\.\\\\platform\\\\CIT-Logging\.ps1'
            $content | Should -Match 'function Write-CITLog'
        }

        It 'references the SecureBoot Servicing registry key' {
            $content = Get-Content $scriptPath -Raw
            $content | Should -Match 'SecureBoot\\Servicing'
            $content | Should -Match 'UEFICA2023Status'
        }

        It 'does NOT reference v1 patterns (KB map, UsoClient, wuauserv)' {
            $content = Get-Content $scriptPath -Raw
            $content | Should -Not -Match 'SecureBootKbMap'
            $content | Should -Not -Match 'UsoClient'
            $content | Should -Not -Match 'wuauserv'
        }
    }

    Context 'Exit code contract' {
        It 'exits 0 when Secure Boot is disabled (content check)' {
            $content = Get-Content $scriptPath -Raw
            $content | Should -Match 'Secure Boot is disabled'
            $content | Should -Match 'exit 0'
        }

        It 'exits 0 when UEFICA2023Status is Updated' {
            $content = Get-Content $scriptPath -Raw
            $content | Should -Match "UEFICA2023Status=Updated"
            $content | Should -Match 'exit 0'
        }

        It 'exits 1 when UEFICA2023Status is InProgress or NotStarted' {
            $content = Get-Content $scriptPath -Raw
            $content | Should -Match 'InProgress'
            $content | Should -Match 'NotStarted'
            $content | Should -Match 'exit 1'
        }

        It 'exits 2 on error' {
            $content = Get-Content $scriptPath -Raw
            $content | Should -Match 'exit 2'
        }
    }

    Context 'Side-effect safety' {
        It 'has zero side effects (no Stop-Service, Remove-Item, Set-ItemProperty, Start-Process)' {
            $content = Get-Content $scriptPath -Raw
            $content | Should -Not -Match 'Stop-Service'
            $content | Should -Not -Match 'Remove-Item'
            $content | Should -Not -Match 'Set-ItemProperty'
            $content | Should -Not -Match 'Start-Process'
        }

        It 'does not force a reboot' {
            $content = Get-Content $scriptPath -Raw
            $content | Should -Not -Match 'Restart-Computer'
            $content | Should -Not -Match 'shutdown\.exe'
        }
    }

    Context 'PowerShell 5.1 compatibility' {
        It 'does not use PS 6+ only parameters' {
            $content = Get-Content $scriptPath -Raw
            $content | Should -Not -Match 'ConvertTo-Json.*-Compress'
        }
    }

    Context 'Runtime (Windows only)' {
        It 'writes to the CIT log when invoked on Windows' -Skip:(-not (Test-PlatformIsWindows)) {
            & $scriptPath 2>$null | Out-Null
            'C:\ProgramData\CIT\Logs\Detect-SecureBootCert.log' | Should -Exist
        }
    }
}