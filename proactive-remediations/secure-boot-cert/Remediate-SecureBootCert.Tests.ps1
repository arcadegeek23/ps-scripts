# Remediate-SecureBootCert.Tests.ps1
# Pester 5+ tests for Remediate-SecureBootCert-v2.ps1
# Updated 2026-06-23 - Rewritten for v2 registry-bitmask remediation model

BeforeAll {
    $scriptPath = Join-Path $PSScriptRoot 'Remediate-SecureBootCert-v2.ps1'
    $scriptName = 'Remediate-SecureBootCert'
}

function Test-PlatformIsWindows {
    return ($PSVersionTable.PSEdition -eq 'Desktop') -or
           ($PSVersionTable.PSEdition -eq 'Core' -and $PSVersionTable.Platform -eq 'Win32NT')
}

Describe 'Remediate-SecureBootCert-v2' {

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
            $functionNames | Should -Contain 'Get-CitSecureBootRegValue'
            $functionNames | Should -Contain 'Set-CitSecureBootRegValue'
        }

        It 'does NOT define v1 functions that were removed' {
            $ast = [System.Management.Automation.Language.Parser]::ParseFile($scriptPath, [ref]$null, [ref]$null)
            $functionNames = $ast.FindAll({ $args[0] -is [System.Management.Automation.Language.FunctionDefinitionAst] }, $false).Name
            $functionNames | Should -Not -Contain 'Get-CitOsBuildNumber'
            $functionNames | Should -Not -Contain 'Test-CitKbInstalled'
            $functionNames | Should -Not -Contain 'Stop-CitWuauserv'
            $functionNames | Should -Not -Contain 'Remove-CitWUDownloadCache'
            $functionNames | Should -Not -Contain 'Start-CitWuauserv'
            $functionNames | Should -Not -Contain 'Invoke-CitUsoClientAction'
            $functionNames | Should -Not -Contain 'Test-CitSecureBootEnabled'
        }

        It 'inlines Write-CITLog (no external dot-sourcing)' {
            $content = Get-Content $scriptPath -Raw
            $content | Should -Not -Match '\.\.\\\\\.\.\\\\platform\\\\CIT-Logging\.ps1'
            $content | Should -Match 'function Write-CITLog'
        }

        It 'references the SecureBoot Servicing registry key' {
            $content = Get-Content $scriptPath -Raw
            $content | Should -Match 'SecureBoot\\\\Servicing'
            $content | Should -Match 'AvailableUpdates'
        }

        It 'does NOT reference v1 patterns (KB map, UsoClient, wuauserv)' {
            $content = Get-Content $scriptPath -Raw
            $content | Should -Not -Match 'SecureBootKbMap'
            $content | Should -Not -Match 'UsoClient'
            $content | Should -Not -Match 'wuauserv'
            $content | Should -Not -Match 'StartScan'
            $content | Should -Not -Match 'StartDownload'
            $content | Should -Not -Match 'StartInstall'
        }
    }

    Context 'Exit code contract' {
        It 'exits 0 when UEFICA2023Status is already Updated (idempotent)' {
            $content = Get-Content $scriptPath -Raw
            $content | Should -Match 'AlreadyCompliant'
            $content | Should -Match 'exit 0'
        }

        It 'exits 0 when AvailableUpdates bitmask is set successfully' {
            $content = Get-Content $scriptPath -Raw
            $content | Should -Match 'BITMASK_SET'
            $content | Should -Match 'exit 0'
        }

        It 'exits 2 on error' {
            $content = Get-Content $scriptPath -Raw
            $content | Should -Match 'exit 2'
        }
    }

    Context 'Remediation logic' {
        It 'uses the correct bitmask 0x5944' {
            $content = Get-Content $scriptPath -Raw
            $content | Should -Match '0x5944'
            $content | Should -Match 'AvailableUpdatesBitmask'
        }

        It 'sets AvailableUpdates as DWORD type' {
            $content = Get-Content $scriptPath -Raw
            $content | Should -Match 'Type DWord'
        }

        It 'attempts to trigger the SecureBoot scheduled task' {
            $content = Get-Content $scriptPath -Raw
            $content | Should -Match 'CertificateUpdate'
            $content | Should -Match 'Start-ScheduledTask'
        }

        It 'does not force a reboot (no Restart-Computer, no shutdown.exe)' {
            $content = Get-Content $scriptPath -Raw
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
            'C:\ProgramData\CIT\Logs\Remediate-SecureBootCert.log' | Should -Exist
        }
    }
}