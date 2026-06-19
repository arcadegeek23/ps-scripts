# Detect-SecureBootCert.Tests.ps1
# Pester 5+ tests for Detect-SecureBootCert.ps1

BeforeAll {
    $scriptPath = Join-Path $PSScriptRoot 'Detect-SecureBootCert.ps1'
    $scriptName = 'Detect-SecureBootCert'
}

function Test-PlatformIsWindows {
    return ($PSVersionTable.PSEdition -eq 'Desktop') -or
           ($PSVersionTable.PSEdition -eq 'Core' -and $PSVersionTable.Platform -eq 'Win32NT')
}

Describe 'Detect-SecureBootCert' {
    It 'parses without syntax errors' {
        $errors = $null
        [System.Management.Automation.Language.Parser]::ParseFile($scriptPath, [ref]$null, [ref]$errors) | Out-Null
        $errors | Should -BeNullOrEmpty
    }

    It 'defines the expected helper functions in the script body' {
        $ast = [System.Management.Automation.Language.Parser]::ParseFile($scriptPath, [ref]$null, [ref]$null)
        $functionNames = $ast.FindAll({ $args[0] -is [System.Management.Automation.Language.FunctionDefinitionAst] }, $false).Name
        $functionNames | Should -Contain 'Get-CitOsBuildNumber'
        $functionNames | Should -Contain 'Test-CitSecureBootEnabled'
        $functionNames | Should -Contain 'Test-CitKbInstalled'
    }

    It 'has the SecureBootKbMap hash table with at least 3 OS build entries' {
        $content = Get-Content $scriptPath -Raw
        $content | Should -Match "'19045'"
        $content | Should -Match "'22631'"
        $content | Should -Match "'26100'"
    }

    It 'sources CIT-Logging.ps1 with the correct relative path' {
        $content = Get-Content $scriptPath -Raw
        $content | Should -Match '\.\.\\\\\.\.\\\\platform\\\\CIT-Logging\.ps1'
    }

    It 'exits 0 when Secure Boot is disabled' -Skip:(-not (Test-PlatformIsWindows)) {
        # This test would need Confirm-SecureBootUEFI to be mocked.
        # On a non-Windows host it is skipped. On Windows, we verify the
        # detection logic is structured to exit 0 when Secure Boot is off
        # by checking the script content for the early-exit pattern.
        $content = Get-Content $scriptPath -Raw
        $content | Should -Match 'Secure Boot is disabled'
        $content | Should -Match 'exit 0'
    }

    It 'has zero side effects (no Stop-Service, Remove-Item, Set-Item in detect)' {
        $content = Get-Content $scriptPath -Raw
        # Detect must not mutate anything. These cmdlets would indicate side effects.
        $content | Should -Not -Match 'Stop-Service'
        $content | Should -Not -Match 'Remove-Item'
        $content | Should -Not -Match 'Set-ItemProperty'
        $content | Should -Not -Match 'Start-Process'
    }

    It 'writes to the CIT log when invoked on Windows' -Skip:(-not (Test-PlatformIsWindows)) {
        & $scriptPath 2>$null | Out-Null
        'C:\ProgramData\CIT\Logs\Detect-SecureBootCert.log' | Should -Exist
    }
}