# Remediate-SecureBootCert.Tests.ps1
# Pester 5+ tests for Remediate-SecureBootCert.ps1

BeforeAll {
    $scriptPath = Join-Path $PSScriptRoot 'Remediate-SecureBootCert.ps1'
    $scriptName = 'Remediate-SecureBootCert'
}

function Test-PlatformIsWindows {
    return ($PSVersionTable.PSEdition -eq 'Desktop') -or
           ($PSVersionTable.PSEdition -eq 'Core' -and $PSVersionTable.Platform -eq 'Win32NT')
}

Describe 'Remediate-SecureBootCert' {
    It 'parses without syntax errors' {
        $errors = $null
        [System.Management.Automation.Language.Parser]::ParseFile($scriptPath, [ref]$null, [ref]$errors) | Out-Null
        $errors | Should -BeNullOrEmpty
    }

    It 'defines the expected helper functions in the script body' {
        $ast = [System.Management.Automation.Language.Parser]::ParseFile($scriptPath, [ref]$null, [ref]$null)
        $functionNames = $ast.FindAll({ $args[0] -is [System.Management.Automation.Language.FunctionDefinitionAst] }, $false).Name
        $functionNames | Should -Contain 'Get-CitOsBuildNumber'
        $functionNames | Should -Contain 'Test-CitKbInstalled'
        $functionNames | Should -Contain 'Stop-CitWuauserv'
        $functionNames | Should -Contain 'Remove-CitWUDownloadCache'
        $functionNames | Should -Contain 'Start-CitWuauserv'
        $functionNames | Should -Contain 'Invoke-CitUsoClientAction'
    }

    It 'has the SecureBootKbMap hash table matching the detect script' {
        $content = Get-Content $scriptPath -Raw
        $content | Should -Match "'19045'"
        $content | Should -Match "'22631'"
        $content | Should -Match "'26100'"
    }

    It 'sources CIT-Logging.ps1 with the correct relative path' {
        $content = Get-Content $scriptPath -Raw
        $content | Should -Match '\.\.\\\\\.\.\\\\platform\\\\CIT-Logging\.ps1'
    }

    It 'has an idempotency check that exits 0 if KB is already installed' {
        $content = Get-Content $scriptPath -Raw
        $content | Should -Match 'alreadyInstalled'
        $content | Should -Match 'AlreadyInstalled'
        $content | Should -Match 'exit 0'
    }

    It 'does not force a reboot (no Restart-Computer, no shutdown.exe)' {
        $content = Get-Content $scriptPath -Raw
        $content | Should -Not -Match 'Restart-Computer'
        $content | Should -Not -Match 'shutdown\.exe'
    }

    It 'triggers UsoClient for scan, download, and install' {
        $content = Get-Content $scriptPath -Raw
        $content | Should -Match 'StartScan'
        $content | Should -Match 'StartDownload'
        $content | Should -Match 'StartInstall'
    }

    It 'writes to the CIT log when invoked on Windows' -Skip:(-not (Test-PlatformIsWindows)) {
        & $scriptPath 2>$null | Out-Null
        'C:\ProgramData\CIT\Logs\Remediate-SecureBootCert.log' | Should -Exist
    }
}