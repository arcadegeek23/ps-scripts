# FW-Verify.Tests.ps1
# Pester 5+ tests for FW-Verify.ps1

BeforeAll {
    $scriptPath = Join-Path $PSScriptRoot 'FW-Verify.ps1'
    $scriptName = 'FW-Verify'
}

function Test-PlatformIsWindows {
    return ($PSVersionTable.PSEdition -eq 'Desktop') -or
           ($PSVersionTable.PSEdition -eq 'Core' -and $PSVersionTable.Platform -eq 'Win32NT')
}

Describe 'FW-Verify' {
    It 'parses without syntax errors' {
        $errors = $null
        [System.Management.Automation.Language.Parser]::ParseFile($scriptPath, [ref]$null, [ref]$errors) | Out-Null
        $errors | Should -BeNullOrEmpty
    }

    It 'writes to the CIT log when invoked on Windows' -Skip:(-not (Test-PlatformIsWindows)) {
        & $scriptPath | Out-Null
        'C:\ProgramData\CIT\Logs\FW-Verify.log' | Should -Exist
    }
}
