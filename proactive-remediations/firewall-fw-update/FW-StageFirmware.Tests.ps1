# FW-StageFirmware.Tests.ps1
# Pester 5+ tests for FW-StageFirmware.ps1

BeforeAll {
    $scriptPath = Join-Path $PSScriptRoot 'FW-StageFirmware.ps1'
    $scriptName = 'FW-StageFirmware'
}

function Test-PlatformIsWindows {
    return ($PSVersionTable.PSEdition -eq 'Desktop') -or
           ($PSVersionTable.PSEdition -eq 'Core' -and $PSVersionTable.Platform -eq 'Win32NT')
}

Describe 'FW-StageFirmware' {
    It 'parses without syntax errors' {
        $errors = $null
        [System.Management.Automation.Language.Parser]::ParseFile($scriptPath, [ref]$null, [ref]$errors) | Out-Null
        $errors | Should -BeNullOrEmpty
    }

    It 'writes to the CIT log when invoked on Windows' -Skip:(-not (Test-PlatformIsWindows)) {
        & $scriptPath | Out-Null
        'C:\ProgramData\CIT\Logs\FW-StageFirmware.log' | Should -Exist
    }
}
