# CIT-PIA-WUDiag.Tests.ps1
# Pester 5+ tests for CIT-PIA-WUDiag.ps1

BeforeAll {
    $scriptPath = Join-Path $PSScriptRoot 'CIT-PIA-WUDiag.ps1'
    $scriptName = 'CIT-PIA-WUDiag'
}

function Test-PlatformIsWindows {
    return ($PSVersionTable.PSEdition -eq 'Desktop') -or
           ($PSVersionTable.PSEdition -eq 'Core' -and $PSVersionTable.Platform -eq 'Win32NT')
}

Describe 'CIT-PIA-WUDiag' {
    It 'parses without syntax errors' {
        $errors = $null
        [System.Management.Automation.Language.Parser]::ParseFile($scriptPath, [ref]$null, [ref]$errors) | Out-Null
        $errors | Should -BeNullOrEmpty
    }

    It 'defines the expected helper functions in the script body' {
        $ast = [System.Management.Automation.Language.Parser]::ParseFile($scriptPath, [ref]$null, [ref]$null)
        $functionNames = $ast.FindAll({ $args[0] -is [System.Management.Automation.Language.FunctionDefinitionAst] }, $false).Name
        $functionNames | Should -Contain 'Get-CitFreeSpaceGB'
        $functionNames | Should -Contain 'Test-CitPendingReboot'
        $functionNames | Should -Contain 'Get-CitServiceStatus'
        $functionNames | Should -Contain 'Get-CitLastWUErrorCode'
        $functionNames | Should -Contain 'Get-CitSoftwareDistributionSizeGB'
    }

    It 'writes to the CIT log when invoked on Windows' -Skip:(-not (Test-PlatformIsWindows)) {
        & $scriptPath | Out-Null
        'C:\ProgramData\CIT\Logs\CIT-PIA-WUDiag.log' | Should -Exist
    }
}
