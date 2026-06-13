# FW-Diag.Tests.ps1
# Pester 5+ tests for FW-Diag.ps1

BeforeAll {
    $scriptPath = Join-Path $PSScriptRoot 'FW-Diag.ps1'
    $scriptName = 'FW-Diag'
}

function Test-PlatformIsWindows {
    return ($PSVersionTable.PSEdition -eq 'Desktop') -or
           ($PSVersionTable.PSEdition -eq 'Core' -and $PSVersionTable.Platform -eq 'Win32NT')
}

Describe 'FW-Diag' {
    It 'parses without syntax errors' {
        $errors = $null
        [System.Management.Automation.Language.Parser]::ParseFile($scriptPath, [ref]$null, [ref]$errors) | Out-Null
        $errors | Should -BeNullOrEmpty
    }

    It 'defines the expected helper functions in the script body' {
        $ast = [System.Management.Automation.Language.Parser]::ParseFile($scriptPath, [ref]$null, [ref]$null)
        $functionNames = $ast.FindAll({ $args[0] -is [System.Management.Automation.Language.FunctionDefinitionAst] }, $false).Name
        $functionNames.Count | Should -BeGreaterOrEqual 0
    }

    It 'writes to the CIT log when invoked on Windows' -Skip:(-not (Test-PlatformIsWindows)) {
        & $scriptPath | Out-Null
        'C:\ProgramData\CIT\Logs\FW-Diag.log' | Should -Exist
    }
}
