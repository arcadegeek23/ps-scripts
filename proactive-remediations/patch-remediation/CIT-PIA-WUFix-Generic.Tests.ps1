# CIT-PIA-WUFix-Generic.Tests.ps1
# Pester 5+ tests for CIT-PIA-WUFix-Generic.ps1

BeforeAll {
    $scriptPath = Join-Path $PSScriptRoot 'CIT-PIA-WUFix-Generic.ps1'
    $scriptName = 'CIT-PIA-WUFix-Generic'
}

function Test-PlatformIsWindows {
    return ($PSVersionTable.PSEdition -eq 'Desktop') -or
           ($PSVersionTable.PSEdition -eq 'Core' -and $PSVersionTable.Platform -eq 'Win32NT')
}

Describe 'CIT-PIA-WUFix-Generic' {
    It 'parses without syntax errors' {
        $errors = $null
        [System.Management.Automation.Language.Parser]::ParseFile($scriptPath, [ref]$null, [ref]$errors) | Out-Null
        $errors | Should -BeNullOrEmpty
    }

    It 'defines the expected helper functions in the script body' {
        $ast = [System.Management.Automation.Language.Parser]::ParseFile($scriptPath, [ref]$null, [ref]$null)
        $functionNames = $ast.FindAll({ $args[0] -is [System.Management.Automation.Language.FunctionDefinitionAst] }, $false).Name
        $functionNames | Should -Contain 'Stop-CitWuauserv'
        $functionNames | Should -Contain 'Remove-CitWUDownloadCache'
        $functionNames | Should -Contain 'Start-CitWuauserv'
        $functionNames | Should -Contain 'Invoke-CitUsoClientAction'
    }

    It 'writes to the CIT log when invoked on Windows' -Skip:(-not (Test-PlatformIsWindows)) {
        & $scriptPath | Out-Null
        'C:\ProgramData\CIT\Logs\CIT-PIA-WUFix-Generic.log' | Should -Exist
    }
}
