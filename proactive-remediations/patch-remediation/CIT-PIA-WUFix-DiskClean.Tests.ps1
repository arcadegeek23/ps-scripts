# CIT-PIA-WUFix-DiskClean.Tests.ps1
# Pester 5+ tests for CIT-PIA-WUFix-DiskClean.ps1

BeforeAll {
    $scriptPath = Join-Path $PSScriptRoot 'CIT-PIA-WUFix-DiskClean.ps1'
    $scriptName = 'CIT-PIA-WUFix-DiskClean'
}

function Test-PlatformIsWindows {
    return ($PSVersionTable.PSEdition -eq 'Desktop') -or
           ($PSVersionTable.PSEdition -eq 'Core' -and $PSVersionTable.Platform -eq 'Win32NT')
}

Describe 'CIT-PIA-WUFix-DiskClean' {
    It 'parses without syntax errors' {
        $errors = $null
        [System.Management.Automation.Language.Parser]::ParseFile($scriptPath, [ref]$null, [ref]$errors) | Out-Null
        $errors | Should -BeNullOrEmpty
    }

    It 'defines the expected helper functions in the script body' {
        $ast = [System.Management.Automation.Language.Parser]::ParseFile($scriptPath, [ref]$null, [ref]$null)
        $functionNames = $ast.FindAll({ $args[0] -is [System.Management.Automation.Language.FunctionDefinitionAst] }, $false).Name
        $functionNames | Should -Contain 'Invoke-CitDiskCleanup'
        $functionNames | Should -Contain 'Invoke-CitComponentCleanup'
        $functionNames | Should -Contain 'Remove-CitTempFiles'
    }

    It 'writes to the CIT log when invoked on Windows' -Skip:(-not (Test-PlatformIsWindows)) {
        & $scriptPath | Out-Null
        'C:\ProgramData\CIT\Logs\CIT-PIA-WUFix-DiskClean.log' | Should -Exist
    }
}
