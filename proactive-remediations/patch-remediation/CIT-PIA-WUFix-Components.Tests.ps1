# CIT-PIA-WUFix-Components.Tests.ps1
# Pester 5+ tests for CIT-PIA-WUFix-Components.ps1

BeforeAll {
    $scriptPath = Join-Path $PSScriptRoot 'CIT-PIA-WUFix-Components.ps1'
    $null = $scriptPath
}

function Test-PlatformIsWindows {
    return ($PSVersionTable.PSEdition -eq 'Desktop') -or
           ($PSVersionTable.PSEdition -eq 'Core' -and $PSVersionTable.Platform -eq 'Win32NT')
}

Describe 'CIT-PIA-WUFix-Components' {
    It 'parses without syntax errors' {
        $errors = $null
        [System.Management.Automation.Language.Parser]::ParseFile($scriptPath, [ref]$null, [ref]$errors) | Out-Null
        $errors | Should -BeNullOrEmpty
    }

    It 'defines the expected helper functions in the script body' {
        $ast = [System.Management.Automation.Language.Parser]::ParseFile($scriptPath, [ref]$null, [ref]$null)
        $functionNames = $ast.FindAll({ $args[0] -is [System.Management.Automation.Language.FunctionDefinitionAst] }, $false).Name
        $functionNames | Should -Contain 'Stop-CitWUServices'
        $functionNames | Should -Contain 'Rename-CitWUFolders'
        $functionNames | Should -Contain 'Start-CitWUServices'
        $functionNames | Should -Contain 'Invoke-CitDismRestoreHealth'
        $functionNames | Should -Contain 'Invoke-CitSFC'
        $functionNames | Should -Contain 'Invoke-CitWUScan'
    }

    It 'gates the COMPLETE token on every core step succeeding' {
        $content = Get-Content -Path $scriptPath -Raw
        $content | Should -Match '\$coreSuccess\s*=\s*\$stopped\s+-and\s+\$renamed\s+-and\s+\$dism\s+-and\s+\$sfc\s+-and\s+\$started'
        $content | Should -Match 'if\s*\(\s*-not\s+\$coreSuccess\s*\)'
    }

    It 'still emits the COMPLETE protocol token unchanged for downstream parsers' {
        $content = Get-Content -Path $scriptPath -Raw
        $content | Should -Match "Status\s*=\s*'COMPLETE'"
    }

    It 'emits a FAILED status and exit 2 on a partial run' {
        $content = Get-Content -Path $scriptPath -Raw
        $content | Should -Match "Status\s*=\s*'FAILED'"
        $content | Should -Match 'exit 2'
    }

    It 'writes to the CIT log when invoked on Windows' -Skip:(-not (Test-PlatformIsWindows)) {
        & $scriptPath | Out-Null
        'C:\ProgramData\CIT\Logs\CIT-PIA-WUFix-Components.log' | Should -Exist
    }
}
