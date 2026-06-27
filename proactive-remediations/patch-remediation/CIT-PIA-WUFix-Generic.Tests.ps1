#Requires -Version 5.1
# CIT-PIA-WUFix-Generic.Tests.ps1
# Pester 5+ tests for CIT-PIA-WUFix-Generic.ps1

BeforeAll {
    $scriptPath = Join-Path $PSScriptRoot 'CIT-PIA-WUFix-Generic.ps1'
    $null = $scriptPath
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
        $functionNames | Should -Contain 'Invoke-CitComUpdateCycle'
        $functionNames | Should -Contain 'Invoke-CitUsoClientAction'
    }

    It 'drives the Windows Update COM API for scan/download/install (primary path, not UsoClient)' {
        $content = Get-Content -Path $scriptPath -Raw
        $content | Should -Match 'Microsoft\.Update\.Session'
        $content | Should -Match 'CreateUpdateSearcher'
        $content | Should -Match 'CreateUpdateDownloader'
        $content | Should -Match 'CreateUpdateInstaller'
    }

    It 'gates the COMPLETE token on the cache clear and the COM cycle succeeding' {
        $content = Get-Content -Path $scriptPath -Raw
        $content | Should -Match 'if\s*\(\s*\$cache\s+-and\s+\$com\.Succeeded\s*\)'
        $content | Should -Match 'ResultCode'
    }

    It 'still emits the COMPLETE protocol token unchanged for downstream parsers' {
        $content = Get-Content -Path $scriptPath -Raw
        $content | Should -Match "Status\s*=\s*'COMPLETE'"
    }

    It 'emits a FAILED status and exit 2 when work did not succeed' {
        $content = Get-Content -Path $scriptPath -Raw
        $content | Should -Match "Status\s*=\s*'FAILED'"
        $content | Should -Match 'exit 2'
    }

    It 'writes to the CIT log when invoked on Windows' -Skip:(-not (Test-PlatformIsWindows)) {
        & $scriptPath | Out-Null
        'C:\ProgramData\CIT\Logs\CIT-PIA-WUFix-Generic.log' | Should -Exist
    }
}
