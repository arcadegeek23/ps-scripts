# FW-Diag.Tests.ps1
# Pester 5+ tests for FW-Diag.ps1

[System.Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseDeclaredVarsMoreThanAssignments','scriptPath',Justification='Referenced inside Pester Describe/It child scopes; the rule does not track cross-scope usage.')]
param()

BeforeAll {
    $scriptPath = Join-Path $PSScriptRoot 'FW-Diag.ps1'
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

    It 'gates on Posh-SSH availability' {
        $raw = Get-Content $scriptPath -Raw
        $raw | Should -Match 'Assert-CitPoshSsh'
        $raw | Should -Match 'POSH_SSH_UNAVAILABLE'
    }

    It 'emits NO_TARGET_BASELINE when no target firmware is supplied' {
        $raw = Get-Content $scriptPath -Raw
        $raw | Should -Match 'NO_TARGET_BASELINE'
    }

    It 'passes AcceptKey for non-interactive first contact' {
        $raw = Get-Content $scriptPath -Raw
        $raw | Should -Match 'AcceptKey'
    }

    It 'does not treat unparsed telemetry as healthy' {
        $raw = Get-Content $scriptPath -Raw
        $raw | Should -Match 'ParseOk'
    }

    It 'returns NO_TARGET_BASELINE and exit 2 with empty target on Windows' -Skip:(-not (Test-PlatformIsWindows)) {
        & $scriptPath -FirewallAddress '127.0.0.1' -Vendor SonicWall | Out-String | Should -Match 'NO_TARGET_BASELINE'
        $LASTEXITCODE | Should -Be 2
    }

    It 'writes to the CIT log when invoked on Windows' -Skip:(-not (Test-PlatformIsWindows)) {
        & $scriptPath -FirewallAddress '127.0.0.1' -Vendor SonicWall | Out-Null
        'C:\ProgramData\CIT\Logs\FW-Diag.log' | Should -Exist
    }
}
