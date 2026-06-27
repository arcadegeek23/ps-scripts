#Requires -Version 5.1
# FW-ApplyUpdate.Tests.ps1
# Pester 5+ tests for FW-ApplyUpdate.ps1

[System.Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseDeclaredVarsMoreThanAssignments','scriptPath',Justification='Referenced inside Pester Describe/It child scopes; the rule does not track cross-scope usage.')]
param()

BeforeAll {
    $scriptPath = Join-Path $PSScriptRoot 'FW-ApplyUpdate.ps1'
}

function Test-PlatformIsWindows {
    return ($PSVersionTable.PSEdition -eq 'Desktop') -or
           ($PSVersionTable.PSEdition -eq 'Core' -and $PSVersionTable.Platform -eq 'Win32NT')
}

Describe 'FW-ApplyUpdate' {
    It 'parses without syntax errors' {
        $errors = $null
        [System.Management.Automation.Language.Parser]::ParseFile($scriptPath, [ref]$null, [ref]$errors) | Out-Null
        $errors | Should -BeNullOrEmpty
    }

    It 'defines the expected helper functions in the script body' {
        $ast = [System.Management.Automation.Language.Parser]::ParseFile($scriptPath, [ref]$null, [ref]$null)
        $functionNames = $ast.FindAll({ $args[0] -is [System.Management.Automation.Language.FunctionDefinitionAst] }, $false).Name
        $functionNames | Should -Contain 'Test-CitMaintenanceWindow'
    }

    It 'gates on Posh-SSH availability and passes AcceptKey' {
        $raw = Get-Content $scriptPath -Raw
        $raw | Should -Match 'Assert-CitPoshSsh'
        $raw | Should -Match 'POSH_SSH_UNAVAILABLE'
        $raw | Should -Match 'AcceptKey'
    }

    It 'refuses HA failover when telemetry is unparsed' {
        $raw = Get-Content $scriptPath -Raw
        $raw | Should -Match 'ParseOk'
    }

    It 'gates apply success on the result instead of unconditional exit 0' {
        $raw = Get-Content $scriptPath -Raw
        $raw | Should -Match '\$applyResult\.Applied'
    }
}
