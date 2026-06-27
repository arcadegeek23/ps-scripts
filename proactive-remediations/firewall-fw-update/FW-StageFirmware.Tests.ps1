# FW-StageFirmware.Tests.ps1
# Pester 5+ tests for FW-StageFirmware.ps1

[System.Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseDeclaredVarsMoreThanAssignments','scriptPath',Justification='Referenced inside Pester Describe/It child scopes; the rule does not track cross-scope usage.')]
param()

BeforeAll {
    $scriptPath = Join-Path $PSScriptRoot 'FW-StageFirmware.ps1'
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

    It 'gates on Posh-SSH availability and passes AcceptKey' {
        $raw = Get-Content $scriptPath -Raw
        $raw | Should -Match 'Assert-CitPoshSsh'
        $raw | Should -Match 'POSH_SSH_UNAVAILABLE'
        $raw | Should -Match 'AcceptKey'
    }
}
