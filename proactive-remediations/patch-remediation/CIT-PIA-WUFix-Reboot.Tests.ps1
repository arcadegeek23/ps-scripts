# CIT-PIA-WUFix-Reboot.Tests.ps1
# Pester 5+ tests for CIT-PIA-WUFix-Reboot.ps1

BeforeAll {
    $scriptPath = Join-Path $PSScriptRoot 'CIT-PIA-WUFix-Reboot.ps1'
    $scriptName = 'CIT-PIA-WUFix-Reboot'
}

function Test-PlatformIsWindows {
    return ($PSVersionTable.PSEdition -eq 'Desktop') -or
           ($PSVersionTable.PSEdition -eq 'Core' -and $PSVersionTable.Platform -eq 'Win32NT')
}

Describe 'CIT-PIA-WUFix-Reboot' {
    It 'parses without syntax errors' {
        $errors = $null
        [System.Management.Automation.Language.Parser]::ParseFile($scriptPath, [ref]$null, [ref]$errors) | Out-Null
        $errors | Should -BeNullOrEmpty
    }

    It 'sources the shared logger and uses approved verbs' {
        $content = Get-Content -Path $scriptPath -Raw
        $content | Should -Match 'CIT-Logging\.ps1'
        $content | Should -Match 'Restart-Computer'
    }

    It 'writes to the CIT log when invoked on Windows' -Skip:(-not (Test-PlatformIsWindows)) {
        & $scriptPath | Out-Null
        'C:\ProgramData\CIT\Logs\CIT-PIA-WUFix-Reboot.log' | Should -Exist
    }
}
