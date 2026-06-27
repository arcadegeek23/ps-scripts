# CIT-PIA-WUFix-Reboot.Tests.ps1
# Pester 5+ tests for CIT-PIA-WUFix-Reboot.ps1

BeforeAll {
    $scriptPath = Join-Path $PSScriptRoot 'CIT-PIA-WUFix-Reboot.ps1'
    $null = $scriptPath
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

    It 'sources the shared logger' {
        $content = Get-Content -Path $scriptPath -Raw
        $content | Should -Match 'CIT-Logging\.ps1'
    }

    It 'uses a reliable active-session check (explorer.exe owner) not Win32_ComputerSystem.UserName' {
        $content = Get-Content -Path $scriptPath -Raw
        $content | Should -Match 'Get-CitActiveSessionState'
        $content | Should -Match "Name='explorer\.exe'"
        $content | Should -Match 'GetOwner'
        $content | Should -Not -Match '\.UserName'
    }

    It 'fails closed: reboot only when forced or detection is certain and no user present' {
        $content = Get-Content -Path $scriptPath -Raw
        $content | Should -Match '\$safeToReboot\s*=\s*\$Force\s+-or\s+\(\s*\$session\.Certain\s+-and\s+-not\s+\$session\.Active\s*\)'
    }

    It 'preserves the downstream protocol tokens (SCHEDULE_VIA_DATTO / IMMEDIATE_REBOOT)' {
        $content = Get-Content -Path $scriptPath -Raw
        $content | Should -Match "Action\s*=\s*'SCHEDULE_VIA_DATTO'"
        $content | Should -Match "Action\s*=\s*'IMMEDIATE_REBOOT'"
    }

    It 'flushes stdout before scheduling the reboot' {
        $content = Get-Content -Path $scriptPath -Raw
        $content | Should -Match '\[Console\]::Out\.Flush\(\)'
        $content | Should -Match 'shutdown\.exe'
    }

    It 'writes to the CIT log when invoked on Windows' -Skip:(-not (Test-PlatformIsWindows)) {
        & $scriptPath | Out-Null
        'C:\ProgramData\CIT\Logs\CIT-PIA-WUFix-Reboot.log' | Should -Exist
    }
}
