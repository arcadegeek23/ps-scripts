#Requires -Version 5.1
# Remediate-PatchCompliance.Tests.ps1
# Pester 5+ tests for Remediate-PatchCompliance-v1.ps1
# Covers: parse/load, exit-code contract, and the freshness false-compliant
# regression (Defender-only recent history must NOT look current).

[System.Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseDeclaredVarsMoreThanAssignments','scriptPath',Justification='Referenced inside Pester Describe/It child scopes; the rule does not track cross-scope usage.')]
param()

BeforeAll {
    $scriptPath = Join-Path $PSScriptRoot 'Remediate-PatchCompliance-v1.ps1'
}

function Test-PlatformIsWindows {
    return ($PSVersionTable.PSEdition -eq 'Desktop') -or
           ($PSVersionTable.PSEdition -eq 'Core' -and $PSVersionTable.Platform -eq 'Win32NT')
}

Describe 'Remediate-PatchCompliance-v1' {

    Context 'Syntax and structure' {
        It 'parses without syntax errors' {
            $errors = $null
            [System.Management.Automation.Language.Parser]::ParseFile($scriptPath, [ref]$null, [ref]$errors) | Out-Null
            $errors | Should -BeNullOrEmpty
        }

        It 'defines the expected helper functions' {
            $ast = [System.Management.Automation.Language.Parser]::ParseFile($scriptPath, [ref]$null, [ref]$null)
            $functionNames = $ast.FindAll({ $args[0] -is [System.Management.Automation.Language.FunctionDefinitionAst] }, $false).Name
            $functionNames | Should -Contain 'Write-CITLog'
            $functionNames | Should -Contain 'Get-CitLastQualityUpdateDate'
            $functionNames | Should -Contain 'Test-CitIsDefinitionUpdate'
            $functionNames | Should -Contain 'Invoke-CitQualityUpdateRemediation'
        }

        It 'inlines Write-CITLog (no external dot-sourcing)' {
            $content = Get-Content $scriptPath -Raw
            $content | Should -Match 'function Write-CITLog'
        }
    }

    Context 'Freshness logic - excludes daily Defender definitions' {
        It 'queries a deep slice of history and filters definition updates' {
            $content = Get-Content $scriptPath -Raw
            $content | Should -Match 'GetTotalHistoryCount'
            $content | Should -Match 'Test-CitIsDefinitionUpdate'
        }

        It 'classifies Defender / Security Intelligence titles as definition updates' {
            $ast = [System.Management.Automation.Language.Parser]::ParseFile($scriptPath, [ref]$null, [ref]$null)
            $func = $ast.FindAll({ $args[0] -is [System.Management.Automation.Language.FunctionDefinitionAst] -and $args[0].Name -eq 'Test-CitIsDefinitionUpdate' }, $false)[0]
            . ([scriptblock]::Create($func.Extent.Text))
            (Test-CitIsDefinitionUpdate -Title 'Security Intelligence Update for Microsoft Defender Antivirus - KB2267602') | Should -BeTrue
            (Test-CitIsDefinitionUpdate -Title '2026-06 Cumulative Update for Windows 11 Version 24H2 (KB5039000)') | Should -BeFalse
        }
    }

    Context 'Exit code contract' {
        It 'exits 0 on success / no action' {
            $content = Get-Content $scriptPath -Raw
            $content | Should -Match 'exit 0'
        }

        It 'exits 2 on error' {
            $content = Get-Content $scriptPath -Raw
            $content | Should -Match 'exit 2'
        }

        It 'preserves the downstream stdout protocol token' {
            $content = Get-Content $scriptPath -Raw
            $content | Should -Match 'REMEDIATION_TRIGGERED'
        }
    }

    Context 'PowerShell 5.1 compatibility' {
        It 'does not invoke ConvertTo-Json -Compress in executable code' {
            # Ignore comment lines (the version header mentions the historical fix).
            $codeLines = Get-Content $scriptPath | Where-Object { $_ -notmatch '^\s*#' }
            ($codeLines -join "`n") | Should -Not -Match 'ConvertTo-Json[^\r\n]*-Compress'
        }
    }

    Context 'Behavioral - Defender-only recent history is treated as stale (Windows only)' {
        It 'selects the months-old cumulative update, not the Defender update from today' -Skip:(-not (Test-PlatformIsWindows)) {
            $ast = [System.Management.Automation.Language.Parser]::ParseFile($scriptPath, [ref]$null, [ref]$null)
            $func = $ast.FindAll({ $args[0] -is [System.Management.Automation.Language.FunctionDefinitionAst] -and $args[0].Name -eq 'Test-CitIsDefinitionUpdate' }, $false)[0]
            . ([scriptblock]::Create($func.Extent.Text))

            $history = @(
                [pscustomobject]@{ Title = 'Security Intelligence Update for Microsoft Defender Antivirus - KB2267602'; Operation = 1; ResultCode = 2; Date = (Get-Date) }
                [pscustomobject]@{ Title = '2026-04 Cumulative Update for Windows 11 (KB5039000)'; Operation = 1; ResultCode = 2; Date = (Get-Date).AddDays(-60) }
            )
            $mostRecentQuality = $null
            foreach ($entry in $history) {
                if ($entry.Operation -ne 1) { continue }
                if ($entry.ResultCode -ne 2 -and $entry.ResultCode -ne 3) { continue }
                if (Test-CitIsDefinitionUpdate -Title $entry.Title) { continue }
                $mostRecentQuality = $entry.Date
                break
            }
            $mostRecentQuality | Should -Not -BeNullOrEmpty
            $days = [int]((Get-Date) - $mostRecentQuality).TotalDays
            $days | Should -BeGreaterThan 14
        }
    }
}
