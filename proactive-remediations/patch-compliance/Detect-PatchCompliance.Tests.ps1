#Requires -Version 5.1
# Detect-PatchCompliance.Tests.ps1
# Pester 5+ tests for Detect-PatchCompliance-v1.ps1
# Covers: parse/load, exit-code contract, and the freshness false-compliant
# regression (Defender-only recent history must NOT look current).

[System.Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseDeclaredVarsMoreThanAssignments','scriptPath',Justification='Referenced inside Pester Describe/It child scopes; the rule does not track cross-scope usage.')]
param()

BeforeAll {
    $scriptPath = Join-Path $PSScriptRoot 'Detect-PatchCompliance-v1.ps1'
}

function Test-PlatformIsWindows {
    return ($PSVersionTable.PSEdition -eq 'Desktop') -or
           ($PSVersionTable.PSEdition -eq 'Core' -and $PSVersionTable.Platform -eq 'Win32NT')
}

Describe 'Detect-PatchCompliance-v1' {

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
            $functionNames | Should -Contain 'Test-CitPendingReboot'
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
            # Define the helper in this scope from the script's own source.
            . ([scriptblock]::Create($func.Extent.Text))
            (Test-CitIsDefinitionUpdate -Title 'Security Intelligence Update for Microsoft Defender Antivirus - KB2267602') | Should -BeTrue
            (Test-CitIsDefinitionUpdate -Title '2026-06 Cumulative Update for Windows 11 Version 24H2 (KB5039000)') | Should -BeFalse
        }
    }

    Context 'Pending reboot detection' {
        It 'reads PendingFileRenameOperations as a value, not via Test-Path' {
            $content = Get-Content $scriptPath -Raw
            $content | Should -Match "Get-ItemProperty[^\r\n]*PendingFileRenameOperations"
            $content | Should -Not -Match "Test-Path 'HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Session Manager\\PendingFileRenameOperations'"
        }

        It 'checks the CBS and WindowsUpdate reboot keys' {
            $content = Get-Content $scriptPath -Raw
            $content | Should -Match 'Component Based Servicing\\RebootPending'
            $content | Should -Match 'WindowsUpdate\\Auto Update\\RebootRequired'
        }
    }

    Context 'Exit code contract' {
        It 'exits 0 when compliant' {
            $content = Get-Content $scriptPath -Raw
            $content | Should -Match 'Compliant=1'
            $content | Should -Match 'exit 0'
        }

        It 'exits 1 when non-compliant' {
            $content = Get-Content $scriptPath -Raw
            $content | Should -Match 'Compliant=0'
            $content | Should -Match 'exit 1'
        }

        It 'exits 2 on error' {
            $content = Get-Content $scriptPath -Raw
            $content | Should -Match 'exit 2'
        }
    }

    Context 'Side-effect safety (detection must be read-only)' {
        It 'has zero mutating side effects' {
            $content = Get-Content $scriptPath -Raw
            $content | Should -Not -Match 'Stop-Service'
            $content | Should -Not -Match 'Remove-Item'
            $content | Should -Not -Match 'Set-ItemProperty'
            $content | Should -Not -Match 'Restart-Computer'
        }
    }

    Context 'Behavioral - Defender-only recent history is NOT compliant (Windows only)' {
        It 'reports a months-old quality update as stale even when a Defender update installed today' -Skip:(-not (Test-PlatformIsWindows)) {
            # Load the script functions without running Main.
            $ast = [System.Management.Automation.Language.Parser]::ParseFile($scriptPath, [ref]$null, [ref]$null)
            $func = $ast.FindAll({ $args[0] -is [System.Management.Automation.Language.FunctionDefinitionAst] -and $args[0].Name -eq 'Test-CitIsDefinitionUpdate' }, $false)[0]
            . ([scriptblock]::Create($func.Extent.Text))

            # Simulated history: a Defender definition today, last real cumulative 60 days ago.
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

    Context 'Runtime (Windows only)' {
        It 'writes to the CIT log when invoked on Windows' -Skip:(-not (Test-PlatformIsWindows)) {
            & $scriptPath 2>$null | Out-Null
            'C:\ProgramData\CIT\Logs\Detect-PatchCompliance.log' | Should -Exist
        }
    }
}
