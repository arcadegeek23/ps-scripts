# Remediate-HPBIOS.Tests.ps1
# Pester 5+ tests for Remediate-HPBIOS.ps1
# Created: 2026-06-24

BeforeAll {
    $scriptPath = Join-Path $PSScriptRoot 'Remediate-HPBIOS.ps1'
}

function Test-PlatformIsWindows {
    return ($PSVersionTable.PSEdition -eq 'Desktop') -or
           ($PSVersionTable.PSEdition -eq 'Core' -and $PSVersionTable.Platform -eq 'Win32NT')
}

Describe 'Remediate-HPBIOS' {

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
            $functionNames | Should -Contain 'Test-CitResealSentinel'
            $functionNames | Should -Contain 'Set-CitBIOSUpdateSentinel'
            $functionNames | Should -Contain 'Test-CitHPCMSLInstalled'
            $functionNames | Should -Contain 'Install-CitHPCMSL'
            $functionNames | Should -Contain 'Get-CitBitLockerStatus'
            $functionNames | Should -Contain 'Get-CitHPBIOSPassword'
        }

        It 'inlines Write-CITLog (no external dot-sourcing)' {
            $content = Get-Content $scriptPath -Raw
            $content | Should -Not -Match '\.\\.\\\\\\.\\.\\\\platform\\\\CIT-Logging\.ps1'
            $content | Should -Match 'function Write-CITLog'
        }

        It 'uses ASCII-only (no em-dash, no smart quotes)' {
            $content = Get-Content $scriptPath -Raw
            $content | Should -Not -Match '[\u2014\u2013\u201c\u201d\u2018\u2019\u2026]'
        }

        It 'references HPCMSL module' {
            $content = Get-Content $scriptPath -Raw
            $content | Should -Match 'HPCMSL'
        }

        It 'references Get-HPBIOSUpdates cmdlet' {
            $content = Get-Content $scriptPath -Raw
            $content | Should -Match 'Get-HPBIOSUpdates'
        }

        It 'references Suspend-BitLocker' {
            $content = Get-Content $scriptPath -Raw
            $content | Should -Match 'Suspend-BitLocker'
        }

        It 'references the HP BIOS sentinel registry key' {
            $content = Get-Content $scriptPath -Raw
            $content | Should -Match 'HPBIOSUpdate'
        }

        It 'does NOT use PS 5.1 incompatible syntax' {
            $content = Get-Content $scriptPath -Raw
            $content | Should -Not -Match '\?\?'
            $content | Should -Not -Match '\?@'
        }

        It 'does NOT force a reboot (no Restart-Computer, no shutdown)' {
            $content = Get-Content $scriptPath -Raw
            $content | Should -Not -Match 'Restart-Computer'
            $content | Should -Not -Match 'shutdown\.exe'
        }
    }

    Context 'Sentinel function logic' {
        BeforeAll {
            # Parse the sentinel functions and make them available
            $errors = $null
            $ast = [System.Management.Automation.Language.Parser]::ParseFile($scriptPath, [ref]$null, [ref]$errors)
            $funcs = $ast.FindAll({ $args[0] -is [System.Management.Automation.Language.FunctionDefinitionAst] }, $false)

            # Define the sentinel key variable and import the functions
            $setFunc = $funcs | Where-Object { $_.Name -eq 'Set-CitBIOSUpdateSentinel' }
            $testFunc = $funcs | Where-Object { $_.Name -eq 'Test-CitResealSentinel' }
            if ($setFunc) { . ([ScriptBlock]::Create($setFunc.ToString())) }
            if ($testFunc) {
                # Need to set $SentinelKey first
                $scriptBody = "`$SentinelKey = 'HKLM:\SOFTWARE\CIT\HPBIOSUpdate'; " + $testFunc.ToString()
                . ([ScriptBlock]::Create($scriptBody))
            }
        }

        It 'Test-CitResealSentinel returns false when key does not exist' {
            # This test runs on the build machine, not the target device.
            # The sentinel key won't exist here, so it should return false.
            # On Mac/pwsh, registry paths don't exist so Test-Path returns false.
            if ($PSVersionTable.Platform -eq 'Unix') {
                Set-ItResult -Skipped -Because 'Windows registry not available on Unix'
                return
            }
            Test-CitResealSentinel | Should -Be $false
        }
    }

    Context 'Safety features' {
        It 'checks for BIOS password before flashing' {
            $content = Get-Content $scriptPath -Raw
            $content | Should -Match 'BIOSPassword'
            $content | Should -Match 'Get-CitHPBIOSPassword'
        }

        It 'writes sentinel on all exit paths (success, error, manual)' {
            $content = Get-Content $scriptPath -Raw
            # Sentinel should be written for HPCMSL install failure
            $content | Should -Match 'Set-CitBIOSUpdateSentinel.*HPCMSLInstallFailed'
            # Sentinel should be written for flash failure
            $content | Should -Match 'Set-CitBIOSUpdateSentinel.*FlashFailed'
            # Sentinel should be written for BIOS password
            $content | Should -Match 'Set-CitBIOSUpdateSentinel.*BIOSPasswordSet'
            # Sentinel should be written for unhandled error
            $content | Should -Match 'Set-CitBIOSUpdateSentinel.*UnhandledError'
        }

        It 'uses -BitLocker Suspend flag in Get-HPBIOSUpdates call' {
            $content = Get-Content $scriptPath -Raw
            $content | Should -Match 'Get-HPBIOSUpdates.*-BitLocker.*Suspend'
        }

        It 'uses -Force and -Yes flags for non-interactive flash' {
            $content = Get-Content $scriptPath -Raw
            $content | Should -Match 'Get-HPBIOSUpdates.*-Force'
            $content | Should -Match 'Get-HPBIOSUpdates.*-Yes'
        }
    }

    Context 'Exit codes' {
        It 'exits 0 for success or manual action needed' {
            $content = Get-Content $scriptPath -Raw
            $exit0Matches = ([regex]::Matches($content, 'exit 0')).Count
            $exit0Matches | Should -BeGreaterOrEqual 3
        }

        It 'exits 2 for script errors' {
            $content = Get-Content $scriptPath -Raw
            $content | Should -Match 'exit 2'
        }
    }
}