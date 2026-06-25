# Detect-HPBIOS.Tests.ps1
# Pester 5+ tests for Detect-HPBIOS.ps1
# Created: 2026-06-24

BeforeAll {
    $scriptPath = Join-Path $PSScriptRoot 'Detect-HPBIOS.ps1'
    $scriptName = 'Detect-HPBIOS'
}

function Test-PlatformIsWindows {
    return ($PSVersionTable.PSEdition -eq 'Desktop') -or
           ($PSVersionTable.PSEdition -eq 'Core' -and $PSVersionTable.Platform -eq 'Win32NT')
}

Describe 'Detect-HPBIOS' {

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
            $functionNames | Should -Contain 'Get-CitManufacturer'
            $functionNames | Should -Contain 'Test-CitHPDevice'
            $functionNames | Should -Contain 'Get-CitSecureBootRegValue'
            $functionNames | Should -Contain 'ConvertTo-CitUInt32'
            $functionNames | Should -Contain 'Format-CitDwordHex'
            $functionNames | Should -Contain 'Get-CitLatestSecureBootEvent'
            $functionNames | Should -Contain 'Test-CitBIOSUpdateSentinel'
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

        It 'references the HP BIOS sentinel registry key' {
            $content = Get-Content $scriptPath -Raw
            $content | Should -Match 'HPBIOSUpdate'
        }

        It 'references UEFICA2023Error registry value' {
            $content = Get-Content $scriptPath -Raw
            $content | Should -Match 'UEFICA2023Error'
        }

        It 'references Event ID 1797' {
            $content = Get-Content $scriptPath -Raw
            $content | Should -Match '1797'
        }

        It 'checks for HP manufacturer' {
            $content = Get-Content $scriptPath -Raw
            $content | Should -Match 'Hewlett-Packard'
        }

        It 'does NOT use PS 5.1 incompatible syntax' {
            $content = Get-Content $scriptPath -Raw
            $content | Should -Not -Match '\?\?'    # null coalescing
            $content | Should -Not -Match '\?@'     # ternary
        }
    }

    Context 'Test-CitHPDevice function logic' {
        BeforeAll {
            # Parse and execute just the function definitions
            $errors = $null
            $ast = [System.Management.Automation.Language.Parser]::ParseFile($scriptPath, [ref]$null, [ref]$errors)
            $funcs = $ast.FindAll({ $args[0] -is [System.Management.Automation.Language.FunctionDefinitionAst] }, $false)
            $testFunc = $funcs | Where-Object { $_.Name -eq 'Test-CitHPDevice' }
            if ($testFunc) {
                $funcText = $testFunc.Extent.Text
                $scriptBlock = [ScriptBlock]::Create($funcText)
                . $scriptBlock
            }
        }

        It 'identifies HP as HP device' {
            Test-CitHPDevice -Manufacturer 'HP' | Should -Be $true
        }

        It 'identifies Hewlett-Packard as HP device' {
            Test-CitHPDevice -Manufacturer 'Hewlett-Packard' | Should -Be $true
        }

        It 'identifies HP Inc. as HP device' {
            Test-CitHPDevice -Manufacturer 'HP Inc.' | Should -Be $true
        }

        It 'does NOT identify Dell as HP device' {
            Test-CitHPDevice -Manufacturer 'Dell Inc.' | Should -Be $false
        }

        It 'does NOT identify Lenovo as HP device' {
            Test-CitHPDevice -Manufacturer 'Lenovo' | Should -Be $false
        }

        It 'does NOT identify empty string as HP device' {
            Test-CitHPDevice -Manufacturer '' | Should -Be $false
        }

        It 'does NOT identify null as HP device' {
            Test-CitHPDevice -Manufacturer $null | Should -Be $false
        }
    }

    Context 'Exit codes' {
        It 'exits 0 for compliant (no remediation needed)' {
            $content = Get-Content $scriptPath -Raw
            # Multiple exit 0 paths exist for compliant scenarios
            $exit0Matches = ([regex]::Matches($content, 'exit 0')).Count
            $exit0Matches | Should -BeGreaterOrEqual 4
        }

        It 'exits 1 for non-compliant (needs BIOS update)' {
            $content = Get-Content $scriptPath -Raw
            $content | Should -Match 'exit 1'
        }

        It 'exits 2 for script errors' {
            $content = Get-Content $scriptPath -Raw
            $content | Should -Match 'exit 2'
        }
    }
}