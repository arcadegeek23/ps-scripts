BeforeAll {
    $script:DetectPath = Join-Path $PSScriptRoot 'Detect-PatchCompliance-v1.ps1'
    $script:RemediatePath = Join-Path $PSScriptRoot 'Remediate-PatchCompliance-v1.ps1'

    function Get-CodeOnlyContent {
        param([string]$Path)
        return (Get-Content $Path -Raw) -replace '(?m)^\s*#.*$', ''
    }
}

Describe 'Patch Compliance proactive remediation scripts' {
    Context 'syntax and encoding' {
        It 'parses detection and remediation scripts without syntax errors' {
            foreach ($path in @($script:DetectPath, $script:RemediatePath)) {
                $errors = $null
                [System.Management.Automation.Language.Parser]::ParseFile($path, [ref]$null, [ref]$errors) | Out-Null
                $errors | Should -BeNullOrEmpty
            }
        }

        It 'uses plain script bytes without NULs or non-ASCII characters' {
            foreach ($path in @($script:DetectPath, $script:RemediatePath)) {
                $bytes = [System.IO.File]::ReadAllBytes($path)
                ($bytes | Where-Object { $_ -eq 0 }).Count | Should -Be 0
                ($bytes | Where-Object { $_ -gt 127 }).Count | Should -Be 0
            }
        }
    }

    Context 'Intune runtime contract' {
        It 'inlines logging and keeps log write failures non-fatal' {
            foreach ($path in @($script:DetectPath, $script:RemediatePath)) {
                $content = Get-Content $path -Raw
                $content | Should -Match 'function Write-CITLog'
                $content | Should -Not -Match 'CIT-Logging\.ps1'
                $content | Should -Match 'try \{ Add-Content'
            }
        }

        It 'keeps detection read-only' {
            $codeOnly = Get-CodeOnlyContent -Path $script:DetectPath
            $codeOnly | Should -Not -Match 'New-ItemProperty'
            $codeOnly | Should -Not -Match 'Set-ItemProperty'
            $codeOnly | Should -Not -Match 'Remove-Item'
            $codeOnly | Should -Not -Match 'Start-Process'
            $codeOnly | Should -Not -Match 'Start-Service'
            $codeOnly | Should -Not -Match 'Stop-Service'
        }

        It 'uses typed registry writes compatible with Windows PowerShell 5.1' {
            $codeOnly = Get-CodeOnlyContent -Path $script:RemediatePath
            $codeOnly | Should -Match 'New-ItemProperty'
            $codeOnly | Should -Match 'PropertyType String'
            $codeOnly | Should -Match 'PropertyType DWord'
            $codeOnly | Should -Not -Match 'Set-ItemProperty[^\r\n]*-Type'
            $codeOnly | Should -Not -Match 'Set-ItemProperty[^\r\n]*-PropertyType'
        }

        It 'records async Windows Update staging and detection honors it' {
            $detect = Get-Content $script:DetectPath -Raw
            $remediate = Get-Content $script:RemediatePath -Raw

            $detect | Should -Match 'QualityUpdateStaged'
            $detect | Should -Match 'FeatureUpdateStaged'
            $detect | Should -Match 'FeatureUpdateStagingWindowHours'
            $remediate | Should -Match 'Set-CitPatchComplianceStage'
            $remediate | Should -Match "StageName 'QualityUpdate'"
            $remediate | Should -Match "StageName 'FeatureUpdate'"
        }

        It 'does not force reboot or upgrade installation' {
            $codeOnly = Get-CodeOnlyContent -Path $script:RemediatePath
            $codeOnly | Should -Not -Match 'Restart-Computer'
            $codeOnly | Should -Not -Match 'shutdown\.exe'
            $codeOnly | Should -Not -Match 'UpdateOS'
        }
    }
}
