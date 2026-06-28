#Requires -Version 5.1
# CIT-Logging.Tests.ps1
# Pester 5+ tests for platform/CIT-Logging.ps1
#
# Load-contract test (docs/QA-PROCESS.md, section 4): production scripts dot-source
# this helper THE SAME WAY they do in the field -- with -ScriptName. Before the
# param() fix this crashed with a ParameterBindingException before the caller's
# try/catch ran, killing FW-ApplyUpdate.ps1 and CIT-PIA-WUDiag.ps1 on every device.

BeforeAll {
    $script:helperPath = Join-Path $PSScriptRoot 'CIT-Logging.ps1'
}

Describe 'CIT-Logging load contract' {

    It 'parses without syntax errors' {
        $errors = $null
        [System.Management.Automation.Language.Parser]::ParseFile($helperPath, [ref]$null, [ref]$errors) | Out-Null
        $errors | Should -BeNullOrEmpty
    }

    It 'dot-sources WITH -ScriptName exactly as production does, without throwing' {
        # This is the load-contract assertion. It must not throw.
        { . $helperPath -ScriptName 'CIT-Logging.Tests' } | Should -Not -Throw
    }

    It 'dot-sources WITH NO arguments without throwing (backward compatible)' {
        { . $helperPath } | Should -Not -Throw
    }

    It 'defines Write-CITLog after the production-style dot-source' {
        . $helperPath -ScriptName 'CIT-Logging.Tests'
        Get-Command Write-CITLog -ErrorAction SilentlyContinue | Should -Not -BeNullOrEmpty
    }

    It 'defines Invoke-CITSafely after the production-style dot-source' {
        . $helperPath -ScriptName 'CIT-Logging.Tests'
        Get-Command Invoke-CITSafely -ErrorAction SilentlyContinue | Should -Not -BeNullOrEmpty
    }
}

Describe 'Write-CITLog resilience' {

    BeforeAll {
        . $helperPath -ScriptName 'CIT-Logging.Tests'
    }

    It 'does not throw to the caller when the log write fails (best-effort logging)' {
        # Simulate a transient log-file lock: Add-Content throws even though the
        # directory exists. Under $ErrorActionPreference='Stop' an unguarded write
        # would terminate the caller; the helper must swallow it and return.
        Mock -CommandName Add-Content -MockWith { throw [System.IO.IOException]::new('locked') }
        Mock -CommandName Test-Path   -MockWith { $true }

        $ErrorActionPreference = 'Stop'
        { Write-CITLog -Message 'probe' -Level INFO -ScriptName 'CIT-Logging.Tests' } | Should -Not -Throw
    }
}

Describe 'Invoke-CITSafely contract' {

    BeforeAll {
        . $helperPath -ScriptName 'CIT-Logging.Tests'
        # Keep the test hermetic: do not touch the real log directory.
        Mock -CommandName Write-CITLog -MockWith { }
    }

    It 'returns $true when the script block succeeds' {
        Invoke-CITSafely -ScriptBlock { 1 + 1 } -ScriptName 'CIT-Logging.Tests' | Should -BeTrue
    }

    It 'returns $false and does not rethrow when the script block fails' {
        Invoke-CITSafely -ScriptBlock { throw 'boom' } -ScriptName 'CIT-Logging.Tests' -Context 'probe' | Should -BeFalse
    }
}
