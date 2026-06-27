@{
    # PSScriptAnalyzerSettings.psd1 -- repo root.
    # Used identically by the local validation skill (tools/Invoke-CITScriptValidation.ps1)
    # and CI (.github/workflows/qa.yml). Tuned for Intune / NT AUTHORITY\SYSTEM / Windows
    # PowerShell 5.1, which is the production runtime for these scripts.
    #
    # Reference: docs/QA-PROCESS.md (section 1.5).

    Severity = @('Error', 'Warning')

    # Rules that map to confirmed deploy failures in this repo.
    IncludeRules = @(
        'PSAvoidUsingCmdletAliases',                    # ? / % / gci hide intent in SYSTEM logs
        'PSAvoidUsingPositionalParameters',
        'PSUseApprovedVerbs',                           # Stage-/Apply-/Failover-* warn-noise on stderr
        'PSPossibleIncorrectComparisonWithNull',        # $item.$Name -ne $null  (secure-boot-cert)
        'PSUseDeclaredVarsMoreThanAssignments',         # $renamed/$dism/$sfc captured then ignored
        'PSAvoidUsingWriteHost',                        # PIA/Datto parse stdout; Write-Host bypasses the stream
        'PSAvoidUsingInvokeExpression',
        'PSAvoidUsingPlainTextForPassword',
        'PSAvoidUsingConvertToSecureStringWithPlainText',
        'PSUseCompatibleSyntax',                        # flags PS7-only syntax for the 5.1 target
        'PSUseCompatibleCommands',                      # flags cmdlets/params missing on 5.1
        'PSUseBOMForUnicodeEncodedFile',                # backs the encoding lint
        'PSUseShouldProcessForStateChangingFunctions',
        'PSAvoidGlobalVars',
        'PSReviewUnusedParameter'
    )

    # These are unattended Intune / Datto remediation scripts that run
    # non-interactively as NT AUTHORITY\SYSTEM. -WhatIf / -Confirm / ShouldProcess
    # has no operator to prompt and does not apply, so the rule is excluded
    # repo-wide rather than suppressed per-function.
    ExcludeRules = @(
        'PSUseShouldProcessForStateChangingFunctions'
    )

    Rules = @{
        PSUseCompatibleSyntax = @{
            Enable         = $true
            TargetVersions = @('5.1')                   # Windows PowerShell 5.1 is the prod runtime
        }
        PSUseCompatibleCommands = @{
            Enable         = $true
            # Desktop 5.1 on Win10/11. Regenerate richer profiles with New-PSScriptAnalyzerProfile if needed.
            TargetProfiles = @(
                'win-8_x64_10.0.19041.0_5.1.19041.1_x64_4.0.30319.42000_framework'
            )
        }
    }
}
