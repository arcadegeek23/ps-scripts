# vendor-parsing.Tests.ps1
# Pester 5+ tests for the firewall vendor partials and credential resolver.
# These exercise the deploy-failure guards added for SYSTEM context, the
# Posh-SSH gate, $matches/ParseOk parsing, and the gated success flags.
# They run cross-platform: no real SSH hardware or Posh-SSH module required.

BeforeAll {
    $here = $PSScriptRoot

    # Stub the logging helper so the partials can be dot-sourced in isolation.
    function Write-CITLog {
        [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSReviewUnusedParameter','',Justification='Mock function parameters exist to match the real signature; intentionally unused.')]
        param(
            [string] $Message,
            [string] $Level = 'INFO',
            [string] $ScriptName
        )
    }

    # Define a no-op Invoke-SSHCommand so Pester's Mock has a command to replace
    # (Posh-SSH is not installed in the cross-platform test host).
    function Invoke-SSHCommand {
        [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSReviewUnusedParameter','',Justification='Mock function parameters exist to match the real signature; intentionally unused.')]
        param($SSHSession, [string] $Command, $ErrorAction)
    }

    . (Join-Path $here 'credential-resolution.ps1')
    . (Join-Path $here 'vendor-sonicwall.ps1')
    . (Join-Path $here 'vendor-fortinet.ps1')

    # Lightweight fake of Invoke-SSHCommand output: .Output (string array) and
    # .ExitStatus, matching the Posh-SSH shape the partials consume.
    function New-FakeSshResult {
        param([string[]] $Output, [int] $ExitStatus = 0)
        return [PSCustomObject]@{ Output = $Output; ExitStatus = $ExitStatus }
    }
}

Describe 'credential-resolution' {

    It 'defines the Posh-SSH availability gate' {
        Get-Command Assert-CitPoshSsh -ErrorAction SilentlyContinue | Should -Not -BeNullOrEmpty
    }

    It 'does not build the default key path from USERPROFILE' {
        $raw = Get-Content (Join-Path $PSScriptRoot 'credential-resolution.ps1') -Raw
        # The systemprofile trap: USERPROFILE must not be joined into the key path.
        $raw | Should -Not -Match "Join-Path\s+\`$env:USERPROFILE"
        $raw | Should -Match 'ProgramData'
    }

    It 'returns a Username alongside an SSH key so KeyFile auth has a user' {
        $keyFile = Join-Path ([System.IO.Path]::GetTempPath()) ('cit-test-{0}.key' -f ([guid]::NewGuid()))
        Set-Content -Path $keyFile -Value 'dummy' -Force
        try {
            $cred = Get-CitFirewallCredential -KeyPath $keyFile
            $cred.Source   | Should -Be 'SSH_KEY'
            $cred.Username | Should -Not -BeNullOrEmpty
        } finally {
            Remove-Item $keyFile -Force -ErrorAction SilentlyContinue
        }
    }

    It 'reports NO_CREDENTIAL_SOURCE when nothing is available' {
        $saved = @{
            Key  = $env:CIT_FW_SSH_KEY
            Pia  = $env:PIA_FW_CREDENTIAL
            Tok  = $env:ITGLUE_API_TOKEN
            Sub  = $env:ITGLUE_SUBDOMAIN
        }
        # Point the key override at a path that definitely does not exist (and is
        # valid on this OS) so resolution falls through to NO_CREDENTIAL_SOURCE
        # without touching a Windows-only C:\ drive on the Linux/macOS test host.
        $env:CIT_FW_SSH_KEY    = (Join-Path ([System.IO.Path]::GetTempPath()) ('cit-missing-{0}.key' -f ([guid]::NewGuid())))
        $env:PIA_FW_CREDENTIAL = ''
        $env:ITGLUE_API_TOKEN  = ''
        $env:ITGLUE_SUBDOMAIN  = ''
        try {
            $cred = Get-CitFirewallCredential -KeyPath ''
            $cred.Source | Should -Be 'NO_CREDENTIAL_SOURCE'
        } finally {
            $env:CIT_FW_SSH_KEY    = $saved.Key
            $env:PIA_FW_CREDENTIAL = $saved.Pia
            $env:ITGLUE_API_TOKEN  = $saved.Tok
            $env:ITGLUE_SUBDOMAIN  = $saved.Sub
        }
    }
}

Describe 'Get-CitSonicWallVersion parsing' {

    It 'parses real version output and sets ParseOk true' {
        Mock Invoke-SSHCommand {
            if ($Command -eq 'show version') {
                New-FakeSshResult -Output @('Model Name: NSa 2700', 'Firmware Version: SonicOS 7.1.2-7018-R6177', 'Up Time: 5 Days 02:00:00')
            } else {
                New-FakeSshResult -Output @('HA State: standalone')
            }
        }
        $diag = Get-CitSonicWallVersion -SshSession 'fake'
        $diag.ParseOk    | Should -BeTrue
        $diag.Firmware   | Should -Be 'SonicOS 7.1.2-7018-R6177'
        $diag.Model      | Should -Be 'NSa 2700'
        $diag.UptimeDays | Should -Be 5
    }

    It 'sets ParseOk false (no fake telemetry) when version cannot be parsed' {
        Mock Invoke-SSHCommand { New-FakeSshResult -Output @('garbage line', 'no version here') }
        $diag = Get-CitSonicWallVersion -SshSession 'fake'
        $diag.ParseOk  | Should -BeFalse
        $diag.Firmware | Should -BeNullOrEmpty
        $diag.UptimeDays | Should -BeNullOrEmpty
    }

    It 'parses HARole from a joined string, not stale $matches' {
        Mock Invoke-SSHCommand {
            if ($Command -eq 'show version') {
                New-FakeSshResult -Output @('Firmware Version: SonicOS 7.1.2-7018-R6177')
            } else {
                New-FakeSshResult -Output @('HA State: active', 'Peer Status: Online', 'Current Role: primary')
            }
        }
        $diag = Get-CitSonicWallVersion -SshSession 'fake'
        $diag.HAState       | Should -Be 'active'
        $diag.HARole        | Should -Be 'primary'
        $diag.HAPeerPresent | Should -BeTrue
    }
}

Describe 'Get-CitFortinetVersion parsing' {

    It 'parses real version output and sets ParseOk true' {
        Mock Invoke-SSHCommand {
            if ($Command -eq 'get system status') {
                New-FakeSshResult -Output @('Version: FortiGate-60F v7.4.3,build2571,GA', 'Model name: FortiGate-60F')
            } else {
                New-FakeSshResult -Output @('Mode: standalone')
            }
        }
        $diag = Get-CitFortinetVersion -SshSession 'fake'
        $diag.ParseOk  | Should -BeTrue
        $diag.Firmware | Should -Not -BeNullOrEmpty
    }

    It 'sets ParseOk false (no UptimeDays=42 stub) when version cannot be parsed' {
        Mock Invoke-SSHCommand { New-FakeSshResult -Output @('nothing useful') }
        $diag = Get-CitFortinetVersion -SshSession 'fake'
        $diag.ParseOk    | Should -BeFalse
        $diag.Firmware   | Should -BeNullOrEmpty
        $diag.UptimeDays | Should -BeNullOrEmpty
    }
}

Describe 'Backup gates Success on ExitStatus' {

    It 'SonicWall: non-zero ExitStatus yields Success false' {
        Mock Invoke-SSHCommand { New-FakeSshResult -Output @('error') -ExitStatus 1 }
        $r = Backup-CitSonicWallConfig -SshSession 'fake' -DestinationPath ([System.IO.Path]::GetTempPath())
        $r.Success     | Should -BeFalse
        $r.BackupError | Should -Not -BeNullOrEmpty
    }

    It 'Fortinet: empty output yields Success false' {
        Mock Invoke-SSHCommand { New-FakeSshResult -Output @() -ExitStatus 0 }
        $r = Backup-CitFortinetConfig -SshSession 'fake' -DestinationPath ([System.IO.Path]::GetTempPath())
        $r.Success | Should -BeFalse
    }
}

Describe 'Stage and Apply gate on ExitStatus' {

    It 'SonicWall stage: non-zero ExitStatus yields Staged false' {
        $img = Join-Path ([System.IO.Path]::GetTempPath()) ('cit-img-{0}.sig' -f ([guid]::NewGuid()))
        Set-Content -Path $img -Value 'x' -Force
        try {
            Mock Invoke-SSHCommand { New-FakeSshResult -Output @('failed') -ExitStatus 2 }
            $r = Save-CitSonicWallFirmware -SshSession 'fake' -ImagePath $img
            $r.Staged | Should -BeFalse
            $r.Error  | Should -Not -BeNullOrEmpty
        } finally {
            Remove-Item $img -Force -ErrorAction SilentlyContinue
        }
    }

    It 'Fortinet apply: non-zero ExitStatus yields Applied false and RebootInit false' {
        Mock Invoke-SSHCommand { New-FakeSshResult -Output @('failed') -ExitStatus 3 }
        $r = Install-CitFortinetUpdate -SshSession 'fake' -ImagePath 'C:\x.out'
        $r.Applied    | Should -BeFalse
        $r.RebootInit | Should -BeFalse
    }

    It 'SonicWall apply: zero ExitStatus yields Applied true' {
        Mock Invoke-SSHCommand { New-FakeSshResult -Output @('upgrading') -ExitStatus 0 }
        $r = Install-CitSonicWallUpdate -SshSession 'fake' -ImagePath 'C:\x.sig'
        $r.Applied | Should -BeTrue
    }
}
