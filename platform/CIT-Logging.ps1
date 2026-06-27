#Requires -Version 5.1
# CIT-Logging.ps1
# Shared logging helpers for all CIT Intune scripts.
# Source with: . "$PSScriptRoot\..\platform\CIT-Logging.ps1" -ScriptName 'MyScript'
#
# Logs to: C:\ProgramData\CIT\Logs\<ScriptName>.log
# Format:  YYYY-MM-DD HH:mm:ss.fff [LEVEL] [ScriptName] message

# Optional dot-source contract: callers may pass -ScriptName (the documented
# usage above). The parameter is optional, so scripts that dot-source with no
# arguments and call Write-CITLog -ScriptName '...' per-call still work unchanged.
[Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSReviewUnusedParameter', 'ScriptName', Justification = 'Accepted for the caller dot-source contract (callers dot-source with -ScriptName); intentionally not referenced in the helper body.')]
param(
    [string] $ScriptName
)

function Write-CITLog {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] [string] $Message,
        [Parameter()] [ValidateSet('INFO','WARN','ERROR','DEBUG')] [string] $Level = 'INFO',
        [Parameter(Mandatory)] [string] $ScriptName
    )

    $logDir = 'C:\ProgramData\CIT\Logs'
    if (-not (Test-Path $logDir)) {
        try { New-Item -Path $logDir -ItemType Directory -Force | Out-Null } catch { return }
    }

    $ts   = (Get-Date).ToString('yyyy-MM-dd HH:mm:ss.fff')
    $line = "$ts [$Level] [$ScriptName] $Message"

    # Best-effort logging: a transient file lock (concurrent write, AV scan) must
    # never throw to the caller. Callers often run under $ErrorActionPreference='Stop',
    # where an unguarded write failure would turn a successful action into an error
    # exit. Retry briefly, then give up silently.
    for ($attempt = 1; $attempt -le 3; $attempt++) {
        try {
            $logFile = Join-Path $logDir "$ScriptName.log"
            Add-Content -Path $logFile -Value $line -Encoding UTF8 -ErrorAction Stop
            break
        }
        catch {
            if ($attempt -ge 3) { return }
            Start-Sleep -Milliseconds 100
        }
    }
}

# Run a script block and emit a structured error to the log on failure.
# Returns $true if the block succeeded, $false otherwise.
function Invoke-CITSafely {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] [scriptblock] $ScriptBlock,
        [Parameter(Mandatory)] [string]     $ScriptName,
        [Parameter()]    [string]     $Context = ''
    )

    try {
        & $ScriptBlock | Out-Null
        return $true
    } catch {
        $msg = if ($Context) { "$Context failed: $($_.Exception.Message)" } else { $_.Exception.Message }
        Write-CITLog -Message $msg -Level ERROR -ScriptName $ScriptName
        return $false
    }
}
